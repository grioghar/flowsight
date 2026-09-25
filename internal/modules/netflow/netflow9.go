package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/grioghar/flowsight/internal/core"
)

// NetFlow v9 format (RFC 3954)
// Template-based flow export using Netflow v9 format

type netFlow9Header struct {
	Version     uint16
	Count       uint16
	SysUptime   uint32
	UnixSecs    uint32
	SequenceNum uint32
	SourceID    uint32
}

type netFlow9FlowSet struct {
	FlowSetID uint16
	Length    uint16
}

type netFlow9Template struct {
	TemplateID uint16
	FieldCount uint16
}

type netFlow9TemplateField struct {
	Type   uint16
	Length uint16
}

// NetFlow v9 field types (subset of commonly used ones)
const (
	NF9_IN_BYTES          = 1
	NF9_IN_PKTS           = 2
	NF9_FLOWS             = 3
	NF9_PROTOCOL          = 4
	NF9_SRC_TOS           = 5
	NF9_TCP_FLAGS         = 6
	NF9_L4_SRC_PORT       = 7
	NF9_L4_DST_PORT       = 11
	NF9_LAST_SWITCHED     = 21
	NF9_FIRST_SWITCHED    = 22
	NF9_OUT_BYTES         = 23
	NF9_OUT_PKTS          = 24
	NF9_IPV4_SRC_ADDR     = 8
	NF9_IPV4_DST_ADDR     = 12
	NF9_IPV6_SRC_ADDR     = 27
	NF9_IPV6_DST_ADDR     = 28
	NF9_INPUT_IFACE       = 10
	NF9_OUTPUT_IFACE      = 14
	NF9_IPV4_NEXT_HOP     = 15
	NF9_SRC_AS            = 16
	NF9_DST_AS            = 17
	NF9_BGP_IPV4_NEXT_HOP = 18
	NF9_SRC_MASK          = 9
	NF9_DST_MASK          = 13
	NF9_APPLICATION_NAME  = 96
	NF9_APPLICATION_ID    = 95
)

func (c *collector) handleNetFlow9(packet []byte, remoteAddr *net.UDPAddr) {
	if len(packet) < 20 {
		return
	}

	var hdr netFlow9Header
	r := bytes.NewReader(packet)
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return
	}

	if hdr.Version != 9 {
		return
	}

	exporter := c.getExporter(remoteAddr.IP.String())
	if exporter == nil {
		return
	}

	baseTime := int64(hdr.UnixSecs)
	sysUptime := int64(hdr.SysUptime)

	var flows []core.Flow
	pos := 20

	for i := 0; i < int(hdr.Count); i++ {
		if pos+4 > len(packet) {
			break
		}

		var fs netFlow9FlowSet
		fs.FlowSetID = binary.BigEndian.Uint16(packet[pos : pos+2])
		fs.Length = binary.BigEndian.Uint16(packet[pos+2 : pos+4])

		if fs.Length < 4 {
			break
		}

		if pos+int(fs.Length) > len(packet) {
			break
		}

		if fs.FlowSetID == 0 {
			// Template FlowSet; skip for now (templates are cached)
			pos += int(fs.Length)
			continue
		}
		if fs.FlowSetID == 1 {
			// Options Template FlowSet; skip
			pos += int(fs.Length)
			continue
		}

		// Data FlowSet
		dataFlows, _ := c.parseNetFlow9DataSet(packet[pos:pos+int(fs.Length)], hdr.SourceID, baseTime, sysUptime, exporter, remoteAddr)
		flows = append(flows, dataFlows...)

		pos += int(fs.Length)
	}

	if len(flows) > 0 {
		atomic.AddUint64(&exporter.flowsTotal, uint64(len(flows)))
		look, _ := c.m.ctx.Service("enrich").(core.CountryLookup)
		anyc, _ := c.m.ctx.Service("anycast").(core.AnycastLookup)
		var isLocal func(string) bool
		if c.m.identity != nil {
			isLocal = c.m.identity.IsLocal
		}
		core.FillCountries(flows, look, anyc, isLocal)
		_ = c.m.ctx.Store.AddFlows(flows)
	}
}

func (c *collector) parseNetFlow9DataSet(data []byte, sourceID uint32, baseTime, sysUptime int64, exporter *exporterState, remoteAddr *net.UDPAddr) ([]core.Flow, error) {
	if len(data) < 4 {
		return nil, nil
	}

	flowSetID := binary.BigEndian.Uint16(data[0:2])
	length := binary.BigEndian.Uint16(data[2:4])

	// For now, store one default template per source ID and parse with it
	// A full implementation would cache templates per (sourceID, domainID)
	// and parse options templates to learn the schema

	tmplKey := fmt.Sprintf("%d,%d", sourceID, 0)
	exporter.mu.RLock()
	tmpl := exporter.templates9[tmplKey]
	exporter.mu.RUnlock()

	if tmpl == nil || tmpl.templateID != flowSetID {
		// No template known; skip this flow set
		return nil, nil
	}

	if len(data) < 4 {
		return nil, nil
	}

	recordLen := 0
	for _, f := range tmpl.fields {
		recordLen += int(f.length)
	}

	if recordLen == 0 {
		return nil, nil
	}

	var flows []core.Flow
	pos := 4
	for pos+recordLen <= int(length) {
		rec := data[pos : pos+recordLen]
		flow := c.decodeNetFlow9Record(rec, tmpl, baseTime, sysUptime, exporter, remoteAddr)
		if flow.SrcIP != "" && flow.DstIP != "" {
			flows = append(flows, flow)
			atomic.AddUint64(&exporter.recordsTotal, 1)
		}
		pos += recordLen
	}

	return flows, nil
}

func (c *collector) decodeNetFlow9Record(rec []byte, tmpl *template9, baseTime, sysUptime int64, exporter *exporterState, remoteAddr *net.UDPAddr) core.Flow {
	flow := core.Flow{
		Source: "netflow9:" + remoteAddr.IP.String(),
		TS:     baseTime,
	}

	pos := 0
	var srcIP, dstIP string
	var srcPort, dstPort int
	var proto string
	var bytes, packets int64
	var firstTime, lastTime uint32

	for _, f := range tmpl.fields {
		if pos+int(f.length) > len(rec) {
			break
		}

		field := rec[pos : pos+int(f.length)]
		pos += int(f.length)

		switch f.fieldType {
		case NF9_IPV4_SRC_ADDR:
			if len(field) >= 4 {
				srcIP = net.IP(field[:4]).String()
			}
		case NF9_IPV4_DST_ADDR:
			if len(field) >= 4 {
				dstIP = net.IP(field[:4]).String()
			}
		case NF9_L4_SRC_PORT:
			if len(field) >= 2 {
				srcPort = int(binary.BigEndian.Uint16(field))
			}
		case NF9_L4_DST_PORT:
			if len(field) >= 2 {
				dstPort = int(binary.BigEndian.Uint16(field))
			}
		case NF9_PROTOCOL:
			if len(field) >= 1 {
				proto = protoName(field[0])
			}
		case NF9_IN_BYTES:
			if len(field) >= 4 {
				bytes = int64(binary.BigEndian.Uint32(field))
			}
		case NF9_OUT_BYTES:
			if len(field) >= 4 {
				// Some implementations report direction; we use IN as BytesIn
				// and OUT or total as BytesOut
			}
		case NF9_IN_PKTS:
			if len(field) >= 4 {
				packets = int64(binary.BigEndian.Uint32(field))
			}
		case NF9_FIRST_SWITCHED:
			if len(field) >= 4 {
				firstTime = binary.BigEndian.Uint32(field)
			}
		case NF9_LAST_SWITCHED:
			if len(field) >= 4 {
				lastTime = binary.BigEndian.Uint32(field)
			}
		case NF9_INPUT_IFACE:
			if len(field) >= 2 {
				flow.Iface = fmt.Sprintf("ifIndex %d", binary.BigEndian.Uint16(field))
			} else if len(field) >= 4 {
				flow.Iface = fmt.Sprintf("ifIndex %d", binary.BigEndian.Uint32(field))
			}
		}
	}

	flow.SrcIP = srcIP
	flow.DstIP = dstIP
	flow.SrcPort = srcPort
	flow.DstPort = dstPort
	flow.Proto = proto
	flow.BytesOut = bytes
	flow.Packets = packets

	if firstTime > 0 {
		flow.TS = (baseTime * 1000) - int64(sysUptime) + int64(firstTime)
		if flow.TS < 0 {
			flow.TS = baseTime
		}
	}

	if lastTime >= firstTime && firstTime > 0 {
		flow.Duration = float64(lastTime-firstTime) / 1000.0
	}

	flow.Key = fmt.Sprintf("netflow9:%s:%d-%s:%d/%s@%d", srcIP, srcPort, dstIP, dstPort, proto, flow.TS)

	return flow
}

// StoreTemplate stores a NetFlow v9 template for later use
func (ex *exporterState) storeTemplate9(sourceID uint32, tmpl *template9) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	key := fmt.Sprintf("%d,%d", sourceID, tmpl.domainID)
	ex.templates9[key] = tmpl
}
