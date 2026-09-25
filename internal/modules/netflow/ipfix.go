package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/grioghar/flowsight/internal/core"
)

// IPFIX format (RFC 5101, RFC 7011)
// Similar to NetFlow v9 but with updated field types and 64-bit counters

type ipfixHeader struct {
	Version     uint16
	Length      uint16
	ExportTime  uint32
	SequenceNum uint32
	DomainID    uint32
}

type ipfixSet struct {
	SetID  uint16
	Length uint16
}

// IPFIX Information Element IDs (subset)
const (
	IPFIX_IN_BYTES                  = 1
	IPFIX_IN_PKTS                   = 2
	IPFIX_FLOWS                     = 3
	IPFIX_PROTOCOL                  = 4
	IPFIX_SRC_TOS                   = 5
	IPFIX_TCP_FLAGS                 = 6
	IPFIX_L4_SRC_PORT               = 7
	IPFIX_L4_DST_PORT               = 11
	IPFIX_LAST_SWITCHED             = 21
	IPFIX_FIRST_SWITCHED            = 22
	IPFIX_OUT_BYTES                 = 23
	IPFIX_OUT_PKTS                  = 24
	IPFIX_IPV4_SRC_ADDR             = 8
	IPFIX_IPV4_DST_ADDR             = 12
	IPFIX_IPV6_SRC_ADDR             = 27
	IPFIX_IPV6_DST_ADDR             = 28
	IPFIX_INPUT_SNMP                = 10
	IPFIX_OUTPUT_SNMP               = 14
	IPFIX_IPV4_NEXT_HOP             = 15
	IPFIX_SRC_AS                    = 16
	IPFIX_DST_AS                    = 17
	IPFIX_APPLICATION_NAME          = 96
	IPFIX_APPLICATION_CATEGORY_NAME = 207
	IPFIX_FLOW_START_MILLISECONDS   = 152
	IPFIX_FLOW_END_MILLISECONDS     = 153
	IPFIX_DELTA_IN_BYTES            = 29
	IPFIX_DELTA_OUT_BYTES           = 30
	IPFIX_DELTA_IN_PKTS             = 31
	IPFIX_DELTA_OUT_PKTS            = 32
)

func (c *collector) handleIPFIX(packet []byte, remoteAddr *net.UDPAddr) {
	if len(packet) < 16 {
		return
	}

	var hdr ipfixHeader
	r := bytes.NewReader(packet)
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return
	}

	if hdr.Version != 10 {
		return // Not IPFIX (which is version 10)
	}

	if int(hdr.Length) > len(packet) {
		return
	}

	exporter := c.getExporter(remoteAddr.IP.String())
	if exporter == nil {
		return
	}

	exportTime := int64(hdr.ExportTime)

	var flows []core.Flow
	pos := 16

	for pos < int(hdr.Length) {
		if pos+4 > int(hdr.Length) {
			break
		}

		var set ipfixSet
		set.SetID = binary.BigEndian.Uint16(packet[pos : pos+2])
		set.Length = binary.BigEndian.Uint16(packet[pos+2 : pos+4])

		if set.Length < 4 {
			break
		}

		if pos+int(set.Length) > int(hdr.Length) {
			break
		}

		if set.SetID == 2 {
			// Template Set
			c.parseIPFIXTemplateSet(packet[pos:pos+int(set.Length)], hdr.DomainID, exporter)
		} else if set.SetID == 3 {
			// Options Template Set; skip
		} else {
			// Data Set
			dataFlows, dropped := c.parseIPFIXDataSet(packet[pos:pos+int(set.Length)], hdr.DomainID, exportTime, exporter, remoteAddr)
			flows = append(flows, dataFlows...)
			if dropped > 0 {
				atomic.AddUint64(&exporter.dropsTotal, dropped)
			}
		}

		pos += int(set.Length)
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

// parseIPFIXTemplateSet extracts templates from a template set.
func (c *collector) parseIPFIXTemplateSet(data []byte, domainID uint32, exporter *exporterState) {
	if len(data) < 4 {
		return
	}

	pos := 4 // skip set header
	for pos+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[pos : pos+2])
		fieldCount := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4

		fields := make([]fieldIP, 0, fieldCount)

		for j := 0; j < int(fieldCount); j++ {
			if pos+4 > len(data) {
				return
			}

			id := binary.BigEndian.Uint16(data[pos : pos+2])
			length := binary.BigEndian.Uint16(data[pos+2 : pos+4])
			pos += 4

			// Check for enterprise bit
			isEnterprise := (id & 0x8000) != 0
			if isEnterprise {
				// Enterprise element; skip the 4-byte enterprise number
				if pos+4 > len(data) {
					return
				}
				pos += 4
			}

			fields = append(fields, fieldIP{id: id & 0x7fff, length: length, length_: length == 65535})
		}

		// Cache the template
		exporter.tmplCacheI.StoreIP(domainID, templateID, fields)
	}
}

// parseIPFIXDataSet parses data records for a template.
func (c *collector) parseIPFIXDataSet(data []byte, domainID uint32, exportTime int64, exporter *exporterState, remoteAddr *net.UDPAddr) ([]core.Flow, uint64) {
	if len(data) < 4 {
		return nil, 0
	}

	setID := binary.BigEndian.Uint16(data[0:2])

	// Get template for this set
	fields, ok := exporter.tmplCacheI.GetIP(domainID, setID)
	if !ok {
		// No template known; count as drop and skip
		return nil, 1
	}

	var flows []core.Flow
	pos := 4

	for pos < len(data) {
		flow, consumed := c.decodeIPFIXRecord(data[pos:], fields, exportTime, exporter, remoteAddr)
		if consumed == 0 {
			break
		}
		if flow.SrcIP != "" && flow.DstIP != "" {
			flows = append(flows, flow)
			atomic.AddUint64(&exporter.recordsTotal, 1)
		}
		pos += consumed
	}

	return flows, 0
}

// decodeIPFIXRecord turns one IPFIX record into a core.Flow.
func (c *collector) decodeIPFIXRecord(data []byte, fields []fieldIP, exportTime int64, exporter *exporterState, remoteAddr *net.UDPAddr) (core.Flow, int) {
	flow := core.Flow{
		Source: "ipfix:" + remoteAddr.IP.String(),
		TS:     exportTime,
	}

	pos := 0
	var srcIP, dstIP string
	var srcPort, dstPort int
	var proto string
	var inBytes, outBytes, inPkts, outPkts int64
	var flowStartMs, flowEndMs int64

	for _, f := range fields {
		if f.length_ {
			// Variable length field
			if pos >= len(data) {
				break
			}
			lenByte := data[pos]
			pos++
			var fieldLen int
			if lenByte == 255 && pos+1 < len(data) {
				fieldLen = int(binary.BigEndian.Uint16(data[pos : pos+2]))
				pos += 2
			} else {
				fieldLen = int(lenByte)
			}
			if pos+fieldLen > len(data) {
				break
			}
			// Skip variable-length field for now
			pos += fieldLen
			continue
		}

		if pos+int(f.length) > len(data) {
			break
		}

		field := data[pos : pos+int(f.length)]
		pos += int(f.length)

		switch f.id {
		case IPFIX_IPV4_SRC_ADDR:
			if len(field) >= 4 {
				srcIP = net.IP(field[:4]).String()
			}
		case IPFIX_IPV4_DST_ADDR:
			if len(field) >= 4 {
				dstIP = net.IP(field[:4]).String()
			}
		case IPFIX_IPV6_SRC_ADDR:
			if len(field) >= 16 {
				srcIP = net.IP(field[:16]).String()
			}
		case IPFIX_IPV6_DST_ADDR:
			if len(field) >= 16 {
				dstIP = net.IP(field[:16]).String()
			}
		case IPFIX_L4_SRC_PORT:
			if len(field) >= 2 {
				srcPort = int(binary.BigEndian.Uint16(field))
			}
		case IPFIX_L4_DST_PORT:
			if len(field) >= 2 {
				dstPort = int(binary.BigEndian.Uint16(field))
			}
		case IPFIX_PROTOCOL:
			if len(field) >= 1 {
				proto = protoName(field[0])
			}
		case IPFIX_IN_BYTES:
			if len(field) >= 8 {
				inBytes = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				inBytes = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_OUT_BYTES:
			if len(field) >= 8 {
				outBytes = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				outBytes = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_DELTA_IN_BYTES:
			if len(field) >= 8 {
				inBytes = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				inBytes = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_DELTA_OUT_BYTES:
			if len(field) >= 8 {
				outBytes = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				outBytes = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_IN_PKTS:
			if len(field) >= 8 {
				inPkts = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				inPkts = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_OUT_PKTS:
			if len(field) >= 8 {
				outPkts = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				outPkts = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_DELTA_IN_PKTS:
			if len(field) >= 8 {
				inPkts = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				inPkts = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_DELTA_OUT_PKTS:
			if len(field) >= 8 {
				outPkts = int64(binary.BigEndian.Uint64(field))
			} else if len(field) >= 4 {
				outPkts = int64(binary.BigEndian.Uint32(field))
			}
		case IPFIX_FLOW_START_MILLISECONDS:
			if len(field) >= 8 {
				flowStartMs = int64(binary.BigEndian.Uint64(field))
			}
		case IPFIX_FLOW_END_MILLISECONDS:
			if len(field) >= 8 {
				flowEndMs = int64(binary.BigEndian.Uint64(field))
			}
		case IPFIX_INPUT_SNMP:
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
	flow.BytesIn = inBytes
	flow.BytesOut = outBytes
	flow.Packets = inPkts + outPkts
	if flow.Packets == 0 {
		flow.Packets = inPkts
	}

	if flowStartMs > 0 {
		flow.TS = flowStartMs / 1000
	}

	if flowEndMs > 0 && flowStartMs > 0 {
		flow.Duration = float64(flowEndMs-flowStartMs) / 1000.0
	}

	flow.Key = fmt.Sprintf("ipfix:%s:%d-%s:%d/%s@%d", srcIP, srcPort, dstIP, dstPort, proto, flow.TS)

	return flow, pos
}
