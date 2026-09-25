package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// NetFlow v5 format (RFC 3954)
// https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html

type netFlow5Header struct {
	Version      uint16
	Count        uint16
	SysUptime    uint32
	UnixSecs     uint32
	UnixNsecs    uint32
	FlowSequence uint32
	EngineType   uint8
	EngineID     uint8
	SamplingMode uint8
	SamplingRate uint16
}

type netFlow5Record struct {
	SrcAddr     [4]byte
	DstAddr     [4]byte
	NextHop     [4]byte
	InputIface  uint16
	OutputIface uint16
	Packets     uint32
	Bytes       uint32
	FirstTime   uint32
	LastTime    uint32
	SrcPort     uint16
	DstPort     uint16
	Pad1        uint8
	TCPFlags    uint8
	Protocol    uint8
	ToS         uint8
	SrcAS       uint16
	DstAS       uint16
	SrcMask     uint8
	DstMask     uint8
	Pad2        uint16
}

func (c *collector) handleNetFlow5(packet []byte, remoteAddr *net.UDPAddr) {
	if len(packet) < 24 {
		return
	}

	var hdr netFlow5Header
	r := bytes.NewReader(packet)
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return
	}

	if hdr.Version != 5 {
		return
	}

	exporter := c.getExporter(remoteAddr.IP.String())
	if exporter == nil {
		return
	}

	recordSize := uint16(binary.Size(netFlow5Record{}))
	if uint16(len(packet)) < 24+hdr.Count*recordSize {
		return
	}

	now := time.Now().Unix()
	baseUptime := int64(hdr.SysUptime)
	baseTime := int64(hdr.UnixSecs)

	var flows []core.Flow
	for i := 0; i < int(hdr.Count); i++ {
		offset := 24 + i*int(recordSize)
		if offset+int(recordSize) > len(packet) {
			break
		}

		var rec netFlow5Record
		recR := bytes.NewReader(packet[offset : offset+int(recordSize)])
		if err := binary.Read(recR, binary.BigEndian, &rec); err != nil {
			break
		}

		sampling := uint64(1)
		if hdr.SamplingRate > 0 {
			sampling = uint64(hdr.SamplingRate)
		}
		override := uint64(core.Int(c.m.ctx.Settings(), "sampling_override", 0))
		if override > 0 {
			sampling = override
		}

		srcIP := net.IP(rec.SrcAddr[:]).String()
		dstIP := net.IP(rec.DstAddr[:]).String()

		// Estimate flow start time from firstTime relative to sysUptime
		flowStart := baseTime - (baseUptime-int64(rec.FirstTime))/1000
		if flowStart < 0 {
			flowStart = now
		}

		protoStr := protoName(rec.Protocol)
		key := fmt.Sprintf("netflow5:%s:%d-%s:%d/%s@%d", srcIP, rec.SrcPort, dstIP, rec.DstPort, protoStr, flowStart)

		flow := core.Flow{
			TS:       flowStart,
			Key:      key,
			SrcIP:    srcIP,
			SrcPort:  int(rec.SrcPort),
			DstIP:    dstIP,
			DstPort:  int(rec.DstPort),
			Proto:    protoStr,
			BytesOut: int64(rec.Bytes) * int64(sampling),
			BytesIn:  0,
			Packets:  int64(rec.Packets) * int64(sampling),
			Duration: float64(rec.LastTime-rec.FirstTime) / 1000.0,
			Source:   "netflow5:" + remoteAddr.IP.String(),
			Iface:    fmt.Sprintf("ifIndex %d", rec.InputIface),
		}

		if flow.SrcIP != "" && flow.DstIP != "" {
			flows = append(flows, flow)
		}

		atomic.AddUint64(&exporter.recordsTotal, 1)
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

func protoName(num uint8) string {
	switch num {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 41:
		return "ipv6"
	default:
		return fmt.Sprintf("proto%d", num)
	}
}
