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

// sFlow v5 format (RFC 3176, RFC 3877, RFC 6343)
// Samples raw packet headers with metadata about the link

type sFlowDatagram struct {
	Version      uint32
	AgentAddress [4]byte
	SubAgentID   uint32
	SequenceNum  uint32
	SysUptime    uint32
	NumSamples   uint32
}

type sFlowSampleHeader struct {
	Format     uint32
	Length     uint32
	SampleSeq  uint32
	SourceID   uint32
	SampleRate uint32
	SamplePool uint32
	Drops      uint32
	Input      uint32
	Output     uint32
}

const (
	SFLOW_FLOW_SAMPLE_EXPANDED = 3
	SFLOW_FLOW_SAMPLE          = 1
	SFLOW_COUNTER_SAMPLE       = 2

	SFLOW_FLOW_EF_PACKET_DATA      = 1
	SFLOW_FLOW_EF_EXTENDED_SWITCH  = 1001
	SFLOW_FLOW_EF_EXTENDED_ROUTER  = 1002
	SFLOW_FLOW_EF_EXTENDED_GATEWAY = 1003
)

func (c *collector) handleSFlow5(packet []byte, remoteAddr *net.UDPAddr) {
	if len(packet) < 28 {
		return
	}

	var dg sFlowDatagram
	r := bytes.NewReader(packet)
	if err := binary.Read(r, binary.BigEndian, &dg); err != nil {
		return
	}

	if dg.Version != 5 {
		return
	}

	exporter := c.getExporter(remoteAddr.IP.String())
	if exporter == nil {
		return
	}

	now := time.Now().Unix()
	baseTime := now - int64(dg.SysUptime/1000)

	var flows []core.Flow
	pos := 28

	for i := 0; i < int(dg.NumSamples); i++ {
		if pos+8 > len(packet) {
			break
		}

		// Sample format and length
		format := binary.BigEndian.Uint32(packet[pos : pos+4])
		length := binary.BigEndian.Uint32(packet[pos+4 : pos+8])

		if pos+8+int(length) > len(packet) {
			break
		}

		sampleData := packet[pos+8 : pos+8+int(length)]

		if format == SFLOW_FLOW_SAMPLE || format == SFLOW_FLOW_SAMPLE_EXPANDED {
			dataFlows := c.parseSFlowSample(sampleData, baseTime, exporter, remoteAddr)
			flows = append(flows, dataFlows...)
		}

		pos += 8 + int(length)
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

func (c *collector) parseSFlowSample(data []byte, baseTime int64, exporter *exporterState, remoteAddr *net.UDPAddr) []core.Flow {
	if len(data) < 20 {
		return nil
	}

	r := bytes.NewReader(data)

	// Parse sample header
	var sampleSeq, sourceID, sampleRate, samplePool, drops, input, output uint32
	binary.Read(r, binary.BigEndian, &sampleSeq)
	binary.Read(r, binary.BigEndian, &sourceID)
	binary.Read(r, binary.BigEndian, &sampleRate)
	binary.Read(r, binary.BigEndian, &samplePool)
	binary.Read(r, binary.BigEndian, &drops)
	binary.Read(r, binary.BigEndian, &input)
	binary.Read(r, binary.BigEndian, &output)

	if sampleRate > 0 && sampleRate < 1000000000 {
		sampling := uint64(sampleRate)
		override := uint64(core.Int(c.m.ctx.Settings(), "sampling_override", 0))
		if override > 0 {
			sampling = override
		}
		_ = sampling
	}

	numRecords := uint32(0)
	if err := binary.Read(r, binary.BigEndian, &numRecords); err != nil {
		return nil
	}

	var flows []core.Flow
	for i := 0; i < int(numRecords); i++ {
		if r.Len() < 8 {
			break
		}

		var elemFormat, elemLength uint32
		if err := binary.Read(r, binary.BigEndian, &elemFormat); err != nil {
			break
		}
		if err := binary.Read(r, binary.BigEndian, &elemLength); err != nil {
			break
		}

		if elemLength > uint32(r.Len()) {
			break
		}

		elemData := make([]byte, elemLength)
		if n, err := r.Read(elemData); err != nil || n != int(elemLength) {
			break
		}

		if elemFormat == SFLOW_FLOW_EF_PACKET_DATA {
			flow := c.parseSFlowPacketData(elemData, baseTime, exporter, remoteAddr, sourceID)
			if flow.SrcIP != "" && flow.DstIP != "" {
				flows = append(flows, flow)
				atomic.AddUint64(&exporter.recordsTotal, 1)
			}
		}
	}

	return flows
}

func (c *collector) parseSFlowPacketData(data []byte, baseTime int64, exporter *exporterState, remoteAddr *net.UDPAddr, sourceID uint32) core.Flow {
	flow := core.Flow{
		Source: "sflow5:" + remoteAddr.IP.String(),
		TS:     baseTime,
		Iface:  fmt.Sprintf("ifIndex %d", sourceID),
	}

	if len(data) < 8 {
		return flow
	}

	// Packet data format: headerProtocol (4), frameLength (4), strippedLength (4), headerLength (4), header (variable)
	headerProtocol := binary.BigEndian.Uint32(data[0:4])
	frameLength := binary.BigEndian.Uint32(data[4:8])

	// For now, only handle Ethernet (1) and IPv4/IPv6 payloads
	if headerProtocol != 1 {
		return flow
	}

	if len(data) < 16 {
		return flow
	}

	headerLength := binary.BigEndian.Uint32(data[12:16])
	if 16+int(headerLength) > len(data) {
		return flow
	}

	header := data[16 : 16+int(headerLength)]

	// Parse Ethernet frame
	if len(header) < 14 {
		return flow
	}

	etherType := binary.BigEndian.Uint16(header[12:14])

	// Parse IPv4 or IPv6
	var srcIP, dstIP string
	var protocol uint8
	var srcPort, dstPort uint16

	if etherType == 0x0800 {
		// IPv4
		if len(header) < 14+20 {
			return flow
		}

		ipHeader := header[14:]
		version := ipHeader[0] >> 4
		if version != 4 {
			return flow
		}

		ihl := int((ipHeader[0] & 0x0f) * 4)
		if ihl < 20 {
			return flow
		}

		protocol = ipHeader[9]
		srcIP = net.IP(ipHeader[12:16]).String()
		dstIP = net.IP(ipHeader[16:20]).String()

		// Parse transport header
		if len(ipHeader) >= ihl+4 {
			transportHeader := ipHeader[ihl:]
			switch protocol {
			case 6, 17: // TCP, UDP
				if len(transportHeader) >= 4 {
					srcPort = binary.BigEndian.Uint16(transportHeader[0:2])
					dstPort = binary.BigEndian.Uint16(transportHeader[2:4])
				}
			}
		}
	} else if etherType == 0x86dd {
		// IPv6
		if len(header) < 14+40 {
			return flow
		}

		ipHeader := header[14:]
		version := ipHeader[0] >> 4
		if version != 6 {
			return flow
		}

		protocol = ipHeader[6]
		srcIP = net.IP(ipHeader[8:24]).String()
		dstIP = net.IP(ipHeader[24:40]).String()

		// Parse transport header
		if len(ipHeader) >= 40+4 {
			transportHeader := ipHeader[40:]
			switch protocol {
			case 6, 17: // TCP, UDP
				if len(transportHeader) >= 4 {
					srcPort = binary.BigEndian.Uint16(transportHeader[0:2])
					dstPort = binary.BigEndian.Uint16(transportHeader[2:4])
				}
			}
		}
	} else {
		return flow
	}

	flow.SrcIP = srcIP
	flow.DstIP = dstIP
	flow.SrcPort = int(srcPort)
	flow.DstPort = int(dstPort)
	flow.Proto = protoName(protocol)
	flow.BytesOut = int64(frameLength)
	flow.Packets = 1
	flow.Key = fmt.Sprintf("sflow5:%s:%d-%s:%d/%s@%d", srcIP, srcPort, dstIP, dstPort, flow.Proto, flow.TS)

	return flow
}
