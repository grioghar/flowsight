package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/grioghar/flowsight/internal/core"
)

// sFlow v5 expanded formats (enterprise 0, types 3 and 4)
const (
	SFLOW_EXPANDED_FLOW_SAMPLE    = 3
	SFLOW_EXPANDED_COUNTER_SAMPLE = 4
)

// Handle expanded flow sample format
func (c *collector) parseSFlowExpandedFlowSample(data []byte, baseTime int64, exporter *exporterState, remoteAddr *net.UDPAddr, sourceID uint32) []core.Flow {
	if len(data) < 28 {
		return nil
	}

	r := bytes.NewReader(data)

	// Parse expanded sample header
	var sampleSeq, sourceID32, sampleRate, samplePool, drops uint32
	var inputFormat, inputValue, outputFormat, outputValue uint32
	binary.Read(r, binary.BigEndian, &sampleSeq)
	binary.Read(r, binary.BigEndian, &sourceID32)
	binary.Read(r, binary.BigEndian, &sampleRate)
	binary.Read(r, binary.BigEndian, &samplePool)
	binary.Read(r, binary.BigEndian, &drops)
	binary.Read(r, binary.BigEndian, &inputFormat)
	binary.Read(r, binary.BigEndian, &inputValue)
	binary.Read(r, binary.BigEndian, &outputFormat)
	binary.Read(r, binary.BigEndian, &outputValue)

	sampling := uint64(1)
	if sampleRate > 0 {
		sampling = uint64(sampleRate)
	}
	override := uint64(core.Int(c.m.ctx.Settings(), "sampling_override", 0))
	if override > 0 {
		sampling = override
	}

	numRecords := uint32(0)
	binary.Read(r, binary.BigEndian, &numRecords)

	var flows []core.Flow
	for i := 0; i < int(numRecords); i++ {
		if r.Len() < 8 {
			break
		}

		var elemFormat, elemLength uint32
		binary.Read(r, binary.BigEndian, &elemFormat)
		binary.Read(r, binary.BigEndian, &elemLength)

		if elemLength > uint32(r.Len()) {
			break
		}

		elemData := make([]byte, elemLength)
		if n, err := r.Read(elemData); err != nil || n != int(elemLength) {
			break
		}

		if elemFormat == SFLOW_FLOW_EF_PACKET_DATA {
			flow := c.parseSFlowPacketDataWithVLAN(elemData, baseTime, exporter, remoteAddr, sourceID32, sampling)
			if flow.SrcIP != "" && flow.DstIP != "" {
				flows = append(flows, flow)
				atomic.AddUint64(&exporter.recordsTotal, 1)
			}
		}
	}

	return flows
}

// Parse packet data with VLAN tag support
func (c *collector) parseSFlowPacketDataWithVLAN(data []byte, baseTime int64, exporter *exporterState, remoteAddr *net.UDPAddr, sourceID uint32, sampling uint64) core.Flow {
	flow := core.Flow{
		Source: "sflow5:" + remoteAddr.IP.String(),
		TS:     baseTime,
		Iface:  fmt.Sprintf("ifIndex %d", sourceID),
	}

	if len(data) < 16 {
		return flow
	}

	frameLength := binary.BigEndian.Uint32(data[4:8])
	headerLength := binary.BigEndian.Uint32(data[12:16])

	if 16+int(headerLength) > len(data) {
		return flow
	}

	header := data[16 : 16+int(headerLength)]

	// Parse Ethernet frame with potential VLAN tags
	if len(header) < 14 {
		return flow
	}

	etherType := binary.BigEndian.Uint16(header[12:14])
	ipHeaderOffset := 14

	// Handle VLAN tags (0x8100, 0x88a8)
	for etherType == 0x8100 || etherType == 0x88a8 {
		if ipHeaderOffset+4 > len(header) {
			return flow
		}
		// VLAN tag: next 2 bytes are the inner EtherType
		etherType = binary.BigEndian.Uint16(header[ipHeaderOffset+2 : ipHeaderOffset+4])
		ipHeaderOffset += 4
	}

	// Parse IPv4 or IPv6
	if etherType == 0x0800 {
		// IPv4
		if ipHeaderOffset+20 > len(header) {
			return flow
		}

		ipHeader := header[ipHeaderOffset:]
		version := ipHeader[0] >> 4
		if version != 4 {
			return flow
		}

		ihl := int((ipHeader[0] & 0x0f) * 4)
		if ihl < 20 || ihl > len(ipHeader) {
			return flow
		}

		protocol := ipHeader[9]
		srcIP := net.IP(ipHeader[12:16]).String()
		dstIP := net.IP(ipHeader[16:20]).String()

		flow.SrcIP = srcIP
		flow.DstIP = dstIP
		flow.Proto = protoName(protocol)

		// Parse transport header
		if len(ipHeader) >= ihl+4 {
			transportHeader := ipHeader[ihl:]
			switch protocol {
			case 6, 17: // TCP, UDP
				if len(transportHeader) >= 4 {
					flow.SrcPort = int(binary.BigEndian.Uint16(transportHeader[0:2]))
					flow.DstPort = int(binary.BigEndian.Uint16(transportHeader[2:4]))
				}
			}
		}
	} else if etherType == 0x86dd {
		// IPv6
		if ipHeaderOffset+40 > len(header) {
			return flow
		}

		ipHeader := header[ipHeaderOffset:]
		version := ipHeader[0] >> 4
		if version != 6 {
			return flow
		}

		protocol := ipHeader[6]
		srcIP := net.IP(ipHeader[8:24]).String()
		dstIP := net.IP(ipHeader[24:40]).String()

		flow.SrcIP = srcIP
		flow.DstIP = dstIP

		// Handle IPv6 extension headers
		nextHeader := protocol
		extensionOffset := 40
		for {
			if nextHeader == 6 || nextHeader == 17 {
				// TCP or UDP
				flow.Proto = protoName(nextHeader)
				if ipHeaderOffset+extensionOffset+4 <= len(header) {
					transportHeader := header[ipHeaderOffset+extensionOffset:]
					flow.SrcPort = int(binary.BigEndian.Uint16(transportHeader[0:2]))
					flow.DstPort = int(binary.BigEndian.Uint16(transportHeader[2:4]))
				}
				break
			} else if nextHeader == 0 || nextHeader == 43 || nextHeader == 60 {
				// Hop-by-hop, routing, or destination options
				if ipHeaderOffset+extensionOffset+2 > len(header) {
					break
				}
				nextHeader = header[ipHeaderOffset+extensionOffset]
				// Length field is in 8-byte units, not including the first 8 bytes
				extLen := int(header[ipHeaderOffset+extensionOffset+1]) * 8
				if extLen == 0 {
					extLen = 8
				}
				extensionOffset += extLen
			} else {
				// Unknown extension, stop
				flow.Proto = protoName(nextHeader)
				break
			}
		}
	}

	flow.BytesOut = int64(frameLength) * int64(sampling)
	flow.Packets = int64(sampling)
	flow.Key = fmt.Sprintf("sflow5:%s:%d-%s:%d/%s@%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Proto, flow.TS)

	return flow
}
