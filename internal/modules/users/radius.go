package users

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// RADIUS Accounting packet structure (RFC 2866)
const (
	RADIUSAcctRequest  = 4
	RADIUSAcctResponse = 5
	RADIUSHeaderLen    = 20

	// RADIUS attribute types (RFC 2866)
	AttrUserName           = 1
	AttrFramedIPAddress    = 8
	AttrFramedIPv6Prefix   = 97
	AttrFramedIPv6Address  = 168
	AttrCallingStationID   = 31
	AttrNASIPAddress       = 4
	AttrNASIdentifier      = 32
	AttrAcctSessionID      = 44
	AttrAcctStartType      = 45
	AttrAcctStatusType     = 40
	AttrAcctInputOctets    = 42
	AttrAcctOutputOctets   = 43

	// Accounting Status Type values
	AcctStart     = 1
	AcctInterim   = 3
	AcctStop      = 2
	AcctOn        = 7
	AcctOff       = 8
)

type radiusPacket struct {
	Code      uint8
	ID        uint8
	Length    uint16
	Auth      [16]byte
	Attrs     map[uint8][][]byte
}

// handleRADIUSAccounting processes incoming RADIUS Accounting-Request packets.
func (m *Module) handleRADIUSAccounting(packet []byte, remoteAddr *net.UDPAddr) error {
	if len(packet) < RADIUSHeaderLen {
		return fmt.Errorf("packet too short")
	}

	rp := &radiusPacket{
		Code:   packet[0],
		ID:     packet[1],
		Length: binary.BigEndian.Uint16(packet[2:4]),
	}

	if rp.Code != RADIUSAcctRequest {
		return fmt.Errorf("not an accounting request: %d", rp.Code)
	}

	if rp.Length != uint16(len(packet)) {
		return fmt.Errorf("length mismatch: %d vs %d", rp.Length, len(packet))
	}

	copy(rp.Auth[:], packet[4:20])

	// Parse attributes
	rp.Attrs = make(map[uint8][][]byte)
	offset := RADIUSHeaderLen
	for offset < len(packet) {
		if offset+2 > len(packet) {
			break
		}
		attrType := packet[offset]
		attrLen := int(packet[offset+1])
		if attrLen < 2 || offset+attrLen > len(packet) {
			break
		}
		value := packet[offset+2 : offset+attrLen]
		rp.Attrs[attrType] = append(rp.Attrs[attrType], value)
		offset += attrLen
	}

	// Verify Request Authenticator (HMAC-MD5)
	if !m.verifyRADIUSAuth(packet, rp.Auth) {
		return fmt.Errorf("authentication failed")
	}

	// Extract attributes
	user := getString(rp.Attrs[AttrUserName])
	ipv4 := getIPv4(rp.Attrs[AttrFramedIPAddress])
	ipv6 := getIPv6(rp.Attrs[AttrFramedIPv6Address])
	ipv6Prefix := getIPv6Prefix(rp.Attrs[AttrFramedIPv6Prefix])
	mac := getMAC(rp.Attrs[AttrCallingStationID])
	nasIP := getIPv4(rp.Attrs[AttrNASIPAddress])
	nasID := getString(rp.Attrs[AttrNASIdentifier])
	acctSessionID := getString(rp.Attrs[AttrAcctSessionID])
	statusType := getUint32(rp.Attrs[AttrAcctStatusType])
	bytesIn := getUint32(rp.Attrs[AttrAcctInputOctets])
	bytesOut := getUint32(rp.Attrs[AttrAcctOutputOctets])

	if user == "" {
		return fmt.Errorf("no User-Name attribute")
	}

	// Prefer IPv6 prefix over single address
	if ipv6Prefix != "" {
		ipv6 = ipv6Prefix
	}

	now := time.Now().Unix()

	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.sessionKey(user, acctSessionID)

	// Handle different accounting types
	switch statusType {
	case AcctStart:
		s := &Session{
			User:          user,
			Source:        "radius",
			IPv4:          ipv4,
			IPv6:          ipv6,
			MAC:           mac,
			NasIP:         nasIP,
			NasID:         nasID,
			AcctSessionID: acctSessionID,
			StartTime:     now,
			LastSeen:      now,
			Active:        true,
		}

		// Fetch device name from identity module
		if identity, ok := m.ctx.Service("identity").(core.Identity); ok {
			if ipv4 != "" {
				s.DeviceName = identity.Name(ipv4)
			} else if ipv6 != "" {
				// Extract just the IP for lookup (strip prefix if present)
				ip := ipv6
				if idx := strings.Index(ip, "/"); idx != -1 {
					ip = ip[:idx]
				}
				s.DeviceName = identity.Name(ip)
			}
		}

		m.sessions[key] = s
		m.updateUserAddrs(s)

		// Store in database
		m.ctx.Store.Exec(`
			INSERT INTO user_sessions (user, source, ipv4, ipv6, mac, nas_ip, nas_id, acct_session_id, start_ts, last_seen, bytes_in, bytes_out)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, user, "radius", ipv4, ipv6, mac, nasIP, nasID, acctSessionID, now, now, bytesIn, bytesOut)

	case AcctInterim:
		s, exists := m.sessions[key]
		if exists {
			s.LastSeen = now
			s.BytesIn = uint64(bytesIn)
			s.BytesOut = uint64(bytesOut)

			// Update database
			m.ctx.Store.Exec(`
				UPDATE user_sessions SET last_seen = ?, bytes_in = ?, bytes_out = ?
				WHERE user = ? AND acct_session_id = ?
			`, now, bytesIn, bytesOut, user, acctSessionID)
		}

	case AcctStop:
		s, exists := m.sessions[key]
		if exists {
			s.LastSeen = now
			s.StopTime = now
			s.Active = false
			s.BytesIn = uint64(bytesIn)
			s.BytesOut = uint64(bytesOut)

			// Update database
			m.ctx.Store.Exec(`
				UPDATE user_sessions SET last_seen = ?, stop_ts = ?, bytes_in = ?, bytes_out = ?
				WHERE user = ? AND acct_session_id = ?
			`, now, now, bytesIn, bytesOut, user, acctSessionID)
		}
	}

	// Send Accounting-Response
	m.sendRADIUSResponse(remoteAddr, rp.ID, rp.Auth)

	return nil
}

// verifyRADIUSAuth verifies the Request Authenticator (RFC 2866 3.3).
// Request Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
func (m *Module) verifyRADIUSAuth(packet []byte, auth [16]byte) bool {
	// Replace the authenticator field with zeros for verification
	zeroedPacket := make([]byte, len(packet))
	copy(zeroedPacket, packet)
	copy(zeroedPacket[4:20], make([]byte, 16))

	// Append the secret
	digest := md5.Sum(append(zeroedPacket, []byte(m.radiusSecret)...))

	return digest == auth
}

// sendRADIUSResponse sends an Accounting-Response packet.
func (m *Module) sendRADIUSResponse(addr *net.UDPAddr, id uint8, requestAuth [16]byte) {
	if m.radiusListener == nil {
		return
	}

	// Create response packet
	response := make([]byte, RADIUSHeaderLen)
	response[0] = RADIUSAcctResponse // Code
	response[1] = id                  // ID
	binary.BigEndian.PutUint16(response[2:4], uint16(RADIUSHeaderLen))

	// Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
	digest := md5.Sum(append(response[:4], append(requestAuth[:], []byte(m.radiusSecret)...)...))
	copy(response[4:20], digest[:])

	m.radiusListener.WriteToUDP(response, addr)
}

// Helper functions to extract RADIUS attributes

func getString(attrs [][]byte) string {
	if len(attrs) > 0 {
		return string(attrs[0])
	}
	return ""
}

func getIPv4(attrs [][]byte) string {
	if len(attrs) > 0 && len(attrs[0]) == 4 {
		return net.IP(attrs[0]).String()
	}
	return ""
}

func getIPv6(attrs [][]byte) string {
	if len(attrs) > 0 && len(attrs[0]) == 16 {
		return net.IP(attrs[0]).String()
	}
	return ""
}

// getIPv6Prefix extracts IPv6 address from Framed-IPv6-Prefix (RFC 3162)
// Format: 1 byte reserved + 1 byte prefix length + 16 bytes address
func getIPv6Prefix(attrs [][]byte) string {
	if len(attrs) > 0 && len(attrs[0]) >= 18 {
		prefix := int(attrs[0][1])
		ip := net.IP(attrs[0][2:18])
		return fmt.Sprintf("%s/%d", ip.String(), prefix)
	}
	return ""
}

func getMAC(attrs [][]byte) string {
	if len(attrs) > 0 {
		// MAC address can be in various formats: xx-xx-xx-xx-xx-xx, xx:xx:xx:xx:xx:xx, etc.
		mac := string(attrs[0])
		// Normalize to lowercase without separators for internal use
		return normalizeMac(mac)
	}
	return ""
}

func getUint32(attrs [][]byte) uint32 {
	if len(attrs) > 0 && len(attrs[0]) == 4 {
		return binary.BigEndian.Uint32(attrs[0])
	}
	return 0
}

func normalizeMac(mac string) string {
	// Remove common separators and convert to lowercase
	mac = string(mac)
	for _, sep := range []string{"-", ":", " ", "."} {
		mac = replaceAll(mac, sep, "")
	}
	return mac
}

func replaceAll(s, old, new string) string {
	for {
		idx := index(s, old)
		if idx == -1 {
			return s
		}
		s = s[:idx] + new + s[idx+len(old):]
	}
}

func index(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
