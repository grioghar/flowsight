package users

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ldapEntry caches group membership with TTL.
type ldapEntry struct {
	groups    []string
	fetchedAt time.Time
}

// LDAP BER encoding/decoding for LDAPv3 protocol
// Minimal implementation sufficient for bind and search operations.

// BER tags
const (
	berTagBoolean     = 0x01
	berTagInteger     = 0x02
	berTagOctetString = 0x04
	berTagNull        = 0x05
	berTagEnumerated  = 0x0a
	berTagSequence    = 0x30
	berClassContext   = 0x80
	berConstructed    = 0x20

	// LDAP message types
	ldapBindRequest       = 0
	ldapBindResponse      = 1
	ldapSearchRequest     = 3
	ldapSearchResultEntry = 4
	ldapSearchResultDone  = 5

	// LDAP search scope
	ldapScopeWholeSubtree = 2

	// LDAP result codes
	ldapResultSuccess = 0
)

type berValue struct {
	tag      byte
	value    []byte
	children []*berValue
}

// berEncode encodes a BER value to bytes.
func berEncode(v *berValue) []byte {
	var content []byte
	if len(v.value) > 0 {
		content = v.value
	} else if len(v.children) > 0 {
		for _, child := range v.children {
			content = append(content, berEncode(child)...)
		}
	}

	result := []byte{v.tag}
	result = append(result, berEncodeLength(len(content))...)
	result = append(result, content...)
	return result
}

// berEncodeLength encodes a length value in BER format.
func berEncodeLength(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	}
	var lengthBytes []byte
	for l > 0 {
		lengthBytes = append([]byte{byte(l & 0xff)}, lengthBytes...)
		l >>= 8
	}
	return append([]byte{0x80 | byte(len(lengthBytes))}, lengthBytes...)
}

// berDecode decodes BER values from a byte slice.
func berDecode(data []byte) (*berValue, int, error) {
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("data too short")
	}

	tag := data[0]
	length := int(data[1])
	offset := 2

	if length&0x80 != 0 {
		// Long form length
		lengthOctets := length & 0x7f
		if len(data) < 2+lengthOctets {
			return nil, 0, fmt.Errorf("data too short for length")
		}
		length = 0
		for i := 0; i < lengthOctets; i++ {
			length = (length << 8) | int(data[2+i])
		}
		offset = 2 + lengthOctets
	}

	if len(data) < offset+length {
		return nil, 0, fmt.Errorf("data too short for content")
	}

	v := &berValue{
		tag:   tag,
		value: data[offset : offset+length],
	}

	// Parse children if constructed
	if tag&berConstructed != 0 {
		content := data[offset : offset+length]
		offset := 0
		for offset < len(content) {
			child, read, err := berDecode(content[offset:])
			if err != nil {
				break
			}
			v.children = append(v.children, child)
			offset += read
		}
	}

	return v, offset + length, nil
}

// Helper encoding functions
func berInt(v int32) *berValue {
	var b []byte
	for i := 3; i >= 0; i-- {
		b = append(b, byte((v>>uint(i*8))&0xff))
	}
	for len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		b = b[1:]
	}
	return &berValue{tag: berTagInteger, value: b}
}

func berBool(v bool) *berValue {
	val := byte(0)
	if v {
		val = 0xff
	}
	return &berValue{tag: berTagBoolean, value: []byte{val}}
}

func berEnum(v int32) *berValue {
	var b []byte
	for i := 3; i >= 0; i-- {
		b = append(b, byte((v>>uint(i*8))&0xff))
	}
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return &berValue{tag: berTagEnumerated, value: b}
}

func berOctetString(s string) *berValue {
	return &berValue{tag: berTagOctetString, value: []byte(s)}
}

func berNull() *berValue {
	return &berValue{tag: berTagNull, value: []byte{}}
}

func berSequence(children ...*berValue) *berValue {
	return &berValue{tag: berTagSequence, children: children}
}

func berContextTag(tag byte, children ...*berValue) *berValue {
	t := berClassContext | berConstructed | tag
	return &berValue{tag: t, children: children}
}

// lookupUserGroupsLDAP performs LDAP bind and group lookup.
func (m *Module) lookupUserGroupsLDAP(user string) ([]string, error) {
	if m.ldapConfig == nil {
		return nil, fmt.Errorf("LDAP not configured")
	}

	cfg := m.ldapConfig

	// Parse server URL
	url := cfg.ServerURL
	if !strings.HasPrefix(url, "ldap://") && !strings.HasPrefix(url, "ldaps://") {
		url = "ldap://" + url
	}

	var scheme, host, port string
	if strings.HasPrefix(url, "ldaps://") {
		scheme = "ldaps"
		url = url[8:]
	} else {
		scheme = "ldap"
		url = url[7:]
	}

	if idx := strings.LastIndex(url, ":"); idx != -1 {
		host = url[:idx]
		port = url[idx+1:]
	} else {
		host = url
		if scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}

	// Connect
	var conn net.Conn
	var err error

	addr := net.JoinHostPort(host, port)
	if scheme == "ldaps" {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Bind
	msgID := int32(1)
	bindReq := berSequence(
		berInt(3), // LDAP version
		berOctetString(cfg.BindDN),
		berContextTag(0, berOctetString(cfg.BindPassword)), // Simple auth
	)
	msg := berSequence(berInt(msgID), berContextTag(ldapBindRequest, bindReq.children...))

	if _, err := conn.Write(berEncode(msg)); err != nil {
		return nil, fmt.Errorf("bind send failed: %w", err)
	}

	// Read bind response
	respData := make([]byte, 4096)
	n, err := conn.Read(respData)
	if err != nil {
		return nil, fmt.Errorf("bind response read failed: %w", err)
	}

	resp, _, err := berDecode(respData[:n])
	if err != nil {
		return nil, fmt.Errorf("bind response parse failed: %w", err)
	}

	// Check bind response result code
	if len(resp.children) < 2 {
		return nil, fmt.Errorf("invalid bind response")
	}
	bindResp := resp.children[1]
	if len(bindResp.children) == 0 {
		return nil, fmt.Errorf("invalid bind response")
	}
	resultCode := berDecodeInt(bindResp.children[0])
	if resultCode != ldapResultSuccess {
		return nil, fmt.Errorf("bind failed with code %d", resultCode)
	}

	// Search for user
	msgID = 2
	filter := buildFilter(cfg.UserFilter, user)
	searchReq := berSequence(
		berOctetString(cfg.BaseDN),
		berEnum(ldapScopeWholeSubtree),
		berEnum(0),     // derefAliases = never
		berInt(0),      // sizeLimit
		berInt(0),      // timeLimit
		berBool(false), // typesOnly
		filter,
		berSequence(berOctetString(cfg.GroupAttribute)), // attributes
	)
	msg = berSequence(berInt(msgID), berContextTag(ldapSearchRequest, searchReq.children...))

	if _, err := conn.Write(berEncode(msg)); err != nil {
		return nil, fmt.Errorf("search send failed: %w", err)
	}

	// Read search results
	var groups []string
	for {
		respData = make([]byte, 4096)
		n, err := conn.Read(respData)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("search response read failed: %w", err)
		}

		resp, _, err := berDecode(respData[:n])
		if err != nil {
			break
		}

		if len(resp.children) < 2 {
			break
		}

		protoOp := resp.children[1]

		// Check for SearchResultEntry (tag 0x64 = application 4)
		if protoOp.tag == (berClassContext | berConstructed | 4) {
			groups = extractGroups(protoOp, cfg.GroupAttribute)
		}

		// Check for SearchResultDone (tag 0x65 = application 5)
		if protoOp.tag == (berClassContext | berConstructed | 5) {
			break
		}
	}

	return groups, nil
}

// buildFilter creates a search filter from the template and username.
func buildFilter(template, username string) *berValue {
	// Replace {0} with escaped username
	filter := strings.ReplaceAll(template, "{0}", escapeLDAPFilter(username))

	// Parse simple filter: (attr=value)
	if strings.Contains(filter, "=") {
		parts := strings.Split(filter, "=")
		if len(parts) == 2 {
			attr := strings.TrimSpace(strings.TrimPrefix(parts[0], "("))
			val := strings.TrimSpace(strings.TrimSuffix(parts[1], ")"))
			// Equality match filter (tag 0xa3 = context 3)
			return &berValue{
				tag: berClassContext | berConstructed | 3,
				children: []*berValue{
					berOctetString(attr),
					berOctetString(val),
				},
			}
		}
	}

	// Fallback: presence filter
	return &berValue{
		tag: berClassContext | berConstructed | 3,
		children: []*berValue{
			berOctetString("objectClass"),
			berOctetString("*"),
		},
	}
}

// escapeLDAPFilter escapes special characters in LDAP filter values.
func escapeLDAPFilter(s string) string {
	replacements := []struct {
		old, new string
	}{
		{"*", "\\2a"},
		{"(", "\\28"},
		{")", "\\29"},
		{"\\", "\\5c"},
		{"\x00", "\\00"},
	}
	for _, r := range replacements {
		s = strings.ReplaceAll(s, r.old, r.new)
	}
	return s
}

// extractGroups extracts group membership from a search result entry.
func extractGroups(entry *berValue, groupAttr string) []string {
	var groups []string
	if len(entry.children) < 2 {
		return groups
	}

	// Second child is attributes (sequence of sequences)
	attrs := entry.children[1]
	for _, attr := range attrs.children {
		if len(attr.children) < 2 {
			continue
		}
		attrName := string(attr.children[0].value)
		if strings.EqualFold(attrName, groupAttr) {
			// Extract values from attribute
			vals := attr.children[1]
			for _, val := range vals.children {
				groupDN := string(val.value)
				groupName := extractCN(groupDN)
				if groupName != "" {
					groups = append(groups, groupName)
				}
			}
		}
	}
	return groups
}

// extractCN extracts the CN from an LDAP DN.
func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "cn=") {
			return part[3:]
		}
	}
	return ""
}

// berDecodeInt decodes an integer BER value.
func berDecodeInt(v *berValue) int32 {
	if len(v.value) == 0 {
		return 0
	}
	result := int32(0)
	for _, b := range v.value {
		result = (result << 8) | int32(b)
	}
	return result
}

// FakeLDAP server for testing (listens on 127.0.0.1 and responds with test data)
type fakeLDAPServer struct {
	listener net.Listener
	done     chan bool
}

// StartFakeLDAP starts an in-process fake LDAP server for testing.
func StartFakeLDAP() (*fakeLDAPServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	srv := &fakeLDAPServer{
		listener: listener,
		done:     make(chan bool),
	}

	go func() {
		for {
			select {
			case <-srv.done:
				return
			default:
			}

			listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleFakeLDAPConnection(conn)
		}
	}()

	return srv, nil
}

// Stop stops the fake LDAP server.
func (srv *fakeLDAPServer) Stop() {
	close(srv.done)
	srv.listener.Close()
}

// Addr returns the address the server is listening on.
func (srv *fakeLDAPServer) Addr() string {
	return srv.listener.Addr().String()
}

// handleFakeLDAPConnection handles a connection to the fake LDAP server.
func handleFakeLDAPConnection(conn net.Conn) {
	defer conn.Close()

	data := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(data)
		if err != nil {
			return
		}

		msg, _, err := berDecode(data[:n])
		if err != nil {
			return
		}

		if len(msg.children) < 2 {
			return
		}

		msgID := berDecodeInt(msg.children[0])
		protoOp := msg.children[1]

		// Handle bind request (tag 0x60 = application 0)
		if protoOp.tag == (berClassContext | berConstructed | 0) {
			// Send bind response (success)
			resp := berSequence(
				berInt(msgID),
				berContextTag(ldapBindResponse,
					berInt(ldapResultSuccess), // resultCode
					berOctetString(""),        // matchedDN
					berOctetString(""),        // diagnosticMessage
				),
			)
			conn.Write(berEncode(resp))
			continue
		}

		// Handle search request (tag 0x63 = application 3)
		if protoOp.tag == (berClassContext | berConstructed | 3) {
			// Send search result entry with fake groups
			entry := berSequence(
				berInt(msgID),
				berContextTag(ldapSearchResultEntry,
					berOctetString("uid=testuser,dc=example,dc=com"), // objectName
					berSequence( // attributes
						berSequence(
							berOctetString("memberOf"),
							berSequence(
								berOctetString("cn=admins,dc=example,dc=com"),
								berOctetString("cn=users,dc=example,dc=com"),
							),
						),
					),
				),
			)
			conn.Write(berEncode(entry))

			// Send search result done
			done := berSequence(
				berInt(msgID),
				berContextTag(ldapSearchResultDone,
					berInt(ldapResultSuccess),
					berOctetString(""),
					berOctetString(""),
				),
			)
			conn.Write(berEncode(done))
			return
		}
	}
}
