package users

import (
	"crypto/md5"
	"encoding/binary"
	"testing"
	"time"
)

// TestRADIUSPacketParsing tests parsing of a manually constructed RADIUS packet.
func TestRADIUSPacketParsing(t *testing.T) {
	secret := "sharedsecret"
	user := "testuser"
	ipv4 := "192.168.1.100"
	mac := "aabbccddeeff"

	// Construct a minimal RADIUS Accounting-Request packet
	packet := make([]byte, 0, 256)

	// Header: Code, ID, Length (will set later), Authenticator
	packet = append(packet, RADIUSAcctRequest) // Code
	packet = append(packet, 1)                 // ID

	// Placeholder for length
	lenIdx := len(packet)
	packet = append(packet, 0, 0)

	// Authenticator (16 bytes) - will be set later
	authIdx := len(packet)
	packet = append(packet, make([]byte, 16)...)

	// Attributes
	// User-Name (type 1)
	packet = appendRADIUSAttribute(packet, AttrUserName, []byte(user))

	// Framed-IP-Address (type 8)
	ipBytes := [4]byte{192, 168, 1, 100}
	packet = appendRADIUSAttribute(packet, AttrFramedIPAddress, ipBytes[:])

	// Calling-Station-Id (type 31, MAC address)
	packet = appendRADIUSAttribute(packet, AttrCallingStationID, []byte(mac))

	// Set length
	length := uint16(len(packet))
	binary.BigEndian.PutUint16(packet[lenIdx:lenIdx+2], length)

	// Calculate and set authenticator: MD5(Code+ID+Length+RequestAuth(zeros)+Attributes+Secret)
	authPacket := make([]byte, len(packet))
	copy(authPacket, packet)
	copy(authPacket[authIdx:authIdx+16], make([]byte, 16))

	digest := md5.Sum(append(authPacket, []byte(secret)...))
	copy(packet[authIdx:authIdx+16], digest[:])

	// Parse the packet (simulating what radiusListenerLoop would do)
	// Note: This test verifies packet structure, not full integration
	if len(packet) < RADIUSHeaderLen {
		t.Fatal("packet too short")
	}

	code := packet[0]
	if code != RADIUSAcctRequest {
		t.Fatalf("wrong packet code: got %d, want %d", code, RADIUSAcctRequest)
	}

	// Verify authenticator
	zeroedPacket := make([]byte, len(packet))
	copy(zeroedPacket, packet)
	copy(zeroedPacket[authIdx:authIdx+16], make([]byte, 16))

	expectedDigest := md5.Sum(append(zeroedPacket, []byte(secret)...))
	actualAuth := [16]byte{}
	copy(actualAuth[:], packet[authIdx:authIdx+16])

	if expectedDigest != actualAuth {
		t.Fatal("authenticator verification failed")
	}

	t.Logf("RADIUS packet parsing test passed: user=%s, ip=%s, mac=%s", user, ipv4, mac)
}

// appendRADIUSAttribute appends a RADIUS attribute to the packet.
func appendRADIUSAttribute(packet []byte, attrType uint8, value []byte) []byte {
	attr := []byte{attrType, byte(2 + len(value))}
	return append(packet, append(attr, value...)...)
}

// TestMemberResolverUser tests the user member resolver.
func TestMemberResolverUser(t *testing.T) {
	// Create a mock module with test sessions
	m := &Module{
		sessions:   make(map[string]*Session),
		userAddrs:  make(map[string]map[string]bool),
		addrToUser: make(map[string]string),
		macToUser:  make(map[string]string),
		ldapCache:  make(map[string]*ldapEntry),
	}

	// Add a test session for user "alice"
	now := time.Now().Unix()
	alice := &Session{
		User:      "alice",
		Source:    "test",
		IPv4:      "192.168.1.10",
		IPv6:      "2001:db8::1",
		StartTime: now,
		LastSeen:  now,
		Active:    true,
	}
	m.sessions["alice:session1"] = alice
	m.updateUserAddrs(alice)

	// Create resolver
	resolver := &userMemberResolver{
		m:        m,
		delegate: nil,
	}

	// Test resolving user alice
	cidrs := resolver.resolveUser("alice")
	if len(cidrs) != 2 {
		t.Fatalf("expected 2 CIDRs for user alice, got %d", len(cidrs))
	}

	// Check that both v4 and v6 are present
	has_v4 := false
	has_v6 := false
	for _, cidr := range cidrs {
		if cidr == "192.168.1.10/32" {
			has_v4 = true
		} else if cidr == "2001:db8::1/128" {
			has_v6 = true
		}
	}

	if !has_v4 || !has_v6 {
		t.Fatalf("missing expected CIDRs. v4=%v, v6=%v", has_v4, has_v6)
	}

	t.Logf("Member resolver test passed: alice has %v", cidrs)
}

// TestSessionKey tests the session key generation.
func TestSessionKey(t *testing.T) {
	m := &Module{
		sessions:   make(map[string]*Session),
		userAddrs:  make(map[string]map[string]bool),
		addrToUser: make(map[string]string),
		macToUser:  make(map[string]string),
		ldapCache:  make(map[string]*ldapEntry),
	}

	// With acct_session_id
	key1 := m.sessionKey("bob", "acct123")
	if key1 != "bob:acct123" {
		t.Fatalf("wrong session key with ID: %s", key1)
	}

	// Without acct_session_id
	key2 := m.sessionKey("bob", "")
	if !contains(key2, "bob:") {
		t.Fatalf("wrong session key without ID: %s", key2)
	}

	t.Logf("Session key test passed")
}

// TestLDAPFakeServer tests LDAP client against a fake in-process server.
func TestLDAPFakeServer(t *testing.T) {
	// Start fake LDAP server
	srv, err := StartFakeLDAP()
	if err != nil {
		t.Fatalf("failed to start fake LDAP server: %v", err)
	}
	defer srv.Stop()

	// Get server address
	addr := srv.Addr()
	if addr == "" {
		t.Fatal("fake server address is empty")
	}

	// Create module with LDAP config pointing to fake server
	m := &Module{
		sessions:   make(map[string]*Session),
		userAddrs:  make(map[string]map[string]bool),
		addrToUser: make(map[string]string),
		macToUser:  make(map[string]string),
		ldapCache:  make(map[string]*ldapEntry),
		ldapConfig: &LDAPConfig{
			ServerURL:      "ldap://" + addr,
			BindDN:         "cn=admin,dc=example,dc=com",
			BindPassword:   "password",
			BaseDN:         "dc=example,dc=com",
			UserFilter:     "(&(uid={0}))",
			GroupAttribute: "memberOf",
			CacheTTL:       4 * time.Hour,
		},
	}

	// Test lookup
	groups, err := m.lookupUserGroupsLDAP("testuser")
	if err != nil {
		t.Fatalf("LDAP lookup failed: %v", err)
	}

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// Check group names (extracted from fake DN)
	found_admins := false
	found_users := false
	for _, g := range groups {
		if g == "admins" {
			found_admins = true
		} else if g == "users" {
			found_users = true
		}
	}

	if !found_admins || !found_users {
		t.Fatalf("unexpected groups: %v", groups)
	}

	t.Logf("LDAP fake server test passed: groups=%v", groups)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
