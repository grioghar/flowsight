// Package users tracks user-to-device mappings via RADIUS accounting and
// optional LDAP/AD integration, enabling policies to target users and user groups.
// Identity remains at the device level; this module extends that with optional
// user-derived metadata.
package users

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx *core.Context
	log *slog.Logger

	mu              sync.RWMutex
	radiusListener  *net.UDPConn
	radiusAddr      string
	radiusSecret    string
	radiusClientIPs map[string]bool // Allowed client CIDRs

	// Session tracking: session_id -> Session
	sessions map[string]*Session
	// User to active addresses: user -> {ips/cidrs}
	userAddrs map[string]map[string]bool
	// IP/MAC to user: for fast lookups
	addrToUser map[string]string
	macToUser  map[string]string

	// LDAP cache: user -> groups, with TTL
	ldapCache     map[string]*ldapEntry
	ldapCacheLock sync.RWMutex
	ldapConfig    *LDAPConfig

	lastErr  string
	lastErrT time.Time
}

type Session struct {
	User          string `json:"user"`
	Source        string `json:"source"` // "radius", "ldap", "manual"
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	MAC           string `json:"mac,omitempty"`
	NasIP         string `json:"nas_ip,omitempty"`
	NasID         string `json:"nas_id,omitempty"`
	AcctSessionID string `json:"acct_session_id,omitempty"`
	StartTime     int64  `json:"start_ts"`
	LastSeen      int64  `json:"last_seen"`
	StopTime      int64  `json:"stop_ts,omitempty"`
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	Active        bool   `json:"active"`
	DeviceName    string `json:"device_name,omitempty"` // From identity module
}

type LDAPConfig struct {
	ServerURL      string
	BindDN         string
	BindPassword   string
	BaseDN         string
	UserFilter     string
	GroupAttribute string
	CacheTTL       time.Duration
	StartTLS       bool
}

type SettingRADIUS struct {
	Enabled          bool     `json:"enabled"`
	ListenAddr       string   `json:"listen_addr"`
	Secret           string   `json:"secret"`
	AllowedClientIPs []string `json:"allowed_client_ips"`
}

type SettingLDAP struct {
	Enabled        bool   `json:"enabled"`
	ServerURL      string `json:"server_url"`
	BindDN         string `json:"bind_dn"`
	BindPassword   string `json:"bind_password"`
	BaseDN         string `json:"base_dn"`
	UserFilter     string `json:"user_filter"`
	GroupAttribute string `json:"group_attribute"`
	CacheTTLHours  int    `json:"cache_ttl_hours"`
	StartTLS       bool   `json:"start_tls"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:    "users",
		Version: "1.0",
		After:   []string{"identity"},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.log = ctx.Log
	m.sessions = make(map[string]*Session)
	m.userAddrs = make(map[string]map[string]bool)
	m.addrToUser = make(map[string]string)
	m.macToUser = make(map[string]string)
	m.ldapCache = make(map[string]*ldapEntry)
	m.radiusClientIPs = make(map[string]bool)

	// Register routes
	m.registerRoutes()

	// Register member resolver wrapper
	m.publishMemberResolver()

	// Create/load settings
	m.loadSettings()

	// Start RADIUS listener if enabled
	if err := m.startRADIUS(); err != nil {
		m.lastErr = err.Error()
		m.lastErrT = time.Now()
		m.log.Warn("Failed to start RADIUS listener", "error", err)
	}

	// Load existing sessions from database
	if err := m.loadSessions(); err != nil {
		m.log.Warn("Failed to load existing sessions", "error", err)
	}

	// Register UI panel
	m.ctx.Panel(core.Panel{
		ID:    "users",
		Title: "Users",
		Group: "Inventory",
		Order: 140,
		Icon:  "users",
	})

	return nil
}

func (m *Module) loadSettings() {
	// Load RADIUS settings
	var radiusSetting SettingRADIUS
	if m.ctx.Store.KVGet("users:radius", &radiusSetting) && radiusSetting.Enabled {
		m.radiusAddr = radiusSetting.ListenAddr
		m.radiusSecret = radiusSetting.Secret
		for _, cidr := range radiusSetting.AllowedClientIPs {
			m.radiusClientIPs[cidr] = true
		}
	}

	// Load LDAP settings
	var ldapSetting SettingLDAP
	if m.ctx.Store.KVGet("users:ldap", &ldapSetting) && ldapSetting.Enabled {
		cacheTTL := time.Duration(ldapSetting.CacheTTLHours) * time.Hour
		if cacheTTL == 0 {
			cacheTTL = 4 * time.Hour
		}
		m.ldapConfig = &LDAPConfig{
			ServerURL:      ldapSetting.ServerURL,
			BindDN:         ldapSetting.BindDN,
			BindPassword:   ldapSetting.BindPassword,
			BaseDN:         ldapSetting.BaseDN,
			UserFilter:     ldapSetting.UserFilter,
			GroupAttribute: ldapSetting.GroupAttribute,
			CacheTTL:       cacheTTL,
			StartTLS:       ldapSetting.StartTLS,
		}
	}
}

func (m *Module) registerRoutes() {
	m.ctx.Route("GET", "/api/users", m.apiListUsers,
		core.Doc("Active users and their current sessions"),
		core.Params("user", "filter by username"))

	m.ctx.Route("GET", "/api/users/{name}", m.apiGetUser,
		core.Doc("User details and session history"))

	m.ctx.Route("GET", "/api/users/status", m.apiStatus,
		core.Doc("Module status and configuration"),
		core.Params("detail", "include LDAP cache status if true"))

	m.ctx.Route("POST", "/api/users/session", m.apiAddSession,
		core.Write(),
		core.Doc("Record a user session (for captive portals, scripts)"),
		core.Params("user", "username", "ipv4", "IPv4 address", "ipv6", "IPv6 address or prefix",
			"mac", "MAC address", "nas_ip", "NAS IP", "nas_id", "NAS identifier"))

	m.ctx.Route("POST", "/api/users/ldap/test", m.apiTestLDAP,
		core.Write(),
		core.Doc("Test LDAP connection and user lookup (non-persistent)"),
		core.Params("user", "username to test"))
}

// loadSessions loads sessions from the database, filtering for active ones.
func (m *Module) loadSessions() error {
	rows, err := m.ctx.Store.Rows(`
		SELECT user, source, ipv4, ipv6, mac, nas_ip, nas_id, acct_session_id,
		       start_ts, last_seen, stop_ts, bytes_in, bytes_out
		FROM user_sessions
		WHERE stop_ts IS NULL OR stop_ts > ?
		ORDER BY last_seen DESC
	`, time.Now().Unix()-86400) // Keep active + last 24h stopped

	if err != nil {
		return err
	}

	for _, row := range rows {
		s := Session{
			User:          rowGetString(row, "user"),
			Source:        rowGetString(row, "source"),
			IPv4:          rowGetString(row, "ipv4"),
			IPv6:          rowGetString(row, "ipv6"),
			MAC:           rowGetString(row, "mac"),
			NasIP:         rowGetString(row, "nas_ip"),
			NasID:         rowGetString(row, "nas_id"),
			AcctSessionID: rowGetString(row, "acct_session_id"),
			StartTime:     rowGetInt(row, "start_ts"),
			LastSeen:      rowGetInt(row, "last_seen"),
			StopTime:      rowGetInt(row, "stop_ts"),
			BytesIn:       uint64(rowGetInt(row, "bytes_in")),
			BytesOut:      uint64(rowGetInt(row, "bytes_out")),
		}

		s.Active = s.StopTime == 0

		// Fetch device name from identity module
		if identity, ok := m.ctx.Service("identity").(core.Identity); ok {
			if s.IPv4 != "" {
				s.DeviceName = identity.Name(s.IPv4)
			} else if s.IPv6 != "" {
				s.DeviceName = identity.Name(s.IPv6)
			}
		}

		m.sessions[m.sessionKey(s.User, s.AcctSessionID)] = &s
		m.updateUserAddrs(&s)
	}

	return nil
}

// Helper functions to extract values from row maps
func rowGetString(row map[string]any, key string) string {
	if v, ok := row[key].(string); ok {
		return v
	}
	return ""
}

func rowGetInt(row map[string]any, key string) int64 {
	if v, ok := row[key].(int64); ok {
		return v
	}
	return 0
}

// updateUserAddrs updates the in-memory user->addresses mapping.
func (m *Module) updateUserAddrs(s *Session) {
	if _, exists := m.userAddrs[s.User]; !exists {
		m.userAddrs[s.User] = make(map[string]bool)
	}

	if s.IPv4 != "" {
		m.userAddrs[s.User][s.IPv4+"/32"] = true
		m.addrToUser[s.IPv4] = s.User
	}
	if s.IPv6 != "" {
		// Could be a single IP or a prefix
		if strings.Contains(s.IPv6, "/") {
			m.userAddrs[s.User][s.IPv6] = true
			// For lookup, extract the prefix
			ip := strings.Split(s.IPv6, "/")[0]
			m.addrToUser[ip] = s.User
		} else {
			m.userAddrs[s.User][s.IPv6+"/128"] = true
			m.addrToUser[s.IPv6] = s.User
		}
	}
	if s.MAC != "" {
		m.macToUser[s.MAC] = s.User
	}
}

func (m *Module) sessionKey(user, acctSessionID string) string {
	if acctSessionID != "" {
		return user + ":" + acctSessionID
	}
	return user + ":" + fmt.Sprintf("%d", time.Now().Unix())
}

// API Handlers

func (m *Module) apiListUsers(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filter := r.URL.Query().Get("user")

	seen := make(map[string]*Session)
	for _, s := range m.sessions {
		if filter != "" && s.User != filter {
			continue
		}
		// Keep the most recent session per user
		if existing, ok := seen[s.User]; !ok || existing.LastSeen < s.LastSeen {
			seen[s.User] = s
		}
	}

	users := make([]*Session, 0, len(seen))
	for _, s := range seen {
		users = append(users, s)
	}

	return map[string]any{
		"users": users,
		"count": len(users),
	}, nil
}

func (m *Module) apiGetUser(r *core.Req) (any, error) {
	user := r.Params["name"]

	m.mu.RLock()
	var sessions []*Session
	for _, s := range m.sessions {
		if s.User == user {
			sessions = append(sessions, s)
		}
	}
	m.mu.RUnlock()

	// Get groups from LDAP cache
	groups := m.getUserGroups(user)

	return map[string]any{
		"user":     user,
		"sessions": sessions,
		"groups":   groups,
	}, nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := map[string]any{
		"active_sessions": len(m.sessions),
		"active_users":    len(m.userAddrs),
	}

	if m.lastErr != "" {
		status["last_error"] = m.lastErr
		status["last_error_time"] = m.lastErrT.Unix()
	}

	if m.radiusAddr != "" {
		status["radius_enabled"] = true
		status["radius_addr"] = m.radiusAddr
	}

	if m.ldapConfig != nil {
		detail := r.URL.Query().Get("detail") == "true"
		status["ldap_enabled"] = true
		status["ldap_server"] = m.ldapConfig.ServerURL
		if detail {
			m.ldapCacheLock.RLock()
			status["ldap_cache_size"] = len(m.ldapCache)
			m.ldapCacheLock.RUnlock()
		}
	}

	return status, nil
}

func (m *Module) apiAddSession(r *core.Req) (any, error) {
	user := r.URL.Query().Get("user")
	ipv4 := r.URL.Query().Get("ipv4")
	ipv6 := r.URL.Query().Get("ipv6")
	mac := strings.ToLower(r.URL.Query().Get("mac"))
	nasIP := r.URL.Query().Get("nas_ip")
	nasID := r.URL.Query().Get("nas_id")

	if user == "" {
		return nil, core.BadRequest("user is required")
	}

	now := time.Now().Unix()
	s := &Session{
		User:      user,
		Source:    "manual",
		IPv4:      ipv4,
		IPv6:      ipv6,
		MAC:       mac,
		NasIP:     nasIP,
		NasID:     nasID,
		StartTime: now,
		LastSeen:  now,
		Active:    true,
	}

	m.mu.Lock()
	key := m.sessionKey(user, "")
	m.sessions[key] = s
	m.updateUserAddrs(s)
	m.mu.Unlock()

	// Store in database
	if err := m.ctx.Store.Exec(`
		INSERT INTO user_sessions (user, source, ipv4, ipv6, mac, nas_ip, nas_id, start_ts, last_seen, bytes_in, bytes_out)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
	`, user, "manual", ipv4, ipv6, mac, nasIP, nasID, now, now); err != nil {
		m.log.Warn("Failed to store session", "error", err)
		return nil, core.Errorf(500, "Failed to store session")
	}

	return map[string]any{
		"status": "created",
		"user":   user,
	}, nil
}

func (m *Module) apiTestLDAP(r *core.Req) (any, error) {
	if m.ldapConfig == nil {
		return nil, core.BadRequest("LDAP not configured")
	}

	user := r.URL.Query().Get("user")
	if user == "" {
		return nil, core.BadRequest("user is required")
	}

	// Test connection and lookup without caching
	groups, err := m.lookupUserGroupsLDAP(user)
	if err != nil {
		return nil, core.Errorf(500, "%v", err)
	}

	return map[string]any{
		"user":   user,
		"groups": groups,
	}, nil
}

// Helper to get user groups from LDAP cache or lookup
func (m *Module) getUserGroups(user string) []string {
	m.ldapCacheLock.RLock()
	entry, exists := m.ldapCache[user]
	m.ldapCacheLock.RUnlock()

	if exists && time.Since(entry.fetchedAt) < m.ldapConfig.CacheTTL {
		return entry.groups
	}

	if m.ldapConfig != nil {
		groups, err := m.lookupUserGroupsLDAP(user)
		if err == nil {
			m.ldapCacheLock.Lock()
			m.ldapCache[user] = &ldapEntry{
				groups:    groups,
				fetchedAt: time.Now(),
			}
			m.ldapCacheLock.Unlock()
			return groups
		}
	}

	return nil
}

// startRADIUS starts the RADIUS accounting listener.
func (m *Module) startRADIUS() error {
	if m.radiusAddr == "" || m.radiusSecret == "" {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", m.radiusAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	m.radiusListener = conn
	go m.radiusListenerLoop()

	m.log.Info("RADIUS accounting listener started", "addr", m.radiusAddr)
	return nil
}

// radiusListenerLoop handles incoming RADIUS packets.
func (m *Module) radiusListenerLoop() {
	defer m.radiusListener.Close()

	buffer := make([]byte, 4096)
	for {
		n, remoteAddr, err := m.radiusListener.ReadFromUDP(buffer)
		if err != nil {
			m.mu.Lock()
			m.lastErr = fmt.Sprintf("RADIUS read error: %v", err)
			m.lastErrT = time.Now()
			m.mu.Unlock()
			break
		}

		// Check if client IP is allowed
		if !m.isAllowedRADIUSClient(remoteAddr.IP.String()) {
			continue
		}

		// Parse RADIUS packet
		packet := buffer[:n]
		if err := m.handleRADIUSAccounting(packet, remoteAddr); err != nil {
			m.log.Debug("RADIUS packet error", "addr", remoteAddr, "error", err)
		}
	}
}

// isAllowedRADIUSClient checks if the client IP is in the allowed list.
func (m *Module) isAllowedRADIUSClient(ip string) bool {
	if len(m.radiusClientIPs) == 0 {
		return true // No whitelist = allow all
	}

	// Check against allowed CIDR list
	clientIP := net.ParseIP(ip)
	for cidr := range m.radiusClientIPs {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			if network.Contains(clientIP) {
				return true
			}
		}
	}
	return false
}

func (m *Module) Stop() {
	m.mu.Lock()
	if m.radiusListener != nil {
		m.radiusListener.Close()
	}
	m.mu.Unlock()
}
