package egress

// Reading pf's live state table.
//
// A proxy log line is written when a session closes. A device that spends
// twenty minutes uploading appears in it once, twenty minutes late, which is
// the wrong end of the event for anyone who wants to notice data leaving.
//
// pf already counts every byte of every open connection and updates the
// counters continuously, so that is what this reads. It covers what the
// proxy never sees: pinned sessions, spliced sessions, QUIC on UDP 443,
// VPN and mesh tunnels, and every protocol that is not HTTP at all.
//
// The output of `pfctl -ss -v` is three lines per state:
//
//	all tcp 127.0.0.1:3129 (140.82.114.3:443) <- 10.99.0.162:59216  ESTABLISHED:ESTABLISHED
//	   [2837096760 + 392192] wscale 7  [2817892562 + 65792] wscale 10
//	   age 00:01:09, expires in 00:00:24, 249:432 pkts, 14863:616615 bytes, anchor 4
//
// The two byte counters follow the arrow: the first counts the direction the
// arrow points, the second counts the reply. So in the line above, which a
// device on this network opened through the proxy, 14863 bytes went from
// 10.99.0.162 towards 127.0.0.1:3129 and 616615 came back. Which of those is
// "leaving this network" therefore depends on both the arrow and which end
// is local, and getting it backwards would report every download as an
// upload. states_test.go pins it against a real capture.

import (
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// State is one live connection as pf sees it.
type State struct {
	Proto    string
	Local    string // the address on this network
	Peer     string // the address on the far side
	PeerPort int
	Out      int64 // bytes the local address has sent
	In       int64 // bytes it has received
	Age      time.Duration
	Rule     string

	// outFirst records which way round pf printed the counters for this
	// state, decided from the arrow and which end is local.
	outFirst bool
}

// Key identifies a state across samples.
func (s State) Key() string {
	return s.Local + "|" + s.Peer + "|" + strconv.Itoa(s.PeerPort) + "|" + s.Proto
}

// readStates runs pfctl and parses what it prints. isLocal decides which end
// of a state belongs to this network, because pf prints a redirected state
// with the proxy first and an ordinary outbound state with the gateway first.
func readStates(isLocal func(string) bool) ([]State, error) {
	out, err := exec.Command("pfctl", "-ss", "-v").Output()
	if err != nil {
		return nil, err
	}
	return parseStates(string(out), isLocal), nil
}

// isLoopback recognises the proxy's own end of a redirected session. It has
// to be excluded explicitly: a redirect names 127.0.0.1 as one endpoint, and
// the identity module quite correctly calls that local, which would make both
// ends of every intercepted session look local and discard it.
func isLoopback(ip string) bool {
	return ip == "::1" || strings.HasPrefix(ip, "127.")
}

func parseStates(text string, isLocal func(string) bool) []State {
	// A device is a local address that is not the proxy's own loopback end.
	device := func(ip string) bool { return !isLoopback(ip) && isLocal(ip) }
	var states []State
	var cur *State
	flush := func() {
		if cur != nil && cur.Local != "" && cur.Peer != "" {
			states = append(states, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flush()
			cur = parseHeader(trimmed, device)
			continue
		}
		if cur == nil {
			continue
		}
		if strings.Contains(trimmed, "bytes") {
			parseCounters(trimmed, cur)
		}
	}
	flush()
	return states
}

// parseHeader reads the first line of a state: interface, protocol, the two
// endpoints, an optional NAT address in parentheses, and the arrow.
func parseHeader(line string, isDevice func(string) bool) *State {
	f := strings.Fields(line)
	if len(f) < 4 {
		return nil
	}
	proto := f[1]
	switch proto {
	case "tcp", "udp":
	default:
		return nil // icmp and the rest carry no payload worth watching
	}
	// Endpoints are the fields around the arrow, ignoring the NAT address in
	// parentheses and the state flags at the end.
	arrow := -1
	for i, x := range f {
		if x == "->" || x == "<-" {
			arrow = i
			break
		}
	}
	if arrow < 0 {
		return nil
	}
	var left, right string
	for i := 2; i < arrow; i++ {
		if !strings.HasPrefix(f[i], "(") {
			left = f[i]
		}
	}
	if arrow+1 < len(f) {
		right = f[arrow+1]
	}
	if left == "" || right == "" {
		return nil
	}
	lh, _ := splitHostPort(left)
	rh, rp := splitHostPort(right)
	// The first counter measures the direction the arrow points: towards the
	// left address for "<-", towards the right address for "->". So the first
	// counter is this network's upload exactly when the local end is the one
	// the arrow points away from.
	pointsLeft := f[arrow] == "<-"
	st := &State{Proto: proto}
	switch {
	case isDevice(rh) && !isDevice(lh):
		// A redirected session: the proxy is named first and the device
		// second, with the address the device actually asked for in the
		// parentheses. That address, not the proxy, is where the data is
		// going, so it is the one worth reporting.
		st.Local, st.Peer, st.PeerPort = rh, lh, portOf(left)
		if nh, np := natAddr(f, arrow); nh != "" && !isDevice(nh) {
			st.Peer, st.PeerPort = nh, np
		}
		st.outFirst = pointsLeft
	case isDevice(lh) && !isDevice(rh):
		st.Local, st.Peer, st.PeerPort = lh, rh, rp
		st.outFirst = !pointsLeft
	default:
		// Neither end is local as printed, which is an ordinary outbound
		// session: the gateway's own address is on the wire and the device is
		// in the parentheses.
		nat, _ := natAddr(f, arrow)
		if nat == "" || !isDevice(nat) {
			return nil
		}
		st.Local, st.Peer, st.PeerPort = nat, rh, rp
		st.outFirst = !pointsLeft
	}
	return st
}

// natAddr is the address pf prints in parentheses: the original source of a
// translated outbound session, or the original destination of a redirected
// one. Which it is follows from whether it belongs to this network.
func natAddr(f []string, arrow int) (string, int) {
	for i := 2; i < arrow; i++ {
		if strings.HasPrefix(f[i], "(") {
			return splitHostPort(strings.Trim(f[i], "()"))
		}
	}
	return "", 0
}

// parseCounters reads "age 00:01:09, ... 249:432 pkts, 14863:616615 bytes".
func parseCounters(line string, st *State) {
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "age "):
			st.Age = parseAge(strings.TrimPrefix(part, "age "))
		case strings.HasSuffix(part, " bytes"):
			a, b, ok := pair(strings.TrimSuffix(part, " bytes"))
			if !ok {
				continue
			}
			if st.outFirst {
				st.Out, st.In = a, b
			} else {
				st.In, st.Out = a, b
			}
		case strings.HasPrefix(part, "anchor ") || strings.HasPrefix(part, "rule "):
			st.Rule = part
		}
	}
}

func pair(s string) (int64, int64, bool) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, 0, false
	}
	x, err1 := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
	y, err2 := strconv.ParseInt(strings.TrimSpace(b), 10, 64)
	return x, y, err1 == nil && err2 == nil
}

func parseAge(s string) time.Duration {
	f := strings.Split(strings.TrimSpace(s), ":")
	if len(f) != 3 {
		return 0
	}
	h, _ := strconv.Atoi(f[0])
	m, _ := strconv.Atoi(f[1])
	sec, _ := strconv.Atoi(f[2])
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
}

// splitHostPort handles "1.2.3.4:443" and "[fd00::1]:443".
func splitHostPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			p := 0
			if len(s) > i+2 && s[i+1] == ':' {
				p, _ = strconv.Atoi(s[i+2:])
			}
			return s[1:i], p
		}
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	// An IPv6 address without brackets has more than one colon.
	if strings.Count(s, ":") > 1 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	return s[:i], p
}

func portOf(s string) int { _, p := splitHostPort(s); return p }
