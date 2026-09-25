package inspect

// The pf state table as `pfctl -ss -vv` prints it on FreeBSD 13 to 15.
//
// Each state is a small block: a header line at column zero
//
//	vtnet0 tcp 192.168.1.119:52034 -> 142.250.190.46:443       ESTABLISHED:ESTABLISHED
//	vtnet0 udp 192.168.1.53:53 <- 192.168.1.5:41523              MULTIPLE:SINGLE
//	all icmp 192.168.1.5:1 -> 8.8.8.8:1       0:0
//	vtnet1 tcp 10.0.0.5:44321 (192.168.0.9:44321) -> 1.2.3.4:443  ESTABLISHED:ESTABLISHED
//	vtnet0 tcp 2600:1700::9[52034] -> 2607:f8b0::200e[443]      ESTABLISHED:ESTABLISHED
//
// followed by indented detail lines, of which the useful one reads
//
//	age 00:01:02, expires in 23:59:58, 1234:5678 pkts, 123456:654321 bytes, rule 12
//
// (or "anchor 3, rule 12", or ages like "45s"). A parenthesised address is
// the pre-NAT one and is kept as the source when it is on the source side.
// Lines starting with whitespace are never headers: the -vv sequence lines
// begin with "[" and that is what a naive parser mistook for a protocol.

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	pfHeaderRe = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)(?:\s+\((\S+)\))?\s+(->|<-)\s+(\S+)(?:\s+\((\S+)\))?\s+(\S+)\s*$`)
	pfAgeRe    = regexp.MustCompile(`age\s+([0-9:smhd]+),\s+expires in\s+([0-9:smhd]+),\s+(\d+):(\d+)\s+pkts,\s+(\d+):(\d+)\s+bytes(?:,\s+anchor\s+\d+)?(?:,\s+rule\s+(\d+))?`)
)

// parsePFStates reads the whole table.
func parsePFStates(out string, now time.Time) []*PFState {
	var states []*PFState
	var cur *PFState
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if cur == nil {
				continue
			}
			if m := pfAgeRe.FindStringSubmatch(line); m != nil {
				cur.Age = pfSeconds(m[1])
				cur.Expires = pfSeconds(m[2])
				cur.PktsSrc, _ = strconv.ParseInt(m[3], 10, 64)
				cur.PktsDst, _ = strconv.ParseInt(m[4], 10, 64)
				cur.BytesSrc, _ = strconv.ParseInt(m[5], 10, 64)
				cur.BytesDst, _ = strconv.ParseInt(m[6], 10, 64)
				if m[7] != "" {
					cur.RuleID, _ = strconv.Atoi(m[7])
				}
			}
			continue
		}
		m := pfHeaderRe.FindStringSubmatch(line)
		if m == nil {
			cur = nil
			continue
		}
		src, dst := m[3], m[6]
		if m[4] != "" { // NATed source: the real host is in parentheses
			src = m[4]
		}
		if m[7] != "" {
			dst = m[7]
		}
		sh, sp := pfHostPort(src)
		dh, dp := pfHostPort(dst)
		dir := "out"
		if m[5] == "<-" {
			dir = "in"
		}
		cur = &PFState{Interface: m[1], Proto: strings.ToLower(m[2]), Src: sh, SrcPort: sp, Dst: dh, DstPort: dp,
			Direction: dir, State: m[8], Timestamp: now}
		states = append(states, cur)
	}
	return states
}

// pfHostPort splits "1.2.3.4:443" and "2600::1[443]"; a bare address has
// port 0.
func pfHostPort(s string) (string, int) {
	if i := strings.LastIndex(s, "["); i > 0 && strings.HasSuffix(s, "]") {
		p, _ := strconv.Atoi(s[i+1 : len(s)-1])
		return s[:i], p
	}
	if strings.Count(s, ":") == 1 {
		i := strings.LastIndex(s, ":")
		p, _ := strconv.Atoi(s[i+1:])
		return s[:i], p
	}
	return s, 0
}

// pfSeconds reads "00:01:02", "45s", "3m", "2h".
func pfSeconds(s string) int {
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		total := 0
		for _, p := range parts {
			n, _ := strconv.Atoi(p)
			total = total*60 + n
		}
		return total
	}
	n, _ := strconv.Atoi(strings.TrimRight(s, "smhd"))
	switch {
	case strings.HasSuffix(s, "m"):
		return n * 60
	case strings.HasSuffix(s, "h"):
		return n * 3600
	case strings.HasSuffix(s, "d"):
		return n * 86400
	}
	return n
}
