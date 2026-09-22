package qos

// Turning "this matters more than that" into rules a firewall can act on.
//
// A rule is written the way an operator would say it out loud:
//
//	192.168.1.178 = low          that host yields to everything else
//	redgifs.com   = high         that service goes first
//	10.0.5.0/24   = low, 20      that subnet is also capped at 20 Mbit/s
//	backup.example = 5           no class change, just a ceiling
//
// The left side is an address, a CIDR or a domain. A domain is resolved to
// the addresses the network has actually been seen talking to, because a pf
// table holds addresses and nothing else; a name nobody has looked up yet
// simply matches nothing until they do.

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Class is one priority band. There are three on purpose: the useful
// distinction is "before everything", "normally" and "when there is room",
// and every extra band is another thing to get wrong.
type Class string

const (
	High   Class = "high"
	Normal Class = "normal"
	Low    Class = "low"
)

func (c Class) valid() bool { return c == High || c == Normal || c == Low }

// Rule is one line of the shaping policy.
type Rule struct {
	Raw     string  `json:"raw"`
	Match   string  `json:"match"`             // address, CIDR or domain as written
	IsHost  bool    `json:"is_host"`           // an address or CIDR rather than a name
	Class   Class   `json:"class,omitempty"`   // empty means leave it in the default class
	Ceiling float64 `json:"ceiling,omitempty"` // Mbit/s, 0 for none
	Err     string  `json:"error,omitempty"`
}

// parseRules reads the list as written, keeping bad lines so the interface can
// say which one is wrong rather than silently ignoring it.
func parseRules(lines []string) []Rule {
	var out []Rule
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := Rule{Raw: raw}
		lhs, rhs, ok := strings.Cut(line, "=")
		if !ok {
			r.Err = "expected something of the form \"what = class\""
			out = append(out, r)
			continue
		}
		r.Match = strings.ToLower(strings.TrimSpace(lhs))
		if r.Match == "" {
			r.Err = "nothing to match on"
			out = append(out, r)
			continue
		}
		r.IsHost = isAddress(r.Match)
		for _, part := range strings.Split(rhs, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			switch {
			case part == "":
			case Class(part).valid():
				r.Class = Class(part)
			default:
				n, err := parseRate(part)
				if err != nil {
					r.Err = fmt.Sprintf("%q is neither a class nor a rate", part)
					continue
				}
				r.Ceiling = n
			}
		}
		if r.Err == "" && r.Class == "" && r.Ceiling == 0 {
			r.Err = "says nothing: give a class, a rate, or both"
		}
		out = append(out, r)
	}
	return out
}

// parseRate accepts "20", "20mbit", "20 Mbit/s", "500kbit".
func parseRate(s string) (float64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, "/s")
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "kbit"):
		s, mult = strings.TrimSuffix(s, "kbit"), 0.001
	case strings.HasSuffix(s, "mbit"):
		s, mult = strings.TrimSuffix(s, "mbit"), 1
	case strings.HasSuffix(s, "gbit"):
		s, mult = strings.TrimSuffix(s, "gbit"), 1000
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("not a rate")
	}
	return n * mult, nil
}

func isAddress(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// valid returns the rules worth acting on, in a stable order so the generated
// ruleset does not churn between runs.
func valid(rules []Rule) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Err == "" {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Match < out[j].Match })
	return out
}
