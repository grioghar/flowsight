package paths

// Running a traceroute and reading what comes back.
//
// The output is not as regular as it looks. A hop can answer once and then
// not at all, can answer from a different address each probe because the
// carrier balances across parallel links, and can be silent entirely while
// the hops beyond it answer perfectly well. All three are normal and none of
// them is an error, so the parser keeps what it is given rather than trying
// to tidy it into a single address per hop.
//
// A silent hop is recorded as a hop with no address. That matters: dropping
// it would renumber everything after it and quietly claim the path is one
// hop shorter than it is.

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Hop is one position in a path, with every address seen answering at it.
type Hop struct {
	Index int       `json:"index"`
	IPs   []string  `json:"ips,omitempty"`
	RTTs  []float64 `json:"rtt_ms,omitempty"` // one per address, same order
}

// Answered reports whether anything replied at this position.
func (h Hop) Answered() bool { return len(h.IPs) > 0 }

// Trace is one run to one destination.
type Trace struct {
	Dst      string    `json:"dst"`
	Hops     []Hop     `json:"hops"`
	Complete bool      `json:"complete"` // the destination itself answered
	TS       time.Time `json:"ts"`
	Err      string    `json:"error,omitempty"`
}

// tracer runs the command; replaced in tests.
type tracer func(ctx context.Context, dst string, maxHops int, v6 bool) (string, error)

func runTraceroute(ctx context.Context, dst string, maxHops int, v6 bool) (string, error) {
	bin := "traceroute"
	if v6 {
		bin = "traceroute6"
	}
	// -n keeps it numeric: names are resolved later, from the cache, rather
	// than serially inside the trace where every lookup adds to the runtime.
	// One probe per hop and a short wait, because this runs on a schedule and
	// the point is the shape of the path, not a latency benchmark.
	args := []string{"-n", "-q", "1", "-w", "2", "-m", strconv.Itoa(maxHops), dst}
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return string(out), err
}

// parseTrace reads traceroute's output. Anything it cannot make sense of is
// skipped rather than guessed at.
func parseTrace(dst, out string) Trace {
	t := Trace{Dst: dst, TS: time.Now()}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "traceroute") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		idx, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		hop := Hop{Index: idx}
		// After the index the line is a run of "address rtt ms" groups, with
		// "*" standing in for a probe that went unanswered.
		for i := 1; i < len(f); i++ {
			tok := f[i]
			if tok == "*" || tok == "ms" {
				continue
			}
			if looksLikeAddress(tok) {
				rtt := -1.0
				if i+1 < len(f) {
					if v, err := strconv.ParseFloat(f[i+1], 64); err == nil {
						rtt = v
					}
				}
				if !contains(hop.IPs, tok) {
					hop.IPs = append(hop.IPs, tok)
					hop.RTTs = append(hop.RTTs, rtt)
				}
			}
		}
		t.Hops = append(t.Hops, hop)
		if hop.Answered() && contains(hop.IPs, dst) {
			t.Complete = true
		}
	}
	return t
}

// looksLikeAddress is deliberately loose: traceroute -n prints bare addresses,
// and anything with a dot or a colon and no letters beyond hex is one.
func looksLikeAddress(s string) bool {
	if s == "" {
		return false
	}
	dots, colons := strings.Count(s, "."), strings.Count(s, ":")
	if dots != 3 && colons < 2 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r == '.', r == ':':
		case r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// trace runs one traceroute and returns what it found.
func (m *Module) trace(ctx context.Context, dst string, v6 bool) Trace {
	maxHops := 20
	out, err := m.run(ctx, dst, maxHops, v6)
	t := parseTrace(dst, out)
	// traceroute exits non-zero for ordinary reasons, such as never reaching
	// the destination, so an error only counts when nothing was parsed.
	if err != nil && len(t.Hops) == 0 {
		t.Err = fmt.Sprintf("%v", err)
	}
	return t
}
