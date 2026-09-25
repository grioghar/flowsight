package paths

import "testing"

func TestTrimTrailStopsAtTheEndpointOrTheLastReply(t *testing.T) {
	mk := func(i int, ip string) Node {
		n := Node{ID: ip, Index: i}
		if ip == "" {
			n.Silent = true
		} else {
			n.IPs = []string{ip}
		}
		return n
	}
	reachedRoute := []Node{mk(1, "10.0.0.1"), mk(2, "203.0.113.9"), mk(3, "198.51.100.7"), mk(4, ""), mk(5, "")}
	out, reached, probed, last := trimTrail(reachedRoute, "198.51.100.7")
	if !reached || len(out) != 3 || probed != 5 || last != 3 {
		t.Fatalf("reached: got %d hops reached=%v probed=%d last=%d", len(out), reached, probed, last)
	}
	silentTail := []Node{mk(1, ""), mk(2, "10.0.0.1"), mk(3, "203.0.113.9")}
	for i := 4; i <= 20; i++ {
		silentTail = append(silentTail, mk(i, ""))
	}
	out, reached, probed, last = trimTrail(silentTail, "2001:db8::1")
	if reached || len(out) != 3 || probed != 20 || last != 3 {
		t.Fatalf("unanswered: got %d hops reached=%v probed=%d last=%d", len(out), reached, probed, last)
	}
	if out, reached, _, _ := trimTrail(nil, "x"); reached || len(out) != 0 {
		t.Fatal("empty")
	}
}
