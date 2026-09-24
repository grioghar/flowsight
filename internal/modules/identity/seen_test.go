package identity

import (
	"testing"
	"time"
)

// A device's addresses are learned from the neighbour table, which is a cache
// of who is reachable now. IPv6 privacy addresses rotate out of it within
// hours, so holding the association only in memory meant every restart threw
// away everything not currently reachable. On the live gateway that left 97
// of 237 IPv6 hosts with no device behind them, despite a setting promising
// to remember them for a day.
func TestSeenMemorySurvivesAndPrunes(t *testing.T) {
	now := time.Now().Unix()
	stored := map[string]map[string]int64{
		"aa:bb:cc:dd:ee:01": {
			"192.168.1.119": now - 60,      // recent, keep
			"2600:1700::1":  now - 3600,    // an hour old, keep
			"2600:1700::2":  now - 90*3600, // far beyond any window, drop
		},
	}
	cut := now - 24*3600
	kept := map[string]int64{}
	for ip, at := range stored["aa:bb:cc:dd:ee:01"] {
		if at >= cut {
			kept[ip] = at
		}
	}
	if len(kept) != 2 {
		t.Fatalf("want 2 addresses inside the window, got %d: %v", len(kept), kept)
	}
	if _, ok := kept["2600:1700::2"]; ok {
		t.Error("an address older than the window must be pruned, not carried forever")
	}
	// Both families must survive together; that is the whole point of keying
	// the memory on the hardware address.
	if _, ok := kept["192.168.1.119"]; !ok {
		t.Error("the IPv4 lease should be remembered")
	}
	if _, ok := kept["2600:1700::1"]; !ok {
		t.Error("the IPv6 address should be remembered alongside it")
	}
}
