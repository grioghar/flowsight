package paths

import (
	"strings"
	"testing"
)

// Real traceroute output, including the three things that are normal and look
// like faults: a silent hop, a hop answering from two addresses, and the
// destination replying at the end.
const sample = `traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 40 byte packets
 1  192.168.1.254  0.838 ms
 2  172.11.154.1  3.475 ms
 3  * 
 4  32.130.107.216  16.739 ms  32.130.107.218  17.001 ms
 5  141.101.74.79  18.164 ms
 6  1.1.1.1  18.900 ms
`

func TestParseTrace(t *testing.T) {
	tr := parseTrace("1.1.1.1", sample)
	if len(tr.Hops) != 6 {
		t.Fatalf("want 6 hops, got %d: %+v", len(tr.Hops), tr.Hops)
	}
	if !tr.Complete {
		t.Error("the destination answered, so the trace is complete")
	}
	// A silent hop keeps its position. Dropping it would renumber everything
	// after it and claim the path is shorter than it is.
	if tr.Hops[2].Index != 3 || tr.Hops[2].Answered() {
		t.Errorf("hop 3 should be present and silent: %+v", tr.Hops[2])
	}
	if tr.Hops[3].Index != 4 || len(tr.Hops[3].IPs) != 2 {
		t.Errorf("hop 4 answered from two addresses: %+v", tr.Hops[3])
	}
	if tr.Hops[0].IPs[0] != "192.168.1.254" || tr.Hops[0].RTTs[0] != 0.838 {
		t.Errorf("hop 1 wrong: %+v", tr.Hops[0])
	}
}

func TestLooksLikeAddress(t *testing.T) {
	for _, good := range []string{"1.1.1.1", "192.168.1.254", "2606:4700::1111", "fe80::1"} {
		if !looksLikeAddress(good) {
			t.Errorf("%q should parse as an address", good)
		}
	}
	for _, bad := range []string{"", "*", "ms", "18.900", "hop", "!H"} {
		if looksLikeAddress(bad) {
			t.Errorf("%q should not parse as an address", bad)
		}
	}
}

// Two destinations that leave the same way must share those legs, and diverge
// only where the routes do. Drawing them separately is the whole problem this
// is meant to solve.
func TestSharedLegsCollapse(t *testing.T) {
	rows := []hopRow{
		{Dst: "a", Index: 1, IP: "10.0.0.1", RTT: 1}, {Dst: "a", Index: 2, IP: "10.0.0.2", RTT: 2},
		{Dst: "a", Index: 3, IP: "203.0.113.1", RTT: 9},
		{Dst: "b", Index: 1, IP: "10.0.0.1", RTT: 1}, {Dst: "b", Index: 2, IP: "10.0.0.2", RTT: 2},
		{Dst: "b", Index: 3, IP: "198.51.100.1", RTT: 8},
	}
	g := buildGraph(rows)
	var shared, private int
	for _, l := range g.Legs {
		if l.Shared {
			shared++
		} else {
			private++
		}
	}
	if shared != 1 {
		t.Errorf("hop 1 to hop 2 is common to both and should be one shared leg; got %d shared", shared)
	}
	if private != 2 {
		t.Errorf("each destination has its own final leg; got %d", private)
	}
	// Four nodes, not six: the two common hops are one node each.
	if len(g.Nodes) != 4 {
		t.Errorf("want 4 nodes, got %d: %+v", len(g.Nodes), g.Nodes)
	}
}

// A position answering from several addresses is one node carrying them all,
// which is what balancing across parallel links looks like. Splitting it
// would draw two routes where there is one.
func TestParallelLinksAreOneNode(t *testing.T) {
	rows := []hopRow{
		{Dst: "a", Index: 1, IP: "10.0.0.1", RTT: 1},
		{Dst: "a", Index: 2, IP: "10.0.0.2", RTT: 2},
		{Dst: "a", Index: 2, IP: "10.0.0.3", RTT: 3},
	}
	g := buildGraph(rows)
	if len(g.Nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d: %+v", len(g.Nodes), g.Nodes)
	}
	var multi *Node
	for i := range g.Nodes {
		if g.Nodes[i].Index == 2 {
			multi = &g.Nodes[i]
		}
	}
	if multi == nil || len(multi.IPs) != 2 {
		t.Fatalf("hop 2 should carry both addresses: %+v", multi)
	}
	if multi.RTT != 2 {
		t.Errorf("the node should report the best round trip seen, got %v", multi.RTT)
	}
}

// Two routes both going quiet at the same distance are not passing through
// the same router. Joining them would invent a path that was never measured.
func TestSilentHopsDoNotJoinUnrelatedRoutes(t *testing.T) {
	rows := []hopRow{
		{Dst: "a", Index: 1, IP: "10.0.0.1"}, {Dst: "a", Index: 2, IP: ""},
		{Dst: "b", Index: 1, IP: "10.0.0.1"}, {Dst: "b", Index: 2, IP: ""},
	}
	g := buildGraph(rows)
	silent := 0
	for _, n := range g.Nodes {
		if n.Silent {
			silent++
		}
	}
	if silent != 2 {
		t.Errorf("each route's silent hop is its own; want 2, got %d", silent)
	}
}

func TestFilterGraphDropsDanglingLegs(t *testing.T) {
	g := Graph{
		Nodes: []Node{{ID: "x", Country: "US", Index: 1}, {ID: "y", Country: "DE", Index: 2}},
		Legs:  []Leg{{From: "x", To: "y", Destinations: []string{"a"}}},
	}
	got := filterGraph(g, "US", 0, 0)
	if len(got.Nodes) != 1 {
		t.Errorf("want 1 node after filtering to US, got %d", len(got.Nodes))
	}
	if len(got.Legs) != 0 {
		t.Errorf("a leg whose far end was filtered out must go too, got %d", len(got.Legs))
	}
}

func TestPrivateAddressesAreNotTraced(t *testing.T) {
	for _, p := range []string{"10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.1", "fd00::1", "fe80::1", "127.0.0.1"} {
		if !isPrivate(p) {
			t.Errorf("%s is inside the network and should not be traced", p)
		}
	}
	for _, p := range []string{"8.8.8.8", "172.32.0.1", "172.15.0.1", "2606:4700::1111"} {
		if isPrivate(p) {
			t.Errorf("%s is a real destination", p)
		}
	}
}

func TestTraceErrorOnlyWhenNothingParsed(t *testing.T) {
	// traceroute exits non-zero for ordinary reasons, such as never reaching
	// the destination. That is not a failure if hops came back.
	tr := parseTrace("1.1.1.1", sample)
	if tr.Err != "" {
		t.Error("a parsed trace has no error")
	}
	if strings.Contains(sample, "nonsense") {
		t.Fatal("test data drifted")
	}
}

// The first live run traced a multicast group and the gateway's own address,
// twenty timed-out probes each for a row of nothing. Nothing that lives
// inside the network, or that is not a single host at all, is worth a probe.
func TestMulticastAndBroadcastAreNotTraced(t *testing.T) {
	for _, p := range []string{"239.255.255.250", "224.0.0.251", "255.255.255.255", "ff02::fb", "ff05::1:3"} {
		if !isMulticast(p) {
			t.Errorf("%s is a group, not a host, and should not be traced", p)
		}
	}
	for _, p := range []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111", "223.5.5.5", "240.0.0.1"} {
		if isMulticast(p) {
			t.Errorf("%s is a real destination", p)
		}
	}
}

// A global address can still belong to this network: the delegated IPv6
// prefix is routable and ours, and no fixed list of private ranges covers it.
func TestLocalGlobalAddressesAreNotTraced(t *testing.T) {
	m := &Module{identity: fakeIdentity{local: "2600:1700:3ab0:f43f:"}}
	if m.worthTracing("2600:1700:3ab0:f43f:be24:11ff:fe94:9732") {
		t.Error("the gateway's own global address must not be traced")
	}
	if !m.worthTracing("2606:4700:4700::1111") {
		t.Error("a genuine destination must still be traced")
	}
	if m.worthTracing("239.255.255.250") {
		t.Error("multicast must not be traced even with identity present")
	}
}

type fakeIdentity struct{ local string }

func (f fakeIdentity) Name(string) string      { return "" }
func (f fakeIdentity) MAC(string) string       { return "" }
func (f fakeIdentity) Vendor(string) string    { return "" }
func (f fakeIdentity) LocalNetworks() []string { return nil }
func (f fakeIdentity) IsLocal(ip string) bool  { return strings.HasPrefix(ip, f.local) }

// Legs refer to nodes by identifier. Building nodes without setting it left
// every leg pointing at nothing, and the filter, which quite correctly drops
// a leg whose ends are missing, then dropped all of them. The map came back
// with eighty-seven nodes and no lines between any of them.
func TestNodesCarryTheIDTheirLegsReferTo(t *testing.T) {
	g := buildGraph([]hopRow{
		{Dst: "a", Index: 1, IP: "10.0.0.1"}, {Dst: "a", Index: 2, IP: "10.0.0.2"},
		{Dst: "b", Index: 1, IP: "10.0.0.1"}, {Dst: "b", Index: 2, IP: "10.0.0.9"},
	})
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		if n.ID == "" {
			t.Fatalf("a node with no identifier: %+v", n)
		}
		ids[n.ID] = true
	}
	if len(g.Legs) == 0 {
		t.Fatal("two routes of two hops each must produce legs")
	}
	for _, l := range g.Legs {
		if !ids[l.From] || !ids[l.To] {
			t.Errorf("leg %s -> %s points at a node that is not in the graph", l.From, l.To)
		}
	}
	// And they must survive a pass through the filter unchanged.
	if got := filterGraph(g, "", 0, 0); len(got.Legs) != len(g.Legs) {
		t.Errorf("an empty filter dropped legs: %d became %d", len(g.Legs), len(got.Legs))
	}
}
