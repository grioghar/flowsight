package scan

import "testing"

func TestIdentifyNamesAnEcho(t *testing.T) {
	r := &ScanResult{OpenPorts: []PortInfo{{Port: 55442, Protocol: "tcp", State: "open"}, {Port: 55443, Protocol: "tcp", State: "open"}},
		Findings: []string{"icmp_respond (ttl=64)"}}
	g := identify(r, inventory{Vendor: "Amazon Technologies Inc."})
	if len(g) == 0 || g[0].OS != "Amazon Echo (Alexa device)" || g[0].Confidence < 0.9 {
		t.Fatalf("expected an Echo first: %+v", g)
	}
	m := &Module{}
	m.identifyDevice(r)
	if r.OSGuesses[0].OS != "Amazon Echo (Alexa device)" {
		t.Fatalf("ranked: %+v", r.OSGuesses)
	}
	seen := map[string]bool{}
	for _, x := range r.OSGuesses {
		if seen[x.OS] {
			t.Fatalf("duplicate kind %q", x.OS)
		}
		seen[x.OS] = true
	}
}

func TestIdentifyUsesInventoryWithoutPorts(t *testing.T) {
	r := &ScanResult{}
	g := identify(r, inventory{Vendor: "Roku, Inc", Hostname: "roku-ultra", Fingerprint: "1,3,6,15,26,28,51,58,59,43"})
	kinds := map[string]bool{}
	for _, x := range g {
		kinds[x.OS] = true
	}
	if !kinds["Roku player"] || !kinds["Android device"] {
		t.Fatalf("vendor and fingerprint should both speak: %+v", g)
	}
}
