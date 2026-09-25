package firewall

import (
	"testing"
	"time"
)

func TestParseFilterlogRFC5424(t *testing.T) {
	now := time.Date(2026, 9, 25, 22, 0, 0, 0, time.UTC)
	v4 := `<134>1 2026-09-25T17:01:02-05:00 OPNsense.grio.co filterlog 61012 - [meta sequenceId="9"] 3,7,flowsight/policy,0,igc1,match,pass,in,4,0x0,,64,12345,0,DF,6,tcp,60,192.168.2.47,34.249.231.250,51234,443,0,S,1,,65535,,mss;nop;wscale`
	l, ok := parseFilterlog(v4, now)
	if !ok || l.Anchor != "flowsight/policy" || l.SubRuleNr != 7 || l.RuleNr != 3 || l.Action != "pass" || l.Dir != "in" {
		t.Fatalf("v4 header: %+v ok=%v", l, ok)
	}
	if l.Proto != "tcp" || l.Src != "192.168.2.47" || l.Dst != "34.249.231.250" || l.SrcPort != 51234 || l.DstPort != 443 {
		t.Fatalf("v4 body: %+v", l)
	}
	if l.TS != time.Date(2026, 9, 25, 22, 1, 2, 0, time.UTC).Unix() {
		t.Fatalf("timestamp not taken from the line: %d", l.TS)
	}
	v6 := `<134>1 2026-09-25T17:01:03-05:00 OPNsense filterlog 61012 - [meta sequenceId="10"] 3,,flowsight/policy,0,igc1,match,pass,in,6,0x00,0x00000,64,udp,17,80,2600:1700:3ab0:f43f::19e6,2a05:d018::1,40000,53,72`
	l, ok = parseFilterlog(v6, now)
	if !ok || l.IPv != 6 || l.SubRuleNr != -1 || l.Proto != "udp" || l.Dst != "2a05:d018::1" || l.DstPort != 53 {
		t.Fatalf("v6: %+v ok=%v", l, ok)
	}
	if _, ok := parseFilterlog("Sep 25 17:01:04 OPNsense sshd[1]: Accepted publickey", now); ok {
		t.Fatal("a line without a filterlog record must be ignored")
	}
	if policyOfLabel("flowsight:iot-abroad-monitor:country-except") != "iot-abroad-monitor" || policyOfLabel("x") != "" {
		t.Fatal("label to policy")
	}
}
