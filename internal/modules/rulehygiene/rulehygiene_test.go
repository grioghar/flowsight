package rulehygiene

import (
	"testing"
)

// TestParseRules tests the pfctl -vvsr output parser.
func TestParseRules(t *testing.T) {
	input := `@0 pass in on em0 inet proto tcp from any to any port = 22 label "admin_ssh"
  [ Evaluations: 1500  Packets: 42  Bytes: 12345  States: 5 ]
@1 pass in on em0 inet proto tcp from any to any port = 80
  [ Evaluations: 0  Packets: 0  Bytes: 0  States: 0 ]
@2 pass in on vtnet1 inet from any to any
  [ Evaluations: 500  Packets: 0  Bytes: 0  States: 0 ]
@3 pass in on em0 inet proto tcp from 192.168.1.0/24 to any port = 443
  [ Evaluations: 3000  Packets: 1500  Bytes: 5000000  States: 100 ]
@4 block in on vtnet1 inet from any to 192.168.1.50
  [ Evaluations: 100  Packets: 50  Bytes: 2000  States: 0 ]`

	rules := parseRules(input)

	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}

	// Check first rule.
	if rules[0].Index != 0 {
		t.Errorf("rule 0 index: expected 0, got %d", rules[0].Index)
	}
	if rules[0].Evaluations != 1500 {
		t.Errorf("rule 0 evals: expected 1500, got %d", rules[0].Evaluations)
	}
	if rules[0].Packets != 42 {
		t.Errorf("rule 0 packets: expected 42, got %d", rules[0].Packets)
	}

	// Check shadowed rule (no evaluations).
	if rules[1].Evaluations != 0 {
		t.Errorf("rule 1 evals: expected 0, got %d", rules[1].Evaluations)
	}

	// Check rule with zero packets but high evals.
	if rules[2].Evaluations != 500 {
		t.Errorf("rule 2 evals: expected 500, got %d", rules[2].Evaluations)
	}
	if rules[2].Packets != 0 {
		t.Errorf("rule 2 packets: expected 0, got %d", rules[2].Packets)
	}
}

// TestExtractLabel tests label extraction from rules.
func TestExtractLabel(t *testing.T) {
	tests := []struct {
		rule     string
		expected string
	}{
		{`pass in on em0 inet proto tcp from any to any port = 22 label "a1b2c3d4"`, "a1b2c3d4"},
		{`pass in on em0 inet from any to any`, ""},
		{`pass in on em0 label "uuid-123" inet proto tcp from any to any`, "uuid-123"},
	}

	for _, tt := range tests {
		got := extractLabel(tt.rule)
		if got != tt.expected {
			t.Errorf("extractLabel(%q): expected %q, got %q", tt.rule, tt.expected, got)
		}
	}
}

// TestMatchesAnySource tests source matching.
func TestMatchesAnySource(t *testing.T) {
	m := &Module{}

	tests := []struct {
		rule     string
		expected bool
	}{
		{`pass in on em0 inet from any to any`, true},
		{`pass in on em0 inet from 192.168.1.0/24 to any`, false},
		{`pass in on em0 inet from ! 10.0.0.0/8 to any`, false},
	}

	for _, tt := range tests {
		got := m.matchesAnySource(tt.rule)
		if got != tt.expected {
			t.Errorf("matchesAnySource(%q): expected %v, got %v", tt.rule, tt.expected, got)
		}
	}
}

// TestMatchesAnyDest tests destination matching.
func TestMatchesAnyDest(t *testing.T) {
	m := &Module{}

	tests := []struct {
		rule     string
		expected bool
	}{
		{`pass in on em0 inet from any to any`, true},
		{`pass in on em0 inet from any to 192.168.1.0/24`, false},
		{`pass in on em0 inet from any to port 443`, false},
	}

	for _, tt := range tests {
		got := m.matchesAnyDest(tt.rule)
		if got != tt.expected {
			t.Errorf("matchesAnyDest(%q): expected %v, got %v", tt.rule, tt.expected, got)
		}
	}
}

// TestRestrictsPort tests port restriction detection.
func TestRestrictsPort(t *testing.T) {
	m := &Module{}

	tests := []struct {
		rule     string
		expected bool
	}{
		{`pass in on em0 inet proto tcp from any to any port = 22`, true},
		{`pass in on em0 inet proto tcp from any to any port 80:443`, true},
		{`pass in on em0 inet proto tcp from any to any port != 22`, true},
		{`pass in on em0 inet from any to any`, false},
	}

	for _, tt := range tests {
		got := m.restrictsPort(tt.rule)
		if got != tt.expected {
			t.Errorf("restrictsPort(%q): expected %v, got %v", tt.rule, tt.expected, got)
		}
	}
}

// TestExtractDirection tests direction parsing.
func TestExtractDirection(t *testing.T) {
	m := &Module{}

	tests := []struct {
		rule     string
		expected string
	}{
		{`pass in on em0 inet from any to any`, "in"},
		{`pass out on em0 inet from any to any`, "out"},
		{`block in on em0 inet from any to any`, "in"},
		{`pass drop in on em0 inet from any to any`, "in"},
	}

	for _, tt := range tests {
		got := m.extractDirection(tt.rule)
		if got != tt.expected {
			t.Errorf("extractDirection(%q): expected %q, got %q", tt.rule, tt.expected, got)
		}
	}
}

// TestExtractInterface tests interface extraction.
func TestExtractInterface(t *testing.T) {
	m := &Module{}

	tests := []struct {
		rule     string
		expected string
	}{
		{`pass in on em0 inet from any to any`, "em0"},
		{`pass in on vtnet1 inet from any to any`, "vtnet1"},
		{`pass in on wlan0 inet from any to any`, "wlan0"},
		{`pass inet from any to any`, ""},
	}

	for _, tt := range tests {
		got := m.extractInterface(tt.rule)
		if got != tt.expected {
			t.Errorf("extractInterface(%q): expected %q, got %q", tt.rule, tt.expected, got)
		}
	}
}

// TestIsWANInterface tests WAN detection.
func TestIsWANInterface(t *testing.T) {
	m := &Module{}

	// Default WAN: vtnet1 and wan*.
	wanIfaces := []string{}

	tests := []struct {
		iface    string
		expected bool
	}{
		{"vtnet1", true},
		{"wanbridge", true},
		{"em0", false},
		{"em1", false},
		{"vtnet0", false},
	}

	for _, tt := range tests {
		got := m.isWANInterface(tt.iface, wanIfaces)
		if got != tt.expected {
			t.Errorf("isWANInterface(%q, []): expected %v, got %v", tt.iface, tt.expected, got)
		}
	}
}

// TestCheckPermissive tests permissive rule detection.
func TestCheckPermissive(t *testing.T) {
	m := &Module{}
	wanIfaces := []string{"vtnet1"}
	mgmtPorts := []string{"22", "80", "443"}

	tests := []struct {
		rule        Rule
		expectedSev string // empty if no finding
		description string
	}{
		{
			rule:        Rule{Index: 0, Text: `pass in on vtnet1 inet from any to any`},
			expectedSev: "high",
			description: "WAN inbound any-to-any",
		},
		{
			rule:        Rule{Index: 1, Text: `pass out on vtnet1 inet from any to any`},
			expectedSev: "low",
			description: "outbound unrestricted",
		},
		{
			rule:        Rule{Index: 2, Text: `pass in on em0 inet from any to any`},
			expectedSev: "medium",
			description: "internal any-to-any",
		},
		{
			rule:        Rule{Index: 3, Text: `pass in on vtnet1 inet proto tcp from any to any port = 443`},
			expectedSev: "",
			description: "port-restricted (not flagged)",
		},
	}

	for _, tt := range tests {
		finding := m.checkPermissive(tt.rule, wanIfaces, mgmtPorts)
		if tt.expectedSev == "" {
			if finding != nil {
				t.Errorf("%s: expected no finding, got %+v", tt.description, finding)
			}
		} else {
			if finding == nil {
				t.Errorf("%s: expected finding with severity %q, got nil", tt.description, tt.expectedSev)
			} else if finding.Severity != tt.expectedSev {
				t.Errorf("%s: expected severity %q, got %q", tt.description, tt.expectedSev, finding.Severity)
			}
		}
	}
}

// TestIsInfrastructure tests infrastructure rule detection.
func TestIsInfrastructure(t *testing.T) {
	m := &Module{}

	tests := []struct {
		rule     string
		expected bool
	}{
		{`scrub in on em0`, true},
		{`anchor "flowsight/*"`, true},
		{`set skip on lo0`, true},
		{`table <local> { 192.168.0.0/16 }`, true},
		{`pass in on em0 inet from any to any`, false},
		{`block in on em0 inet from any to any`, false},
	}

	for _, tt := range tests {
		got := m.isInfrastructure(tt.rule)
		if got != tt.expected {
			t.Errorf("isInfrastructure(%q): expected %v, got %v", tt.rule, tt.expected, got)
		}
	}
}

// TestFindIssuesShadowing tests detection of shadowed rules.
func TestFindIssuesShadowing(t *testing.T) {
	m := &Module{}

	rule := Rule{
		Index:       1,
		Text:        `pass in on em0 inet proto tcp from any to any port = 80`,
		Evaluations: 0, // Never evaluated = shadowed
		Packets:     0,
	}

	// Call checkPermissive to ensure no spurious findings.
	// This rule has a port restriction so checkPermissive returns nil.
	finding := m.checkPermissive(rule, []string{}, []string{})
	if finding != nil {
		t.Errorf("port-restricted rule should not be flagged as permissive")
	}
}

// TestFindIssuesPermissive tests detection of permissive rules.
func TestFindIssuesPermissive(t *testing.T) {
	m := &Module{}

	rule := Rule{
		Index: 2,
		Text:  `pass in on vtnet1 inet from any to any`,
	}

	wanIfaces := []string{"vtnet1"}
	mgmtPorts := []string{"22", "80", "443"}

	// Should be detected as high-severity permissive (WAN inbound any-to-any).
	finding := m.checkPermissive(rule, wanIfaces, mgmtPorts)
	if finding == nil {
		t.Errorf("expected permissive finding for WAN any-to-any rule")
	} else if finding.Severity != "high" {
		t.Errorf("expected severity high, got %q", finding.Severity)
	} else if finding.Kind != "permissive" {
		t.Errorf("expected kind permissive, got %q", finding.Kind)
	}
}
