package baseline

import (
	"math"
	"strings"
	"testing"
)

func TestBeaconingDetection(t *testing.T) {
	m := &Module{}

	// Test regular beaconing pattern (low CV)
	regularIntervals := []float64{60, 61, 59, 60, 60, 61, 59, 60}
	mean, stddev := m.calcStats(regularIntervals)
	cv := stddev / mean
	if cv >= 0.2 { // Should be < 0.2
		t.Errorf("Regular pattern CV %.4f should be < 0.2", cv)
	}

	// Test irregular pattern (high CV)
	irregularIntervals := []float64{5, 120, 30, 200, 15, 150, 45}
	mean, stddev = m.calcStats(irregularIntervals)
	cv = stddev / mean
	if cv < 0.5 {
		t.Errorf("Irregular pattern CV %.4f should be >= 0.5", cv)
	}
}

func TestEntropyCalculation(t *testing.T) {
	m := &Module{}

	// High entropy: random-looking domain with many unique characters
	domain1 := "asdflkjqweruiopzxcvbnm.example.com"
	entropy1 := m.calcDNSEntropy(domain1)
	if entropy1 < 4.0 {
		t.Errorf("Random domain entropy %.2f should be > 4.0", entropy1)
	}

	// Lower entropy should be less than high entropy
	domain2 := "example.com"
	entropy2 := m.calcDNSEntropy(domain2)
	if entropy2 >= entropy1 {
		t.Errorf("Simple domain entropy %.2f should be < random domain entropy %.2f", entropy2, entropy1)
	}
}

func TestLabelLength(t *testing.T) {
	m := &Module{}

	domain := "verylongsubdomain.example.com"
	meanLen := m.calcMeanLabelLength(domain)
	if meanLen < 8 {
		t.Errorf("Mean label length %.1f should be > 8 for long subdomain", meanLen)
	}
}

func TestStatsCalculation(t *testing.T) {
	m := &Module{}

	// Test with known values
	values := []float64{1, 2, 3, 4, 5}
	mean, stddev := m.calcStats(values)

	expectedMean := 3.0
	if math.Abs(mean-expectedMean) > 0.001 {
		t.Errorf("Mean %.2f != expected %.2f", mean, expectedMean)
	}

	expectedStddev := math.Sqrt(2.0) // sqrt(variance of 2)
	if math.Abs(stddev-expectedStddev) > 0.001 {
		t.Errorf("StdDev %.4f != expected %.4f", stddev, expectedStddev)
	}
}

func TestFindingTextFormat(t *testing.T) {
	// Verify finding text includes baseline context
	// Expected format: "First time devicename (MAC) talked to X; N days of history had Y [only]"

	testCases := []struct {
		name          string
		text          string
		shouldContain []string
	}{
		{
			name:          "new_country format",
			text:          "First time echo-234f8d (34:d2:70:98:9a:43) talked to IE; 21 days of history had US, CA only",
			shouldContain: []string{"echo-234f8d", "34:d2:70:98:9a:43", "IE", "21 days", "history", "US, CA only"},
		},
		{
			name:          "new_port format",
			text:          "First time printer (aa:bb:cc:dd:ee:ff) talked to tcp/8443; 7 days of history had tcp/443, udp/53 only",
			shouldContain: []string{"printer", "aa:bb:cc:dd:ee:ff", "tcp/8443", "7 days", "history", "tcp/443", "only"},
		},
		{
			name:          "new_destination format",
			text:          "First time iot-device (11:22:33:44:55:66) talked to 192.0.2.1; 14 days of history had 192.0.2.10, 192.0.2.20 only",
			shouldContain: []string{"iot-device", "11:22:33:44:55:66", "192.0.2.1", "14 days", "history", "only"},
		},
		{
			name:          "beaconing format",
			text:          "Regular beacon from camera (11:22:33:44:55:66) to 192.0.2.1: ~60s interval, 256 bytes per packet; 30 days of history showed no such pattern",
			shouldContain: []string{"Regular beacon", "camera", "11:22:33:44:55:66", "192.0.2.1", "60s", "30 days", "history"},
		},
		{
			name:          "dns_tunneling format",
			text:          "DNS tunneling indicators from unknown (11:22:33:44:55:66) to example.com: 45% NXDOMAIN (far above baseline), entropy 5.5, label length 22; 21 days of history showed normal patterns",
			shouldContain: []string{"unknown", "11:22:33:44:55:66", "example.com", "NXDOMAIN", "baseline", "21 days", "history"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, substr := range tc.shouldContain {
				if !strings.Contains(tc.text, substr) {
					t.Errorf("Finding text missing %q: %s", substr, tc.text)
				}
			}
		})
	}
}
