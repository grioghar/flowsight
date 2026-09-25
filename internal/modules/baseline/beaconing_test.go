package baseline

import (
	"math"
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
