package policy

import (
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// TestSQLAggregationQuery verifies that the GROUP BY aggregation query
// correctly aggregates flows by (src_ip, dst_ip, dst_port, app, domain, country).
// This is the core of the apiMatches optimization: instead of reading all
// individual rows and aggregating in Go, we aggregate in SQL with GROUP BY.
func TestSQLAggregationQuery(t *testing.T) {
	// Create a test store.
	s, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Insert test flows with duplicates to test aggregation.
	// We'll insert 4 flows:
	// - Flow 1 & 4: same (src, dst, port, app, domain, country) but different times
	// - Flow 2: different destination
	// - Flow 3: different source
	now := time.Now().Unix()
	testFlows := []struct {
		srcIP    string
		dstIP    string
		dstPort  int
		country  string
		app      string
		domain   string
		bytesIn  int64
		bytesOut int64
		ts       int64
	}{
		{"192.168.1.1", "8.8.8.1", 443, "US", "dns", "google.com", 100, 50, now - 3600},
		{"192.168.1.1", "1.1.1.2", 443, "RU", "https", "ru.example.com", 200, 100, now - 3600},
		{"192.168.1.2", "8.8.8.2", 80, "US", "http", "example.com", 300, 150, now - 3600},
		// Duplicate of flow 1: same (src, dst, port, app, domain, country)
		{"192.168.1.1", "8.8.8.1", 443, "US", "dns", "google.com", 50, 25, now - 1800},
	}

	for _, f := range testFlows {
		err := s.Exec(
			`INSERT INTO flows (src_ip, dst_ip, dst_port, country, app, domain, bytes_in, bytes_out, ts)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.srcIP, f.dstIP, f.dstPort, f.country, f.app, f.domain, f.bytesIn, f.bytesOut, f.ts,
		)
		if err != nil {
			t.Fatalf("Failed to insert flow: %v", err)
		}
	}

	// Execute the aggregation query (simplified version of what apiMatches does).
	// This query groups by (src_ip, dst_ip, dst_port, app, domain, country) and sums bytes/counts sessions.
	query := `SELECT src_ip, dst_ip, COALESCE(dst_port,0) AS dst_port, app, domain, upper(country) AS cc,
		COUNT(*) AS sessions, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out,
		MAX(ts) AS seen
		FROM flows
		WHERE country<>'' AND country<>'-' AND COALESCE(anycast,0)=0
		GROUP BY src_ip, dst_ip, dst_port, app, domain, cc`

	rows, err := s.Rows(query, nil)
	if err != nil {
		t.Fatalf("Aggregation query failed: %v", err)
	}

	if len(rows) != 3 {
		t.Fatalf("Expected 3 aggregated rows (flows 1+4, 2, 3 grouped), got %d", len(rows))
	}

	// Verify the aggregated data.
	// Find the aggregated row for the duplicate flows (src=192.168.1.1, dst=8.8.8.1).
	var found bool
	for _, row := range rows {
		src, _ := row["src_ip"].(string)
		dst, _ := row["dst_ip"].(string)
		if src == "192.168.1.1" && dst == "8.8.8.1" {
			found = true
			sessions := toI(row["sessions"])
			bytesIn := toI(row["bytes_in"])
			bytesOut := toI(row["bytes_out"])
			if sessions != 2 {
				t.Errorf("Expected 2 sessions for (192.168.1.1 -> 8.8.8.1), got %d", sessions)
			}
			expectedBytesIn := int64(100 + 50)
			expectedBytesOut := int64(50 + 25)
			if bytesIn != expectedBytesIn {
				t.Errorf("Expected bytes_in=%d, got %d", expectedBytesIn, bytesIn)
			}
			if bytesOut != expectedBytesOut {
				t.Errorf("Expected bytes_out=%d, got %d", expectedBytesOut, bytesOut)
			}
		}
	}
	if !found {
		t.Fatalf("Did not find aggregated row for (192.168.1.1 -> 8.8.8.1)")
	}

	t.Logf("SQL aggregation test passed: %d aggregated rows from 4 input flows", len(rows))
}
