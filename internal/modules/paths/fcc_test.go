package paths

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFCCCSVRowsAndPicks(t *testing.T) {
	head, rows, err := parseCSVRows(strings.NewReader("\ufeffProvider_ID,Provider_Name,Holding_Company,State_Count,Location_Count\n130077,AT&T Inc.,AT&T,21,\"12,345,678\"\n"), 0)
	if err != nil || len(rows) != 1 || head[0] != "provider_id" {
		t.Fatalf("%v %v %v", head, rows, err)
	}
	if pick(rows[0], "provider_name") != "AT&T Inc." || atoi(pick(rows[0], "location_count")) != 12345678 {
		t.Fatalf("%v", rows[0])
	}
	if stateFIPSAt(39.18, -96.57) != "20" || stateFIPSAt(38.9, -77.03) != "11" || stateFIPSAt(51.5, -0.1) != "" {
		t.Fatal("state lookup")
	}
	m := &Module{fccSum: &fccSummary{Providers: []fccProvider{{ID: "130077", Name: "AT&T Inc.", HoldingCo: "AT&T", States: 21}}}}
	if p := m.fccProviderFor("AT&T Enterprises, LLC"); p == nil || p.ID != "130077" {
		t.Fatalf("name match: %+v", p)
	}
	if m.fccProviderFor("Akamai") != nil {
		t.Fatal("no false match")
	}
}

func TestFCCFileCatalogueEntry(t *testing.T) {
	// Real catalogue entry from FCC API (record_count is a string)
	jsonStr := `{"file_id":1789620,"category":"Summary","subcategory":"Provider Summary","technology_type":"Fixed Broadband","technology_code":"","technology_code_desc":"","speed_tier":null,"state_fips":"","state_name":"","provider_id":"","provider_name":"","file_type":"csv","file_name":"bdc_us_fixed_broadband_provider_summary_D25_15sep2026","record_count":"3758"}`
	var f fccFile
	if err := json.Unmarshal([]byte(jsonStr), &f); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if f.FileID != 1789620 {
		t.Fatalf("file_id mismatch: %d", f.FileID)
	}
	if f.RecordCount() != 3758 {
		t.Fatalf("record_count parse failed: got %d, want 3758", f.RecordCount())
	}

	// Also test with a large record count
	jsonStr2 := `{"file_id":1789622,"category":"Summary","subcategory":"Provider Summary by Geography Type","technology_type":"Fixed Broadband","record_count":"488050"}`
	var f2 fccFile
	if err := json.Unmarshal([]byte(jsonStr2), &f2); err != nil {
		t.Fatalf("unmarshal 2 failed: %v", err)
	}
	if f2.RecordCount() != 488050 {
		t.Fatalf("record_count parse 2 failed: got %d, want 488050", f2.RecordCount())
	}
}
