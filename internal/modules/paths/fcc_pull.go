package paths

// What is actually kept from the FCC release.
//
// The catalogue is ten thousand files, most of them per-provider location
// coverage that runs to tens of gigabytes. Three things are worth a
// gateway's while, and they are small: the national provider summary
// (every fixed-broadband provider, how many states and locations it
// reports), the provider list (ids to names), and, for the state the
// origin is in, the summary by census place -- which providers and
// technologies serve which town. Pulled monthly, kept compact, shown on the
// origin's card and matched against hop operators by name.

import (
	"archive/zip"

	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/grioghar/flowsight/internal/core"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type fccFile struct {
	FileID      int         `json:"file_id"`
	Category    string      `json:"category"`
	Subcategory string      `json:"subcategory"`
	TechType    string      `json:"technology_type"`
	StateFIPS   string      `json:"state_fips"`
	StateName   string      `json:"state_name"`
	FileType    string      `json:"file_type"`
	FileName    string      `json:"file_name"`
	Records     json.Number `json:"record_count"`
}

// RecordCount returns the parsed record count, or 0 if not present or invalid.
func (f *fccFile) RecordCount() int {
	if f.Records == "" {
		return 0
	}
	n, err := f.Records.Int64()
	if err != nil {
		return 0
	}
	return int(n)
}

// fccProvider is one row of the national provider summary, reduced.
type fccProvider struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	HoldingCo string `json:"holding,omitempty"`
	States    int    `json:"states,omitempty"`
	Locations int64  `json:"locations,omitempty"`
	Techs     string `json:"techs,omitempty"`
	MaxDown   int    `json:"max_down,omitempty"`
}

type fccSummary struct {
	AsOf      string              `json:"as_of"`
	PulledAt  int64               `json:"pulled_at"`
	Providers []fccProvider       `json:"providers"`
	Mobile    []fccProvider       `json:"mobile,omitempty"` // mobile broadband providers
	StateFIPS string              `json:"state_fips,omitempty"`
	StateName string              `json:"state_name,omitempty"`
	Places    []fccPlace          `json:"places,omitempty"`
	Columns   map[string][]string `json:"columns"` // header of each file, for the record
	Errors    []string            `json:"errors,omitempty"`
}

// fccPlace is one census place in the origin's state: who serves it.
type fccPlace struct {
	Name      string  `json:"name"`
	Providers int     `json:"providers,omitempty"`
	Served100 float64 `json:"served_100_20,omitempty"` // share of units with 100/20 fixed service
	Fiber     float64 `json:"fiber,omitempty"`
	Cable     float64 `json:"cable,omitempty"`
}

const fccSummaryFile = "fcc-summary.json"

// fccDownload fetches one catalogue file (a zip of a CSV) and returns the
// CSV rows as maps, capped.
func (m *Module) fccDownload(fileID int, maxRows int) ([]string, []map[string]string, error) {
	user, token := m.fccCreds()
	if user == "" || token == "" {
		return nil, nil, fmt.Errorf("no FCC credentials")
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/downloads/downloadFile/availability/%d", fccBase, fileID), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("username", user)
	req.Header.Set("hash_value", token)
	req.Header.Set("User-Agent", "FlowSight/"+m.version())
	resp, err := safeClient(5 * time.Minute).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, nil, fmt.Errorf("fcc file %d: %s: %s", fileID, resp.Status, firstLine(string(b)))
	}
	body, err := io.ReadAll(&throttled{r: io.LimitReader(resp.Body, 256<<20), rate: 2 << 20})
	if err != nil {
		return nil, nil, err
	}
	var csvData []byte
	if zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err == nil {
		for _, f := range zr.File {
			if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				csvData, _ = io.ReadAll(io.LimitReader(rc, 512<<20))
				rc.Close()
				break
			}
		}
	}
	if csvData == nil {
		csvData = body // not a zip after all
	}
	return parseCSVRows(bytes.NewReader(csvData), maxRows)
}

func parseCSVRows(r io.Reader, maxRows int) ([]string, []map[string]string, error) {
	cr := csv.NewReader(r)
	cr.LazyQuotes = true
	cr.FieldsPerRecord = -1
	head, err := cr.Read()
	if err != nil {
		return nil, nil, err
	}
	for i := range head {
		head[i] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(head[i], "\ufeff")))
	}
	var rows []map[string]string
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		row := make(map[string]string, len(head))
		for i, h := range head {
			if i < len(rec) {
				row[h] = strings.TrimSpace(rec[i])
			}
		}
		rows = append(rows, row)
		if maxRows > 0 && len(rows) >= maxRows {
			break
		}
	}
	return head, rows, nil
}

// pick returns the first present column among candidates.
func pick(row map[string]string, cands ...string) string {
	for _, c := range cands {
		if v, ok := row[c]; ok && v != "" {
			return v
		}
	}
	return ""
}

// pickBySubstring finds a column by substring match (case-insensitive), for when
// exact column names vary by release. Numeric columns are prioritized.
func pickBySubstring(row map[string]string, headers []string, substrs ...string) string {
	if len(substrs) == 0 {
		return ""
	}
	// First pass: look for numeric columns matching the substrings
	for _, h := range headers {
		if _, ok := row[h]; !ok || row[h] == "" {
			continue
		}
		// Check if this header contains one of the substrings
		lower := strings.ToLower(h)
		for _, sub := range substrs {
			if strings.Contains(lower, strings.ToLower(sub)) {
				// Check if the value looks numeric
				v := strings.TrimSpace(row[h])
				if v != "" && (isNumericish(v)) {
					return v
				}
			}
		}
	}
	// Fallback: accept any match
	for _, h := range headers {
		if _, ok := row[h]; !ok || row[h] == "" {
			continue
		}
		lower := strings.ToLower(h)
		for _, sub := range substrs {
			if strings.Contains(lower, strings.ToLower(sub)) {
				return row[h]
			}
		}
	}
	return ""
}

// isNumericish returns true if the string looks like a number or percentage.
func isNumericish(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	s = strings.TrimSuffix(s, "%")
	s = strings.ReplaceAll(s, ",", "")
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.ReplaceAll(s, ",", ""))
	return n
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSuffix(strings.ReplaceAll(s, ",", ""), "%"), 64)
	return f
}

// fccPull does the monthly work: the national provider summary, the
// provider list, and the origin state's census-place summary.
func (m *Module) fccPull() error {
	user, token := m.fccCreds()
	if user == "" || token == "" {
		return nil
	}

	// Prevent concurrent fccPull runs
	m.mu.Lock()
	if m.fccPullRunning {
		m.mu.Unlock()
		return nil
	}
	m.fccPullRunning = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.fccPullRunning = false
		m.mu.Unlock()
	}()

	dir := m.providersDir()
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, fccSummaryFile)
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < 30*24*time.Hour {
		return m.loadFCCSummary()
	}
	var files []fccFile
	var raw []json.RawMessage
	m.ctx.Store.KVGet(fccKV+".files", &raw)
	for _, r := range raw {
		var f fccFile
		if json.Unmarshal(r, &f) == nil {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		if err := m.fccJob(); err != nil {
			return err
		}
		m.ctx.Store.KVGet(fccKV+".files", &raw)
		for _, r := range raw {
			var f fccFile
			if json.Unmarshal(r, &f) == nil {
				files = append(files, f)
			}
		}
	}
	m.mu.Lock()
	asOf := m.fcc.AsOf
	m.mu.Unlock()
	sum := fccSummary{AsOf: asOf, PulledAt: time.Now().Unix(), Columns: map[string][]string{}}

	// The national fixed-broadband provider summary.
	for _, f := range files {
		if f.Category == "Summary" && f.Subcategory == "Provider Summary" && f.TechType == "Fixed Broadband" && f.FileType == "csv" {
			head, rows, err := m.fccDownload(f.FileID, 20000)
			if err != nil {
				sum.Errors = append(sum.Errors, err.Error())
				break
			}
			sum.Columns["provider_summary"] = head
			for _, r := range rows {
				p := fccProvider{ID: pick(r, "provider_id", "frn"), Name: pick(r, "provider_name", "brand_name", "holding_company"),
					HoldingCo: pick(r, "holding_company"), States: atoi(pick(r, "state_count", "states", "num_states")),
					Locations: int64(atoi(pick(r, "location_count", "locations", "total_locations", "num_locations"))),
					Techs:     pick(r, "technologies", "technology", "tech"), MaxDown: atoi(pick(r, "max_advertised_download_speed", "max_download_speed"))}
				if p.Name != "" {
					sum.Providers = append(sum.Providers, p)
				}
			}
			break
		}
	}
	sort.Slice(sum.Providers, func(i, j int) bool { return sum.Providers[i].Locations > sum.Providers[j].Locations })

	// The national mobile-broadband provider summary.
	for _, f := range files {
		if f.Category == "Summary" && f.Subcategory == "Provider Summary" && f.TechType == "Mobile Broadband" && f.FileType == "csv" {
			head, rows, err := m.fccDownload(f.FileID, 20000)
			if err != nil {
				sum.Errors = append(sum.Errors, err.Error())
				break
			}
			sum.Columns["mobile_summary"] = head
			for _, r := range rows {
				p := fccProvider{ID: pick(r, "provider_id", "frn"), Name: pick(r, "provider_name", "brand_name", "holding_company"),
					HoldingCo: pick(r, "holding_company"), States: atoi(pick(r, "state_count", "states", "num_states")),
					Locations: int64(atoi(pick(r, "location_count", "locations", "total_locations", "num_locations"))),
					Techs:     pick(r, "technologies", "technology", "tech"), MaxDown: atoi(pick(r, "max_advertised_download_speed", "max_download_speed"))}
				if p.Name != "" {
					sum.Mobile = append(sum.Mobile, p)
				}
			}
			break
		}
	}
	sort.Slice(sum.Mobile, func(i, j int) bool { return sum.Mobile[i].Locations > sum.Mobile[j].Locations })

	// The origin's state: which census places are served, by whom.
	if fips := m.homeStateFIPS(); fips != "" {
		for _, f := range files {
			if f.Category == "Summary" && strings.HasPrefix(f.Subcategory, "Summary by Geography Type - Census Place") && f.TechType == "Fixed Broadband" && f.StateFIPS == fips && f.FileType == "csv" {
				head, rows, err := m.fccDownload(f.FileID, 50000)
				if err != nil {
					sum.Errors = append(sum.Errors, err.Error())
					break
				}
				sum.Columns["census_place"] = head
				sum.StateFIPS, sum.StateName = f.StateFIPS, f.StateName
				byPlace := map[string]*fccPlace{}
				for _, r := range rows {
					name := pick(r, "geography_desc", "geography_name", "place_name", "name")
					if name == "" {
						continue
					}
					pl := byPlace[name]
					if pl == nil {
						pl = &fccPlace{Name: name}
						byPlace[name] = pl
					}
					// Column names vary by release; the biggest 100/20 share
					// seen for the place stands for it. Use substring fallback for robustness.
					if v := atof(pick(r, "speed_100_20", "pct_100_20", "served_100_20")); v > 0 {
						if v > pl.Served100 {
							pl.Served100 = v
						}
					} else if v := atof(pickBySubstring(r, head, "100_20", "served")); v > 0 {
						if v > pl.Served100 {
							pl.Served100 = v
						}
					}
					if v := atof(pick(r, "fiber", "fiber_to_the_premises", "ftth")); v > 0 {
						if v > pl.Fiber {
							pl.Fiber = v
						}
					} else if v := atof(pickBySubstring(r, head, "fiber")); v > 0 {
						if v > pl.Fiber {
							pl.Fiber = v
						}
					}
					if v := atof(pick(r, "cable")); v > 0 {
						if v > pl.Cable {
							pl.Cable = v
						}
					} else if v := atof(pickBySubstring(r, head, "cable")); v > 0 {
						if v > pl.Cable {
							pl.Cable = v
						}
					}
					if v := atoi(pick(r, "provider_count", "providers", "num_providers")); v > 0 {
						if v > pl.Providers {
							pl.Providers = v
						}
					} else if v := atoi(pickBySubstring(r, head, "provider")); v > 0 {
						if v > pl.Providers {
							pl.Providers = v
						}
					}
				}
				for _, pl := range byPlace {
					sum.Places = append(sum.Places, *pl)
				}
				sort.Slice(sum.Places, func(i, j int) bool { return sum.Places[i].Name < sum.Places[j].Name })
				break
			}
		}
	}
	b, _ := json.Marshal(sum)
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	return m.loadFCCSummary()
}

func (m *Module) loadFCCSummary() error {
	b, err := os.ReadFile(filepath.Join(m.providersDir(), fccSummaryFile))
	if err != nil {
		return nil
	}
	var sum fccSummary
	if json.Unmarshal(b, &sum) != nil {
		return nil
	}
	m.mu.Lock()
	m.fccSum = &sum
	m.mu.Unlock()
	return nil
}

// homeStateFIPS is the origin's state, from its coordinates, for the US.
func (m *Module) homeStateFIPS() string {
	h := m.home()
	if !h.OK {
		return ""
	}
	return stateFIPSAt(h.Lat, h.Lon)
}

// fccProviderFor finds a broadband provider by an operator's name, loosely.
func (m *Module) fccProviderFor(org string) *fccProvider {
	m.mu.Lock()
	sum := m.fccSum
	m.mu.Unlock()
	if sum == nil || org == "" {
		return nil
	}
	key := strings.ToLower(strings.Fields(strings.ReplaceAll(org, ",", " "))[0])
	if len(key) < 3 {
		return nil
	}
	for i := range sum.Providers {
		if strings.HasPrefix(strings.ToLower(sum.Providers[i].Name), key) || strings.HasPrefix(strings.ToLower(sum.Providers[i].HoldingCo), key) {
			p := sum.Providers[i]
			return &p
		}
	}
	return nil
}

// apiFCCSummary serves what was kept.
func (m *Module) apiFCCSummary(r *core.Req) (any, error) {
	m.mu.Lock()
	sum := m.fccSum
	m.mu.Unlock()
	if sum == nil {
		return map[string]any{"pulled": false, "note": "nothing pulled yet; press Pull FCC data or wait for the monthly job"}, nil
	}
	out := *sum
	if r.Q("full", "") != "1" && len(out.Providers) > 300 {
		out.Providers = out.Providers[:300]
	}
	return out, nil
}

// apiFCCPull runs the monthly pull now.
func (m *Module) apiFCCPull(r *core.Req) (any, error) {
	_ = os.Remove(filepath.Join(m.providersDir(), fccSummaryFile))
	if err := m.fccPull(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	sum := m.fccSum
	m.mu.Unlock()
	if sum == nil {
		return map[string]any{"ok": false}, nil
	}
	return map[string]any{"ok": len(sum.Errors) == 0, "providers": len(sum.Providers), "places": len(sum.Places), "state": sum.StateName, "errors": sum.Errors, "columns": sum.Columns}, nil
}
