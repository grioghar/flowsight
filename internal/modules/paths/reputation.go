package paths

// What the abuse databases say about an address.
//
// A hop's reputation is a different kind of fact from its position: it says
// whether the address has been reported for scanning, spam or attacks, who
// its ISP is, and what kind of network it sits on. AbuseIPDB publishes that
// per address behind a free key with a daily allowance, so it is asked
// slowly -- well inside the allowance -- only for addresses that appear on
// routes, and remembered for a week.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const abuseKV = "paths.abuse:"
const abuseTTL = 7 * 24 * time.Hour

// Reputation is AbuseIPDB's answer, reduced to what a reader wants.
type Reputation struct {
	Score        int    `json:"score"` // abuse confidence, 0-100
	Reports      int    `json:"reports"`
	Reporters    int    `json:"reporters,omitempty"`
	LastReported string `json:"last_reported,omitempty"`
	ISP          string `json:"isp,omitempty"`
	UsageType    string `json:"usage_type,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Country      string `json:"country,omitempty"`
	Whitelisted  bool   `json:"whitelisted,omitempty"`
	Tor          bool   `json:"tor,omitempty"`
	Source       string `json:"source"`
	At           int64  `json:"at"`
}

type cachedReputation struct {
	At time.Time
	R  *Reputation
}

func (m *Module) abuseKey() string {
	if m.ctx == nil {
		return ""
	}
	return strings.TrimSpace(core.Str(m.ctx.Settings(), "abuseipdb_key", ""))
}

// reputationFor is the cached answer, or nothing; it never asks in the
// request path.
func (m *Module) reputationFor(ip string) *Reputation {
	if m.ctx == nil || m.ctx.Store == nil {
		return nil
	}
	var c cachedReputation
	if m.ctx.Store.KVGet(abuseKV+ip, &c) && time.Since(c.At) < abuseTTL {
		return c.R
	}
	return nil
}

// reputationWanted says whether an address should be asked about: public,
// a key configured, nothing fresh cached.
func (m *Module) reputationWanted(ip string) bool {
	if m.abuseKey() == "" || !validIP(ip) {
		return false
	}
	var c cachedReputation
	return !(m.ctx.Store.KVGet(abuseKV+ip, &c) && time.Since(c.At) < abuseTTL)
}

// askAbuseIPDB fetches one address's record and caches it, including a
// negative answer so a quiet address is not asked about again this week.
func (m *Module) askAbuseIPDB(ip string) error {
	key := m.abuseKey()
	if key == "" {
		return nil
	}
	u := "https://api.abuseipdb.com/api/v2/check?" + url.Values{"ipAddress": {ip}, "maxAgeInDays": {"90"}}.Encode()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "FlowSight/"+m.version())
	resp, err := safeClient(20 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("abuseipdb: daily allowance used")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("abuseipdb: %s", resp.Status)
	}
	r, err := parseAbuseIPDB(body)
	if err != nil {
		return err
	}
	return m.ctx.Store.KVSet(abuseKV+ip, cachedReputation{At: time.Now(), R: r})
}

func parseAbuseIPDB(body []byte) (*Reputation, error) {
	var in struct {
		Data struct {
			Score       int    `json:"abuseConfidenceScore"`
			Reports     int    `json:"totalReports"`
			Reporters   int    `json:"numDistinctUsers"`
			Last        string `json:"lastReportedAt"`
			ISP         string `json:"isp"`
			Usage       string `json:"usageType"`
			Domain      string `json:"domain"`
			Country     string `json:"countryCode"`
			Whitelisted bool   `json:"isWhitelisted"`
			Tor         bool   `json:"isTor"`
		} `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}
	if len(in.Errors) > 0 {
		return nil, fmt.Errorf("abuseipdb: %s", in.Errors[0].Detail)
	}
	d := in.Data
	return &Reputation{Score: d.Score, Reports: d.Reports, Reporters: d.Reporters, LastReported: d.Last, ISP: d.ISP,
		UsageType: d.Usage, Domain: d.Domain, Country: d.Country, Whitelisted: d.Whitelisted, Tor: d.Tor,
		Source: "AbuseIPDB", At: time.Now().Unix()}, nil
}

// reputationJob asks about a few addresses each run, newest hops first.
// Twenty a run every few minutes is well inside the free allowance of a
// thousand a day and leaves room for a manual check.
func (m *Module) reputationJob() error {
	if m.abuseKey() == "" {
		return nil
	}
	rows, err := m.ctx.Store.Rows(`SELECT DISTINCT ip FROM path_hops WHERE ip <> '' ORDER BY last_seen DESC LIMIT 400`)
	if err != nil {
		return err
	}
	asked := 0
	for _, r := range rows {
		ip, _ := r["ip"].(string)
		if !m.reputationWanted(ip) {
			continue
		}
		if err := m.askAbuseIPDB(ip); err != nil {
			m.mu.Lock()
			m.abuseErr = err.Error()
			m.mu.Unlock()
			return nil // the allowance or the service; try again next run
		}
		m.mu.Lock()
		m.abuseErr = ""
		m.abuseAsked++
		m.mu.Unlock()
		asked++
		if asked >= 20 {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return nil
}
