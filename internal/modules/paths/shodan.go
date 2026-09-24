package paths

// Shodan, for what a hop looks like from the outside.
//
// Where the other sources say where an address is and who owns it, Shodan
// says what it is running: the ports it answers on, the names it has been
// seen under, product fingerprints and known vulnerabilities. Two doors.
// InternetDB is free and needs no key, and gives ports, hostnames, CPEs,
// vulnerabilities and tags. The keyed host record adds organisation, ISP,
// operating system, Shodan's own location and when it was last seen, at a
// query credit each -- so it is fetched on click unless the operator asks
// for every hop. Answers are kept a week.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const shodanKV = "paths.shodan:"
const shodanTTL = 7 * 24 * time.Hour

// ShodanRecord is what is kept and shown.
type ShodanRecord struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Org       string   `json:"org,omitempty"`
	ISP       string   `json:"isp,omitempty"`
	OS        string   `json:"os,omitempty"`
	City      string   `json:"city,omitempty"`
	Country   string   `json:"country,omitempty"`
	ASN       string   `json:"asn,omitempty"`
	LastSeen  string   `json:"last_seen,omitempty"`
	Keyed     bool     `json:"keyed"` // the full record, not only InternetDB
	Empty     bool     `json:"empty,omitempty"`
	At        int64    `json:"at"`
	Error     string   `json:"error,omitempty"`
}

type cachedShodan struct {
	At time.Time
	R  *ShodanRecord
}

func (m *Module) shodanKey() string {
	if m.ctx == nil {
		return ""
	}
	return strings.TrimSpace(core.Str(m.ctx.Settings(), "shodan_key", ""))
}

func (m *Module) shodanMode() string {
	if m.ctx == nil {
		return "off"
	}
	mode := strings.ToLower(strings.TrimSpace(core.Str(m.ctx.Settings(), "shodan_mode", "click")))
	if mode != "off" && mode != "all" {
		mode = "click"
	}
	return mode
}

func (m *Module) shodanFor(ip string) *ShodanRecord {
	if m.ctx == nil || m.ctx.Store == nil {
		return nil
	}
	var c cachedShodan
	if m.ctx.Store.KVGet(shodanKV+ip, &c) && time.Since(c.At) < shodanTTL {
		return c.R
	}
	return nil
}

// fetchShodan asks InternetDB, then the keyed host API when a key is set and
// asked for, and caches the merged record.
func (m *Module) fetchShodan(ip string, keyed bool) (*ShodanRecord, error) {
	if !validIP(ip) {
		return nil, fmt.Errorf("not a public address")
	}
	rec := &ShodanRecord{IP: ip, At: time.Now().Unix()}
	client := safeClient(20 * time.Second)
	get := func(u string) ([]byte, int, error) {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", "FlowSight/"+m.version())
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		return b, resp.StatusCode, nil
	}
	b, code, err := get("https://internetdb.shodan.io/" + url.PathEscape(ip))
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusOK:
		var in struct {
			Ports     []int    `json:"ports"`
			Hostnames []string `json:"hostnames"`
			CPEs      []string `json:"cpes"`
			Vulns     []string `json:"vulns"`
			Tags      []string `json:"tags"`
		}
		if json.Unmarshal(b, &in) == nil {
			rec.Ports, rec.Hostnames, rec.CPEs, rec.Vulns, rec.Tags = in.Ports, in.Hostnames, in.CPEs, in.Vulns, in.Tags
		}
	case http.StatusNotFound:
		rec.Empty = true
	default:
		return nil, fmt.Errorf("internetdb: %d", code)
	}
	if keyed {
		if key := m.shodanKey(); key != "" {
			b, code, err := get("https://api.shodan.io/shodan/host/" + url.PathEscape(ip) + "?minify=true&key=" + url.QueryEscape(key))
			if err == nil && code == http.StatusOK {
				var in struct {
					Ports     []int    `json:"ports"`
					Hostnames []string `json:"hostnames"`
					Org       string   `json:"org"`
					ISP       string   `json:"isp"`
					OS        string   `json:"os"`
					City      string   `json:"city"`
					Country   string   `json:"country_name"`
					ASN       string   `json:"asn"`
					Last      string   `json:"last_update"`
					Tags      []string `json:"tags"`
					Vulns     []string `json:"vulns"`
				}
				if json.Unmarshal(b, &in) == nil {
					rec.Keyed = true
					if len(in.Ports) > 0 {
						rec.Ports = in.Ports
					}
					if len(in.Hostnames) > 0 {
						rec.Hostnames = in.Hostnames
					}
					rec.Org, rec.ISP, rec.OS, rec.City, rec.Country, rec.ASN, rec.LastSeen = in.Org, in.ISP, in.OS, in.City, in.Country, in.ASN, in.Last
					if len(in.Tags) > 0 {
						rec.Tags = in.Tags
					}
					if len(in.Vulns) > 0 {
						rec.Vulns = in.Vulns
					}
					rec.Empty = false
				}
			} else if err == nil && code == http.StatusUnauthorized {
				rec.Error = "shodan: key rejected"
			} else if err == nil && code == http.StatusTooManyRequests {
				rec.Error = "shodan: rate limited"
			} else if err == nil && code != http.StatusNotFound {
				rec.Error = fmt.Sprintf("shodan: %d", code)
			}
		}
	}
	sort.Ints(rec.Ports)
	_ = m.ctx.Store.KVSet(shodanKV+ip, cachedShodan{At: time.Now(), R: rec})
	return rec, nil
}

// apiShodan returns the cached record, or fetches it when asked to.
func (m *Module) apiShodan(r *core.Req) (any, error) {
	ip := strings.TrimSpace(r.Q("ip", ""))
	if ip == "" {
		return nil, core.BadRequest("ip is required")
	}
	if m.shodanMode() == "off" {
		return map[string]any{"ip": ip, "off": true, "note": "Shodan lookups are off under Settings › paths › Shodan."}, nil
	}
	if rec := m.shodanFor(ip); rec != nil {
		return rec, nil
	}
	if r.Q("now", "") != "1" {
		return map[string]any{"ip": ip, "cached": false}, nil
	}
	rec, err := m.fetchShodan(ip, true)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.shodanAsked++
	m.mu.Unlock()
	return rec, nil
}

// shodanJob, in "all" mode, works through hops on routes: twenty per run,
// InternetDB always, the keyed record if a key is set.
func (m *Module) shodanJob() error {
	if m.shodanMode() != "all" {
		return nil
	}
	rows, err := m.ctx.Store.Rows(`SELECT DISTINCT ip FROM path_hops WHERE ip <> '' ORDER BY last_seen DESC LIMIT 400`)
	if err != nil {
		return err
	}
	asked := 0
	for _, r := range rows {
		ip, _ := r["ip"].(string)
		if !validIP(ip) || m.shodanFor(ip) != nil {
			continue
		}
		if _, err := m.fetchShodan(ip, true); err != nil {
			m.mu.Lock()
			m.shodanErr = err.Error()
			m.mu.Unlock()
			return nil
		}
		m.mu.Lock()
		m.shodanErr = ""
		m.shodanAsked++
		m.mu.Unlock()
		asked++
		if asked >= 20 {
			break
		}
		time.Sleep(1200 * time.Millisecond)
	}
	return nil
}

func (m *Module) shodanStatus() map[string]any {
	m.mu.Lock()
	asked, errs := m.shodanAsked, m.shodanErr
	m.mu.Unlock()
	return map[string]any{"mode": m.shodanMode(), "keyed": m.shodanKey() != "", "known": m.ctx.Store.KVCount(shodanKV), "asked_this_session": asked, "error": errs}
}
