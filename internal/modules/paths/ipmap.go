package paths

// Where a router actually is, according to people who measured it.
//
// Everything else here is inference. The address database says where a block
// was registered; the router's own name says where its operator files it; the
// timing says where it must roughly be. RIPE's IPmap is different in kind: it
// is the published result of measuring addresses from Atlas probes and
// narrowing them by latency, which is the same argument this module makes
// about impossibility, run at scale by people with thousands of vantage
// points instead of one.
//
// It agrees with the hostnames, which is the encouraging part. 4.68.39.1 is
// dal2 in Lumen's naming and Dallas to IPmap; 129.250.5.57 is londen12 to NTT
// and London to IPmap, against an address database that puts it in Ashburn,
// Virginia. And 62.115.139.15, which the database places in Singapore and the
// speed of light rules out at 33 ms from Kansas, IPmap puts in New York.
//
// It is asked politely. A token bucket holds the rate to something a free
// service run by a non-profit will not notice, answers are kept for a month
// because routers do not move, and a refusal backs the whole thing off rather
// than retrying into a wall.

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const ipmapURL = "https://ipmap-api.ripe.net/v1/locate/"

// ipmapTTL is how long an answer is kept. A router is not moved across a city
// often enough to be worth asking again sooner, and asking again sooner is
// how a free service stops being free.
const ipmapTTL = 30 * 24 * time.Hour

// ipmapMissTTL is how long "they do not know either" is kept. Shorter,
// because coverage grows as more measurements are taken.
const ipmapMissTTL = 7 * 24 * time.Hour

const ipmapKV = "paths.ipmap."

// Placed is one address's position as somebody else measured it.
type Placed struct {
	Lat, Lon float64 `json:"-"`
	City     string  `json:"city,omitempty"`
	Region   string  `json:"region,omitempty"`
	Country  string  `json:"country,omitempty"`
	Score    int     `json:"score,omitempty"`
	OK       bool    `json:"ok"`
}

type ipmapCache struct {
	At time.Time `json:"at"`
	P  Placed    `json:"p"`
	La float64   `json:"la"`
	Lo float64   `json:"lo"`
}

type ipmapReply struct {
	Location *struct {
		CityName    string  `json:"cityName"`
		StateName   string  `json:"stateName"`
		CountryCode string  `json:"countryCodeAlpha2"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Contribs    struct {
			Worlds struct {
				Score int `json:"score"`
			} `json:"worlds"`
		} `json:"contributions"`
	} `json:"location"`
}

func (m *Module) ipmapOn() bool {
	return m.ctx != nil && core.Bool(m.ctx.Settings(), "ipmap", true)
}

// ipmapPerMinute is how many addresses may be asked about each minute.
// Deliberately small: there is no hurry, the answers last a month, and the
// service is somebody else's.
func (m *Module) ipmapPerMinute() int {
	if m.ctx == nil {
		return 20
	}
	n := core.Int(m.ctx.Settings(), "ipmap_per_minute", 20)
	if n < 1 {
		n = 1
	}
	if n > 120 {
		n = 120 // past this it stops being polite whatever the setting says
	}
	return n
}

// knownPlace returns what has already been learned about an address.
func (m *Module) knownPlace(ip string) (Placed, float64, float64, bool) {
	var c ipmapCache
	if !m.ctx.Store.KVGet(ipmapKV+ip, &c) {
		return Placed{}, 0, 0, false
	}
	ttl := ipmapTTL
	if !c.P.OK {
		ttl = ipmapMissTTL
	}
	if time.Since(c.At) > ttl {
		return Placed{}, 0, 0, false
	}
	return c.P, c.La, c.Lo, true
}

// wantPlace remembers an address worth asking about.
func (m *Module) wantPlace(ips []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.geoPending == nil {
		m.geoPending = map[string]bool{}
	}
	for _, ip := range ips {
		if len(m.geoPending) >= 5000 {
			return
		}
		m.geoPending[ip] = true
	}
}

// locateBatch asks about a few addresses, and stops early on any sign that
// the far end has had enough.
func (m *Module) locateBatch() error {
	if !m.ipmapOn() {
		return nil
	}
	m.mu.Lock()
	if time.Now().Before(m.ipmapUntil) {
		m.mu.Unlock()
		return nil // backing off
	}
	var batch []string
	for ip := range m.geoPending {
		batch = append(batch, ip)
		delete(m.geoPending, ip)
		if len(batch) >= m.ipmapPerMinute() {
			break
		}
	}
	m.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	sort.Strings(batch)

	client := &http.Client{Timeout: 20 * time.Second}
	gap := time.Minute / time.Duration(m.ipmapPerMinute())
	for _, ip := range batch {
		if _, _, _, ok := m.knownPlace(ip); ok {
			continue
		}
		p, lat, lon, retry := m.askIPmap(client, ip)
		if retry {
			// Asked to slow down, or the service is unwell. Put the rest back
			// and leave it alone for a while: hammering a service that has
			// just refused is how a polite client becomes a blocked one.
			m.mu.Lock()
			m.ipmapUntil = time.Now().Add(30 * time.Minute)
			for _, rest := range batch {
				m.geoPending[rest] = true
			}
			m.mu.Unlock()
			return nil
		}
		_ = m.ctx.Store.KVSet(ipmapKV+ip, ipmapCache{At: time.Now(), P: p, La: lat, Lo: lon})
		time.Sleep(gap)
	}
	return nil
}

// askIPmap asks about one address. The second return says whether to stop.
func (m *Module) askIPmap(c *http.Client, ip string) (Placed, float64, float64, bool) {
	req, err := http.NewRequest("GET", ipmapURL+ip+"/best", nil)
	if err != nil {
		return Placed{}, 0, 0, false
	}
	req.Header.Set("User-Agent", "flowsight (network path mapping; one address per few seconds)")
	resp, err := c.Do(req)
	if err != nil {
		return Placed{}, 0, 0, true
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Placed{}, 0, 0, false // they do not know either; remember that
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return Placed{}, 0, 0, true
	case resp.StatusCode != http.StatusOK:
		return Placed{}, 0, 0, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Placed{}, 0, 0, false
	}
	var r ipmapReply
	if json.Unmarshal(body, &r) != nil || r.Location == nil {
		return Placed{}, 0, 0, false
	}
	l := r.Location
	if l.Latitude == 0 && l.Longitude == 0 {
		return Placed{}, 0, 0, false
	}
	return Placed{
		City: strings.TrimSpace(l.CityName), Region: strings.TrimSpace(l.StateName),
		Country: strings.TrimSpace(l.CountryCode), Score: l.Contribs.Worlds.Score, OK: true,
	}, l.Latitude, l.Longitude, false
}

var _ = sync.Mutex{}
