package paths

// Who, and what, is at the near end of a route.
//
// A route answers where the traffic went. The next question is whose it
// was and what it was doing: which device on this network, speaking which
// application, to which name, on which port. The flows already hold all of
// it per connection; this folds them for one endpoint into devices, and
// under each device its services, busiest first. Addresses are grouped into
// devices the same way everywhere else on the map, so a laptop with an IPv4
// lease and a handful of rotating IPv6 addresses is one entry.

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Service is one kind of conversation with the endpoint.
type Service struct {
	App      string `json:"app,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Port     int    `json:"port,omitempty"`
	Proto    string `json:"proto,omitempty"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Flows    int64  `json:"flows"`
}

// Talker is one device and everything it did with the endpoint.
type Talker struct {
	Key       string    `json:"key"` // an address of the device, usable as a filter
	Name      string    `json:"name,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
	Addresses []string  `json:"addresses"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Flows     int64     `json:"flows"`
	Services  []Service `json:"services"`
}

// Talkers is the answer for one endpoint.
type Talkers struct {
	Hours    int       `json:"hours"`
	Devices  []Talker  `json:"devices"`
	Services []Service `json:"services"` // across every device, for the summary line
	Flows    int64     `json:"flows"`
	Note     string    `json:"note,omitempty"`
}

const maxTalkerRows = 400

// talkersFor folds the endpoint's flows over the window.
func (m *Module) talkersFor(dst string, hours int) *Talkers {
	if m.ctx == nil || m.ctx.Store == nil || dst == "" {
		return nil
	}
	if hours <= 0 {
		hours = 24
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := m.ctx.Store.Rows(`
		SELECT src_ip, COALESCE(app,'') AS app, COALESCE(domain,'') AS domain, COALESCE(dst_port,0) AS port, COALESCE(proto,'') AS proto,
		       COALESCE(SUM(bytes_in),0) AS bi, COALESCE(SUM(bytes_out),0) AS bo, COUNT(*) AS n
		FROM flows WHERE dst_ip = ? AND ts > ? AND src_ip <> ''
		GROUP BY src_ip, app, domain, port, proto
		ORDER BY bi+bo DESC LIMIT ?`, dst, since, maxTalkerRows)
	if err != nil || len(rows) == 0 {
		return nil
	}
	// Address -> device key. The device is whatever identity says holds the
	// address; failing that, the address stands for itself.
	keyOf := map[string]string{}
	device := func(ip string) string {
		if k, ok := keyOf[ip]; ok {
			return k
		}
		k := ip
		if m.identity != nil {
			if mac := m.identity.MAC(ip); mac != "" {
				k = "mac:" + mac
			}
		}
		keyOf[ip] = k
		return k
	}
	byDev := map[string]*Talker{}
	svcOf := map[string]map[string]*Service{} // device -> service key -> service
	allSvc := map[string]*Service{}
	out := &Talkers{Hours: hours}
	for _, r := range rows {
		ip, _ := r["src_ip"].(string)
		if ip == "" {
			continue
		}
		app, _ := r["app"].(string)
		dom, _ := r["domain"].(string)
		proto, _ := r["proto"].(string)
		port := int(asInt(r["port"]))
		bi, bo, n := asInt(r["bi"]), asInt(r["bo"]), asInt(r["n"])
		k := device(ip)
		t := byDev[k]
		if t == nil {
			t = &Talker{Key: ip}
			if m.identity != nil {
				t.Name = m.identity.Name(ip)
				if mac := m.identity.MAC(ip); mac != "" {
					t.Vendor = m.identity.Vendor(mac)
				}
			}
			byDev[k] = t
			svcOf[k] = map[string]*Service{}
		}
		if !contains(t.Addresses, ip) {
			t.Addresses = append(t.Addresses, ip)
		}
		if t.Name == "" && m.identity != nil {
			t.Name = m.identity.Name(ip)
		}
		t.BytesIn += bi
		t.BytesOut += bo
		t.Flows += n
		out.Flows += n
		sk := strings.Join([]string{app, dom, proto, itoa(port)}, "|")
		for _, bucket := range []map[string]*Service{svcOf[k], allSvc} {
			s := bucket[sk]
			if s == nil {
				s = &Service{App: app, Domain: dom, Port: port, Proto: proto}
				bucket[sk] = s
			}
			s.BytesIn += bi
			s.BytesOut += bo
			s.Flows += n
		}
	}
	for k, t := range byDev {
		for _, s := range svcOf[k] {
			t.Services = append(t.Services, *s)
		}
		sortServices(t.Services)
		if len(t.Services) > 12 {
			t.Services = t.Services[:12]
		}
		sort.Strings(t.Addresses)
		out.Devices = append(out.Devices, *t)
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		return out.Devices[i].BytesIn+out.Devices[i].BytesOut > out.Devices[j].BytesIn+out.Devices[j].BytesOut
	})
	for _, s := range allSvc {
		out.Services = append(out.Services, *s)
	}
	sortServices(out.Services)
	if len(out.Services) > 12 {
		out.Services = out.Services[:12]
	}
	out.Note = "Devices on this network that talked to the endpoint in the window, and what they were doing: the application the flow was classified as, the name it was for, and the port. Busiest first."
	return out
}

func sortServices(s []Service) {
	sort.Slice(s, func(i, j int) bool { return s[i].BytesIn+s[i].BytesOut > s[j].BytesIn+s[j].BytesOut })
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// apiTalkers answers the question on its own, for the API and for a card
// that wants it without the whole route.
func (m *Module) apiTalkers(r *core.Req) (any, error) {
	dst := strings.TrimSpace(r.Q("dst", ""))
	if dst == "" {
		return nil, core.BadRequest("dst is required")
	}
	t := m.talkersFor(dst, r.QInt("hours", 24, 1, 24*30))
	if t == nil {
		return map[string]any{"destination": dst, "devices": []Talker{}, "services": []Service{}, "flows": 0,
			"note": "No flows to this address in the window."}, nil
	}
	return t, nil
}
