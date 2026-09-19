package core

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PolicyDoc is the declarative model every provider compiles from. It lives
// in core because providers in different modules all read it; the policy
// module owns loading, editing and applying it.
//
// Policy names capabilities, never backends: "deny these apps for the kids
// group" is compiled onto whichever installed providers offer app.block,
// web.block and dns.block. Swapping a backend never rewrites a policy.
type PolicyDoc struct {
	Version    int                 `json:"version"`
	Groups     map[string]Group    `json:"groups"`
	Schedules  map[string]Schedule `json:"schedules"`
	Policies   []Policy            `json:"policies"`
	Exclusions Exclusions          `json:"exclusions"`
	Options    Options             `json:"options"`
}

// Group members are addresses, CIDRs, "mac:aa:bb:cc:dd:ee:ff", "zone:<id>",
// "device:<name>" or "all".
type Group struct {
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
}

type Schedule struct {
	Description string   `json:"description,omitempty"`
	Windows     []Window `json:"windows"`
}

// Window: Days are mon..sun (empty = every day). From/To are HH:MM local.
// A window that ends before it starts spans midnight.
type Window struct {
	Days []string `json:"days,omitempty"`
	From string   `json:"from"`
	To   string   `json:"to"`
}

type Policy struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	// Action: "block" enforces, "monitor" only records what would have been blocked.
	Action   string `json:"action"`
	Match    Match  `json:"match"`
	Schedule string `json:"schedule,omitempty"`
	Deny     Deny   `json:"deny"`
	Allow    Allow  `json:"allow"`
	TLS      TLSOpt `json:"tls"`
	// SafeSearch forces safe search on Google, Bing, DuckDuckGo and YouTube for
	// matched clients. YouTube: "", "moderate", "strict".
	SafeSearch bool   `json:"safe_search,omitempty"`
	YouTube    string `json:"youtube,omitempty"`
}

type Match struct {
	All     bool     `json:"all,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Members []string `json:"members,omitempty"`
}

// Deny lists what the policy refuses. Apps and AppCategories use nDPI names;
// Categories are web-content categories from the feeds; Domains match the
// name and every subdomain; TLDs are like "xyz".
type Deny struct {
	Apps          []string `json:"apps,omitempty"`
	AppCategories []string `json:"app_categories,omitempty"`
	Categories    []string `json:"categories,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	TLDs          []string `json:"tlds,omitempty"`
	Countries     []string `json:"countries,omitempty"`
	Ports         []string `json:"ports,omitempty"` // "tcp/25", "udp/53", "tcp/6881-6889"
	Internet      bool     `json:"internet,omitempty"`
}

// Allow carves exceptions out of Deny for the same clients.
type Allow struct {
	Apps    []string `json:"apps,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// TLSOpt turns decrypting inspection on for matched clients. Bypass domains
// are spliced regardless (banking, pinned apps, updates).
type TLSOpt struct {
	Inspect bool     `json:"inspect,omitempty"`
	Bypass  []string `json:"bypass,omitempty"`
}

// Exclusions bypass Flowsight entirely: no interception, no inspection, no
// policy. Zenarmor gates these behind a paid edition; here they are core.
type Exclusions struct {
	Hosts   []string `json:"hosts,omitempty"`   // addresses, CIDRs, mac:
	Domains []string `json:"domains,omitempty"` // never intercepted or blocked
}

type Options struct {
	// BlockPage: where an HTTP client is sent when denied. "" = built-in page.
	BlockPageURL string `json:"block_page_url,omitempty"`
	// DNSBlockMode: "refused" (default, distinguishable in logs) or "nxdomain" or "null".
	DNSBlockMode string `json:"dns_block_mode,omitempty"`
}

// Requirements of one policy: which capabilities must exist for it to mean
// anything. The compiler refuses a policy whose requirements no provider
// meets, because a policy that silently enforces nothing is worse than an
// error.
func (p *Policy) Requirements() []string {
	set := map[string]bool{}
	d := p.Deny
	if len(d.Apps) > 0 || len(d.AppCategories) > 0 {
		set[CapAppBlock] = true
	}
	if len(d.Categories) > 0 || len(d.Domains) > 0 || len(d.TLDs) > 0 {
		set[CapDNSBlock] = true
		set[CapWebBlock] = true
	}
	if len(d.Countries) > 0 || len(d.Ports) > 0 || d.Internet {
		set[CapNetBlock] = true
	}
	if p.TLS.Inspect {
		set[CapTLSInspect] = true
	}
	if p.SafeSearch || p.YouTube != "" {
		set[CapDNSBlock] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	domainRe = regexp.MustCompile(`^(?i)(\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$`)
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	macRe    = regexp.MustCompile(`^(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	timeRe   = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	portRe   = regexp.MustCompile(`^(tcp|udp|any)/(\d{1,5})(-(\d{1,5}))?$`)
	tldRe    = regexp.MustCompile(`^(?i)[a-z0-9-]{2,63}$`)
	ccRe     = regexp.MustCompile(`^[A-Z]{2}$`)
)

// PolicyError is a validation failure; the document is never partially valid.
type PolicyError struct{ Msg string }

func (e *PolicyError) Error() string { return e.Msg }

func perr(format string, a ...any) error { return &PolicyError{Msg: fmt.Sprintf(format, a...)} }

// NormalizeDomain lowercases and trims a domain, rejecting anything else.
func NormalizeDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
	if !domainRe.MatchString(s) {
		return "", fmt.Errorf("%q is not a valid domain", s)
	}
	return strings.TrimPrefix(s, "*."), nil
}

// ValidateMember accepts an IP, CIDR, mac:, zone:, device: or "all".
func ValidateMember(m string) (string, error) {
	m = strings.TrimSpace(m)
	switch {
	case m == "all":
		return m, nil
	case strings.HasPrefix(m, "mac:"):
		if !macRe.MatchString(m[4:]) {
			return "", fmt.Errorf("%q is not a MAC address", m)
		}
		return "mac:" + strings.ToLower(m[4:]), nil
	case strings.HasPrefix(m, "zone:"), strings.HasPrefix(m, "device:"):
		if len(m) < 6 || len(m) > 80 {
			return "", fmt.Errorf("%q is not a valid reference", m)
		}
		return m, nil
	}
	if ip := net.ParseIP(m); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}
	if _, n, err := net.ParseCIDR(m); err == nil {
		return n.String(), nil
	}
	return "", fmt.Errorf("%q is not an address, network, mac:, zone: or device:", m)
}

// Validate checks the whole document and normalises members and domains in
// place. It never applies anything.
func (d *PolicyDoc) Validate() error {
	if d.Version == 0 {
		d.Version = 1
	}
	if d.Version != 1 {
		return perr("unsupported policy version %d", d.Version)
	}
	if d.Groups == nil {
		d.Groups = map[string]Group{}
	}
	if d.Schedules == nil {
		d.Schedules = map[string]Schedule{}
	}
	for name, g := range d.Groups {
		if !nameRe.MatchString(name) {
			return perr("group %q: invalid name", name)
		}
		if len(g.Members) == 0 {
			return perr("group %q has no members", name)
		}
		for i, m := range g.Members {
			v, err := ValidateMember(m)
			if err != nil {
				return perr("group %q: %v", name, err)
			}
			g.Members[i] = v
		}
		d.Groups[name] = g
	}
	for name, s := range d.Schedules {
		if !nameRe.MatchString(name) {
			return perr("schedule %q: invalid name", name)
		}
		if len(s.Windows) == 0 {
			return perr("schedule %q has no windows", name)
		}
		for i, w := range s.Windows {
			if !timeRe.MatchString(w.From) || !timeRe.MatchString(w.To) {
				return perr("schedule %q window %d: times must be HH:MM", name, i+1)
			}
			for j, day := range w.Days {
				day = strings.ToLower(day[:min(3, len(day))])
				if !strings.Contains("mon tue wed thu fri sat sun", day) || len(day) != 3 {
					return perr("schedule %q: unknown day %q", name, w.Days[j])
				}
				w.Days[j] = day
			}
			s.Windows[i] = w
		}
		d.Schedules[name] = s
	}
	seen := map[string]bool{}
	for i := range d.Policies {
		p := &d.Policies[i]
		if !nameRe.MatchString(p.Name) {
			return perr("policy %d: invalid name %q", i+1, p.Name)
		}
		if seen[p.Name] {
			return perr("duplicate policy name %q", p.Name)
		}
		seen[p.Name] = true
		if p.Action == "" {
			p.Action = "block"
		}
		if p.Action != "block" && p.Action != "monitor" {
			return perr("policy %q: action must be block or monitor", p.Name)
		}
		if !p.Match.All && len(p.Match.Groups) == 0 && len(p.Match.Members) == 0 {
			return perr("policy %q matches nobody: set match.all, match.groups or match.members", p.Name)
		}
		for _, g := range p.Match.Groups {
			if _, ok := d.Groups[g]; !ok {
				return perr("policy %q targets unknown group %q", p.Name, g)
			}
		}
		for j, m := range p.Match.Members {
			v, err := ValidateMember(m)
			if err != nil {
				return perr("policy %q: %v", p.Name, err)
			}
			p.Match.Members[j] = v
		}
		if p.Schedule != "" {
			if _, ok := d.Schedules[p.Schedule]; !ok {
				return perr("policy %q uses unknown schedule %q", p.Name, p.Schedule)
			}
		}
		for _, list := range []*[]string{&p.Deny.Domains, &p.Allow.Domains, &p.TLS.Bypass} {
			for j, dom := range *list {
				v, err := NormalizeDomain(dom)
				if err != nil {
					return perr("policy %q: %v", p.Name, err)
				}
				(*list)[j] = v
			}
		}
		for j, t := range p.Deny.TLDs {
			t = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(t), "."))
			if !tldRe.MatchString(t) {
				return perr("policy %q: %q is not a TLD", p.Name, t)
			}
			p.Deny.TLDs[j] = t
		}
		for j, c := range p.Deny.Countries {
			c = strings.ToUpper(strings.TrimSpace(c))
			if !ccRe.MatchString(c) {
				return perr("policy %q: %q is not a two-letter country code", p.Name, c)
			}
			p.Deny.Countries[j] = c
		}
		for _, pt := range p.Deny.Ports {
			if !portRe.MatchString(strings.ToLower(pt)) {
				return perr("policy %q: port %q must look like tcp/25 or udp/1000-2000", p.Name, pt)
			}
		}
		if p.YouTube != "" && p.YouTube != "moderate" && p.YouTube != "strict" {
			return perr("policy %q: youtube must be moderate or strict", p.Name)
		}
		if len(p.Requirements()) == 0 {
			return perr("policy %q denies nothing and inspects nothing", p.Name)
		}
	}
	for i, h := range d.Exclusions.Hosts {
		v, err := ValidateMember(h)
		if err != nil {
			return perr("exclusions: %v", err)
		}
		d.Exclusions.Hosts[i] = v
	}
	for i, dom := range d.Exclusions.Domains {
		v, err := NormalizeDomain(dom)
		if err != nil {
			return perr("exclusions: %v", err)
		}
		d.Exclusions.Domains[i] = v
	}
	switch d.Options.DNSBlockMode {
	case "", "refused", "nxdomain", "null":
	default:
		return perr("options.dns_block_mode must be refused, nxdomain or null")
	}
	return nil
}

// Active reports whether a schedule is in effect at t (no schedule = always).
func (d *PolicyDoc) Active(scheduleName string, t time.Time) bool {
	if scheduleName == "" {
		return true
	}
	s, ok := d.Schedules[scheduleName]
	if !ok {
		return false
	}
	day := strings.ToLower(t.Weekday().String()[:3])
	yday := strings.ToLower(t.AddDate(0, 0, -1).Weekday().String()[:3])
	hm := t.Format("15:04")
	for _, w := range s.Windows {
		spans := w.To <= w.From
		if !spans {
			if dayIn(w.Days, day) && hm >= w.From && hm < w.To {
				return true
			}
			continue
		}
		// Overnight window: today after From, or yesterday's window still running.
		if dayIn(w.Days, day) && hm >= w.From {
			return true
		}
		if dayIn(w.Days, yday) && hm < w.To {
			return true
		}
	}
	return false
}

func dayIn(days []string, d string) bool {
	if len(days) == 0 {
		return true
	}
	for _, x := range days {
		if x == d {
			return true
		}
	}
	return false
}

// Resolver turns group members into concrete addresses. Modules that know
// zones and devices (identity, enroll) publish one under "member_resolver".
type MemberResolver interface {
	// Resolve returns CIDRs for a "zone:", "device:" or "mac:" reference.
	Resolve(ref string) []string
}

// Members returns the concrete CIDRs a policy applies to at compile time.
// "all" yields the local networks the resolver knows (or 0.0.0.0/0 when none).
func (d *PolicyDoc) Members(p *Policy, res MemberResolver) []string {
	set := map[string]bool{}
	add := func(m string) {
		switch {
		case m == "all":
			var nets []string
			if res != nil {
				nets = res.Resolve("all")
			}
			if len(nets) == 0 {
				nets = []string{"0.0.0.0/0", "::/0"}
			}
			for _, n := range nets {
				set[n] = true
			}
		case strings.Contains(m, ":") && !strings.Contains(m, "/"):
			if res != nil {
				for _, n := range res.Resolve(m) {
					set[n] = true
				}
			}
		default:
			set[m] = true
		}
	}
	if p.Match.All {
		add("all")
	}
	for _, g := range p.Match.Groups {
		for _, m := range d.Groups[g].Members {
			add(m)
		}
	}
	for _, m := range p.Match.Members {
		add(m)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ExcludedCIDRs returns exclusion hosts as CIDRs.
func (d *PolicyDoc) ExcludedCIDRs(res MemberResolver) []string {
	set := map[string]bool{}
	for _, h := range d.Exclusions.Hosts {
		if strings.Contains(h, "/") {
			set[h] = true
		} else if res != nil {
			for _, n := range res.Resolve(h) {
				set[n] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Categories is the service the categories module publishes: domain lists
// per web category, and nDPI application knowledge.
type Categories interface {
	// Domains returns the cached list for a web category (error when absent).
	Domains(category string) ([]string, error)
	// List returns known web categories with their sizes.
	List() []CategoryInfo
	// Classify returns the web categories a domain belongs to (may be empty).
	Classify(domain string) []string
}

type CategoryInfo struct {
	Name    string `json:"name"`
	Domains int    `json:"domains"`
	Updated int64  `json:"updated"`
	Source  string `json:"source"`
	Error   string `json:"error,omitempty"`
}

// Identity is the service the identity module publishes.
type Identity interface {
	Name(ip string) string
	MAC(ip string) string
	Vendor(mac string) string
	IsLocal(ip string) bool
	LocalNetworks() []string
}

// AppInfo describes one nDPI application.
type AppInfo struct {
	Category string `json:"category"`
	Breed    string `json:"breed"`
	ID       int    `json:"id"`
}

// AppCatalog is the service the visibility module publishes.
type AppCatalog interface {
	Apps() map[string]AppInfo
	AppCategory(app string) string
}
