// Package licensing holds what the daemon and the license server share: the
// tier ladder, the feature catalogue, and the signed license document.
//
// Nothing here talks to the network. A license is an ed25519-signed JSON
// document; the daemon verifies it against a public key compiled into release
// builds, whether it arrived from the license server (online activation) or
// was pasted in by hand (offline). Expiry is soft: an expired license keeps
// its tier for reading and for what is already running, but tier-gated
// settings cannot be changed until it is renewed.
package licensing

import "sort"

// Tiers, lowest first. Community is what an unlicensed installation runs.
const (
	TierCommunity = "community"
	TierPro       = "pro"
	TierBusiness  = "business"
)

var tierRank = map[string]int{TierCommunity: 0, TierPro: 1, TierBusiness: 2}

// Rank orders tiers; unknown tiers rank below Community so a typo in a
// license can never unlock anything.
func Rank(tier string) int {
	if r, ok := tierRank[tier]; ok {
		return r
	}
	return -1
}

// ValidTier reports whether the tier is one we know.
func ValidTier(tier string) bool { _, ok := tierRank[tier]; return ok }

// Tiers lists the tiers lowest first.
func Tiers() []string { return []string{TierCommunity, TierPro, TierBusiness} }

// Feature is one gated capability. Key is what code asks for; Tier is the
// lowest tier that includes it.
type Feature struct {
	Key   string `json:"key"`
	Tier  string `json:"tier"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
}

// Features is the catalogue. Everything not listed here is Community.
var Features = []Feature{
	{Key: "tls.inspect", Tier: TierPro, Title: "TLS inspection",
		Desc: "Create a FlowSight CA and decrypt selected traffic for content policy and certificate transparency."},
	{Key: "firewall.analyse", Tier: TierPro, Title: "Firewall rule hygiene",
		Desc: "Continuous analysis of the firewall ruleset: unused, shadowed and never-evaluated rules, with change tracking."},
	{Key: "device.enroll", Tier: TierPro, Title: "Device enrolment (enforce)",
		Desc: "Place new devices into zones with DHCP reservations and isolation. Monitoring and classification stay free."},
	{Key: "reports.schedule", Tier: TierPro, Title: "Scheduled reports and export",
		Desc: "Schedule reports for delivery and export data as CSV or JSON. On-screen reports stay free."},
	{Key: "alerting.notify", Tier: TierPro, Title: "Notification channels",
		Desc: "Deliver alerts by e-mail, webhook or chat. Alerts in the UI stay free."},
	{Key: "policy.unlimited", Tier: TierPro, Title: "Unlimited policies and schedules",
		Desc: "Community allows three policies and two schedules."},
	{Key: "retention.extended", Tier: TierPro, Title: "Extended history",
		Desc: "Keep 90 days of history instead of 7 (Business: 365)."},
	{Key: "paths.map", Tier: TierPro, Title: "Path mapping",
		Desc: "The route to the places this network talks to: every hop with its name, carrier and location, collapsed where paths share a leg."},
	{Key: "qos.shape", Tier: TierPro, Title: "Traffic priority",
		Desc: "Decide who waits when the link is full: move the queue onto this firewall and share the link by weight, with ceilings per device or service."},
	{Key: "deep.inspect", Tier: TierBusiness, Title: "Stateful Packet Inspection",
		Desc: "Look inside decrypted sessions: request headers, content types, and the questions inside DNS-over-HTTPS. Bodies are decoded, never stored."},
	{Key: "egress.watch", Tier: TierBusiness, Title: "Live egress monitoring",
		Desc: "See what is leaving the network as it leaves, read from the firewall's own connection counters: pinned sessions, QUIC and encrypted tunnels included. Raises an event while a transfer is still running, and can drop it."},
	{Key: "telemetry.export", Tier: TierBusiness, Title: "Telemetry export",
		Desc: "Stream flows, metrics and events to an OTLP collector or SIEM."},
	{Key: "identity.directory", Tier: TierBusiness, Title: "Directory identity",
		Desc: "Resolve users from LDAP, Active Directory or RADIUS and write policy per user or group."},
	{Key: "admin.multi", Tier: TierBusiness, Title: "Multiple administrators",
		Desc: "Separate API tokens and roles per operator with an audit trail per person."},
	{Key: "use.commercial", Tier: TierBusiness, Title: "Commercial use",
		Desc: "Use on networks operated for a business, a customer or a paying tenant, with SLA support."},
}

// FeatureTier returns the lowest tier that includes a feature; unknown
// features are Community (not gated).
func FeatureTier(key string) string {
	for _, f := range Features {
		if f.Key == key {
			return f.Tier
		}
	}
	return TierCommunity
}

// Includes reports whether a tier includes the feature.
func Includes(tier, feature string) bool { return Rank(tier) >= Rank(FeatureTier(feature)) }

// Limit names. A limit of 0 means unlimited.
const (
	LimitPolicies      = "policies"
	LimitSchedules     = "schedules"
	LimitRetentionDays = "retention_days"
	LimitInstallations = "installations"
)

var limits = map[string]map[string]int{
	TierCommunity: {LimitPolicies: 3, LimitSchedules: 2, LimitRetentionDays: 7, LimitInstallations: 1},
	TierPro:       {LimitPolicies: 0, LimitSchedules: 0, LimitRetentionDays: 90, LimitInstallations: 1},
	TierBusiness:  {LimitPolicies: 0, LimitSchedules: 0, LimitRetentionDays: 365, LimitInstallations: 5},
}

// Limit returns a tier's default limit; 0 is unlimited.
func Limit(tier, name string) int {
	if m, ok := limits[tier]; ok {
		return m[name]
	}
	return limits[TierCommunity][name]
}

// Limits returns every default limit of a tier, sorted by name.
func Limits(tier string) map[string]int {
	src := limits[tier]
	if src == nil {
		src = limits[TierCommunity]
	}
	out := make(map[string]int, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// LimitNames lists the known limit names.
func LimitNames() []string {
	var out []string
	for k := range limits[TierCommunity] {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
