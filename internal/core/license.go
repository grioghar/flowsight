package core

import (
	"fmt"

	"github.com/grioghar/flowsight/internal/licensing"
)

// Licensing is what the rest of the daemon asks about entitlements. The
// license module publishes an implementation as service "license"; without
// one (or without a verifiable license) the installation runs Community.
type Licensing interface {
	// Tier is the effective tier: community, pro or business.
	Tier() string
	// Allowed returns nil when the feature is included, or a 402 *Error that
	// names the feature and the tier it needs.
	Allowed(feature string) error
	// Limit returns the effective limit for a named quantity; 0 is unlimited.
	Limit(name string) int
	// Expired reports a license past its date. Expiry is soft: reads and
	// running behaviour continue, tier-gated changes are refused.
	Expired() bool
}

type communityLicensing struct{}

func (communityLicensing) Tier() string { return licensing.TierCommunity }
func (communityLicensing) Allowed(feature string) error {
	return LockedError(feature, licensing.TierCommunity)
}
func (communityLicensing) Limit(name string) int {
	return licensing.Limit(licensing.TierCommunity, name)
}
func (communityLicensing) Expired() bool { return false }

// LockedError is the 402 returned for a feature the current tier lacks. It
// is nil when the feature is Community.
func LockedError(feature, current string) error {
	need := licensing.FeatureTier(feature)
	if licensing.Rank(current) >= licensing.Rank(need) {
		return nil
	}
	title := feature
	for _, f := range licensing.Features {
		if f.Key == feature {
			title = f.Title
		}
	}
	return &Error{Status: 402, Message: fmt.Sprintf("%s requires the %s tier (this installation is %s)", title, need, current),
		Extra: map[string]any{"locked": true, "feature": feature, "required": need, "tier": current}}
}

// ExpiredError is the 402 returned when a tier-gated change is attempted on
// an expired license.
func ExpiredError(feature string) error {
	return &Error{Status: 402, Message: "the license has expired; what is running stays as it is, but tier features cannot be changed until it is renewed",
		Extra: map[string]any{"expired": true, "feature": feature}}
}

// LimitError is the 402 returned when a Community quantity limit is reached.
func LimitError(what string, limit int, feature string) error {
	return &Error{Status: 402, Message: fmt.Sprintf("the %s tier allows %d %s; upgrade for more", licensing.TierCommunity, limit, what),
		Extra: map[string]any{"locked": true, "feature": feature, "required": licensing.FeatureTier(feature), "limit": limit}}
}

// CapRetention trims a retention policy to what the tier allows.
func CapRetention(r Retention, days int) Retention {
	if days <= 0 {
		return r
	}
	cap := func(v int) int {
		if v <= 0 || v > days {
			return days
		}
		return v
	}
	r.FlowsDays, r.DNSDays, r.AlertsDays, r.EventsDays, r.RollupDays, r.TLSDays =
		cap(r.FlowsDays), cap(r.DNSDays), cap(r.AlertsDays), cap(r.EventsDays), cap(r.RollupDays), cap(r.TLSDays)
	return r
}

// License returns the active Licensing implementation.
func (c *Core) License() Licensing {
	c.mu.RLock()
	svc := c.Services["license"]
	c.mu.RUnlock()
	if l, ok := svc.(Licensing); ok && l != nil {
		return l
	}
	return communityLicensing{}
}

// License is the module-side accessor.
func (c *Context) License() Licensing { return c.Core.License() }

// Needs marks a route as part of a tier feature: the API refuses it with 402
// below that tier, and refuses writes to it while the license is expired.
func Needs(feature string) RouteOption { return func(r *Route) { r.Feature = feature } }

// NeedsJob marks a job as part of a tier feature: the scheduler skips it,
// reporting "locked", while the feature is not licensed.
func NeedsJob(feature string) JobOption { return func(j *Job) { j.Feature = feature } }
