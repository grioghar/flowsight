package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// License is the signed document. Dates are "YYYY-MM-DD" (UTC); an empty
// Expires never expires. Installation, when set, binds the document to one
// installation id (online activations are bound; offline documents may be).
// Refresh is when an online lease should be renewed with the server; offline
// documents leave it empty. Features and Limits extend or override the tier
// defaults, so a license can carry a one-off entitlement.
type License struct {
	ID           string         `json:"id"`
	Key          string         `json:"key,omitempty"` // activation key it was issued for (last 4 only)
	Tier         string         `json:"tier"`
	Licensee     string         `json:"licensee"`
	Email        string         `json:"email,omitempty"`
	Seats        int            `json:"seats"`
	Issued       string         `json:"issued"`
	Expires      string         `json:"expires,omitempty"`
	Installation string         `json:"installation,omitempty"`
	Refresh      string         `json:"refresh,omitempty"`
	Issuer       string         `json:"issuer,omitempty"`
	Features     []string       `json:"features,omitempty"`
	Limits       map[string]int `json:"limits,omitempty"`
	Note         string         `json:"note,omitempty"`
}

// Prefix identifies a version 1 token: "FSL1.<payload>.<signature>", both
// parts base64url without padding.
const Prefix = "FSL1"

const dateLayout = "2006-01-02"

var (
	ErrFormat    = errors.New("not a FlowSight license")
	ErrSignature = errors.New("license signature does not verify")
	ErrTier      = errors.New("license names an unknown tier")
)

// Validate checks the fields a signer or verifier must both agree on.
func (l *License) Validate() error {
	if !ValidTier(l.Tier) || l.Tier == TierCommunity {
		return ErrTier
	}
	if strings.TrimSpace(l.ID) == "" {
		return errors.New("license has no id")
	}
	if _, err := time.Parse(dateLayout, l.Issued); err != nil {
		return fmt.Errorf("bad issued date %q", l.Issued)
	}
	if l.Expires != "" {
		if _, err := time.Parse(dateLayout, l.Expires); err != nil {
			return fmt.Errorf("bad expiry date %q", l.Expires)
		}
	}
	if l.Refresh != "" {
		if _, err := time.Parse(time.RFC3339, l.Refresh); err != nil {
			return fmt.Errorf("bad refresh time %q", l.Refresh)
		}
	}
	if l.Seats < 1 {
		l.Seats = 1
	}
	return nil
}

// Expired reports whether the document's expiry date has passed at t.
func (l *License) Expired(t time.Time) bool {
	if l.Expires == "" {
		return false
	}
	d, err := time.Parse(dateLayout, l.Expires)
	if err != nil {
		return true
	}
	// The whole expiry day is still valid.
	return !t.UTC().Before(d.Add(24 * time.Hour))
}

// DaysLeft is the number of whole days until expiry, negative when past;
// a very large number when the license never expires.
func (l *License) DaysLeft(t time.Time) int {
	if l.Expires == "" {
		return 1 << 20
	}
	d, err := time.Parse(dateLayout, l.Expires)
	if err != nil {
		return -1
	}
	return int(d.Add(24*time.Hour).Sub(t.UTC()).Hours() / 24)
}

// NeedsRefresh reports whether an online lease is due for renewal.
func (l *License) NeedsRefresh(t time.Time) bool {
	if l.Refresh == "" {
		return false
	}
	r, err := time.Parse(time.RFC3339, l.Refresh)
	return err != nil || !t.Before(r)
}

// Includes reports whether the license grants a feature, by tier or by an
// explicit extra entitlement.
func (l *License) Includes(feature string) bool {
	if Includes(l.Tier, feature) {
		return true
	}
	for _, f := range l.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// Limit returns the effective limit: an explicit override or the tier default.
func (l *License) Limit(name string) int {
	if v, ok := l.Limits[name]; ok {
		return v
	}
	return Limit(l.Tier, name)
}

// Sign serialises and signs the license into a token.
func Sign(l *License, priv ed25519.PrivateKey) (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("bad private key")
	}
	payload, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	enc := base64.RawURLEncoding
	return Prefix + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// Parse decodes a token and verifies its signature against pub. It does not
// judge expiry or installation binding; callers decide what those mean.
func Parse(token string, pub ed25519.PublicKey) (*License, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != Prefix {
		return nil, ErrFormat
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, ErrFormat
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, ErrFormat
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, payload, sig) {
		return nil, ErrSignature
	}
	var l License
	if err := json.Unmarshal(payload, &l); err != nil {
		return nil, ErrFormat
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &l, nil
}

// ParseKey decodes a base64 (standard or URL, padded or not) ed25519 key of
// the given size.
func ParseKey(b64 string, size int) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(b64); err == nil && len(b) == size {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not a %d-byte base64 key", size)
}

// NewID returns a random identifier with a prefix, e.g. "lic_7k3m2q9x".
func NewID(prefix string) string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + strings.ToLower(base32(b[:]))
}

// NewKey returns an activation key such as FSP-7K3M-2Q9X-W8RT-5HBD, with a
// tier letter and 20 characters of Crockford base32 (100 bits of entropy).
func NewKey(tier string) string {
	var b [13]byte
	_, _ = rand.Read(b[:])
	s := base32(b[:])[:16]
	t := "C"
	switch tier {
	case TierPro:
		t = "P"
	case TierBusiness:
		t = "B"
	}
	return fmt.Sprintf("FS%s-%s-%s-%s-%s", t, s[0:4], s[4:8], s[8:12], s[12:16])
}

// NormalizeKey upper-cases and strips spaces so keys survive copy and paste.
func NormalizeKey(k string) string {
	k = strings.ToUpper(strings.TrimSpace(k))
	k = strings.ReplaceAll(k, " ", "")
	return k
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func base32(b []byte) string {
	var out strings.Builder
	var acc uint
	var bits uint
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(crockford[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		out.WriteByte(crockford[(acc<<(5-bits))&31])
	}
	return out.String()
}
