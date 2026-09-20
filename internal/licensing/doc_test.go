package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignParseRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	l := &License{ID: "lic_1", Tier: TierPro, Licensee: "Ada", Seats: 1, Issued: "2026-09-20", Expires: "2027-09-20",
		Installation: "inst_a", Refresh: "2026-09-27T00:00:00Z", Features: []string{"telemetry.export"}, Limits: map[string]int{LimitPolicies: 10}}
	tok, err := Sign(l, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, Prefix+".") {
		t.Fatalf("bad prefix: %s", tok[:8])
	}
	got, err := Parse(tok, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tier != TierPro || got.Licensee != "Ada" || got.Installation != "inst_a" {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if !got.Includes("tls.inspect") || !got.Includes("telemetry.export") || got.Includes("identity.directory") {
		t.Fatal("feature inclusion wrong")
	}
	if got.Limit(LimitPolicies) != 10 || got.Limit(LimitRetentionDays) != 90 {
		t.Fatal("limits wrong")
	}
}

func TestTamperAndWrongKey(t *testing.T) {
	pub, priv := keys(t)
	other, _ := keys(t)
	l := &License{ID: "lic_1", Tier: TierPro, Licensee: "Ada", Seats: 1, Issued: "2026-09-20"}
	tok, _ := Sign(l, priv)
	if _, err := Parse(tok, other); err != ErrSignature {
		t.Fatalf("wrong key accepted: %v", err)
	}
	parts := strings.Split(tok, ".")
	// Flip the tier inside the payload: must fail signature, never upgrade.
	payload := strings.Replace(parts[1], parts[1][10:12], "zz", 1)
	if _, err := Parse(parts[0]+"."+payload+"."+parts[2], pub); err == nil {
		t.Fatal("tampered payload accepted")
	}
	if _, err := Parse("garbage", pub); err != ErrFormat {
		t.Fatalf("garbage: %v", err)
	}
}

func TestCommunityCannotBeSigned(t *testing.T) {
	_, priv := keys(t)
	if _, err := Sign(&License{ID: "x", Tier: TierCommunity, Issued: "2026-09-20"}, priv); err != ErrTier {
		t.Fatalf("community signed: %v", err)
	}
	if _, err := Sign(&License{ID: "x", Tier: "platinum", Issued: "2026-09-20"}, priv); err != ErrTier {
		t.Fatalf("unknown tier signed: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	l := &License{Expires: "2026-09-20"}
	if l.Expired(time.Date(2026, 9, 20, 23, 0, 0, 0, time.UTC)) {
		t.Fatal("expiry day itself must still be valid")
	}
	if !l.Expired(time.Date(2026, 9, 21, 0, 0, 1, 0, time.UTC)) {
		t.Fatal("day after expiry must be expired")
	}
	if (&License{}).Expired(time.Now().AddDate(100, 0, 0)) {
		t.Fatal("no expiry means never")
	}
	r := &License{Refresh: "2026-09-27T00:00:00Z"}
	if r.NeedsRefresh(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)) || !r.NeedsRefresh(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("refresh timing wrong")
	}
}

func TestTiersAndKeys(t *testing.T) {
	if Rank("bogus") >= Rank(TierCommunity) {
		t.Fatal("unknown tier must rank below community")
	}
	if Includes(TierCommunity, "tls.inspect") || !Includes(TierPro, "tls.inspect") || Includes(TierPro, "telemetry.export") || !Includes(TierBusiness, "telemetry.export") {
		t.Fatal("catalogue wrong")
	}
	if !Includes(TierCommunity, "something.unlisted") {
		t.Fatal("unlisted features are free")
	}
	k := NewKey(TierPro)
	if !strings.HasPrefix(k, "FSP-") || len(k) != 23 {
		t.Fatalf("key format: %s", k)
	}
	if NormalizeKey(" fsp-7k3m-2q9x-w8rt-5hbd ") != "FSP-7K3M-2Q9X-W8RT-5HBD" {
		t.Fatal("normalize")
	}
	if Limit(TierCommunity, LimitPolicies) != 3 || Limit(TierPro, LimitPolicies) != 0 {
		t.Fatal("limits")
	}
}
