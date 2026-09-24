package paths

import "testing"

func TestAbuseIPDBAnswerIsReduced(t *testing.T) {
	r, err := parseAbuseIPDB([]byte(`{"data":{"ipAddress":"118.25.6.39","isPublic":true,"abuseConfidenceScore":100,"countryCode":"CN","usageType":"Data Center/Web Hosting/Transit","isp":"Tencent Cloud Computing","domain":"tencent.com","isTor":false,"isWhitelisted":false,"totalReports":12,"numDistinctUsers":9,"lastReportedAt":"2026-09-24T09:00:00+00:00"}}`))
	if err != nil || r.Score != 100 || r.Reports != 12 || r.Reporters != 9 || r.ISP != "Tencent Cloud Computing" || r.Country != "CN" || r.Source != "AbuseIPDB" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := parseAbuseIPDB([]byte(`{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this endpoint.","status":429}]}`)); err == nil {
		t.Fatal("an error body must be an error")
	}
	m := &Module{}
	if m.reputationWanted("8.8.8.8") {
		t.Fatal("without a key nothing is asked")
	}
}
