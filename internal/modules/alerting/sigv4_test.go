package alerting

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestSigV4KnownVector tests SigV4 signing against the AWS documentation example.
// This uses the GET request example from AWS SigV4 documentation:
// GET /?Param2=value2&Param1=value1 HTTP/1.1
// Host: example.amazonaws.com
//
// Expected signature: b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500
func TestSigV4KnownVector(t *testing.T) {
	// AWS test vector constants
	secretKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	region := "us-east-1"
	service := "service"
	_ = secretKey // Used in deriving keys below

	// Create request matching AWS example
	req, _ := http.NewRequest("GET", "http://example.amazonaws.com/?Param2=value2&Param1=value1", nil)
	req.Header.Set("Host", "example.amazonaws.com")

	// Use fixed timestamp for reproducibility
	timestamp := "20150830T123600Z"
	datestamp := "20150830"

	// Create canonical request
	canonicalRequest := createCanonicalRequest(req, []byte(""), timestamp)

	// Expected canonical request (from AWS docs, simplified)
	expectedParts := []string{
		"GET",
		"/",
		"Param1=value1&Param2=value2",
	}

	for _, part := range expectedParts {
		if !strings.Contains(canonicalRequest, part) {
			t.Logf("Canonical request missing expected part: %s", part)
			t.Logf("Full canonical request:\n%s", canonicalRequest)
		}
	}

	// Hash the canonical request
	hashedCanonical := hashSHA256(canonicalRequest)

	// Build string to sign
	stringToSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + datestamp + "/" + region + "/" + service + "/aws4_request\n" + hashedCanonical

	// Derive signing key step by step
	kSecret := []byte("AWS4" + secretKey)
	kDate := hmacSHA256(kSecret, datestamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")

	// Calculate signature
	signature := hashSHA256String(kSigning, stringToSign)

	// AWS documentation expects: b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500
	expectedSignature := "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"

	if signature != expectedSignature {
		t.Errorf("Signature mismatch.\nGot:      %s\nExpected: %s", signature, expectedSignature)
		t.Logf("Canonical request:\n%s", canonicalRequest)
		t.Logf("String to sign:\n%s", stringToSign)
	}
}

// hashSHA256String is a helper for testing
func hashSHA256String(key []byte, message string) string {
	h := hmacSHA256(key, message)
	return fmt.Sprintf("%x", h)
}

// TestHashSHA256 tests SHA256 hashing
func TestHashSHA256(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			input:    "test",
			expected: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}

	for _, test := range tests {
		result := hashSHA256(test.input)
		if result != test.expected {
			t.Errorf("hashSHA256(%q) = %s, want %s", test.input, result, test.expected)
		}
	}
}

// TestCanonicalRequest tests canonical request creation
func TestCanonicalRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/path", nil)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Content-Type", "application/json")

	canonical := createCanonicalRequest(req, []byte("body"), "20150830T123600Z")

	if !strings.HasPrefix(canonical, "POST\n") {
		t.Error("Canonical request should start with method")
	}

	if !strings.Contains(canonical, "host:example.com") {
		t.Error("Canonical request should include host header")
	}
}

// TestURIEncode tests URI encoding
func TestURIEncode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/", "/"},
		{"/path/to/resource", "/path/to/resource"},
		{"/path with space", "/path%20with%20space"},
		{"/?query=1", "/%3Fquery%3D1"},
	}

	for _, test := range tests {
		result := uriEncode(test.input)
		if result != test.expected {
			t.Errorf("uriEncode(%q) = %q, want %q", test.input, result, test.expected)
		}
	}
}

// TestSignRequest tests the full SignRequest function
func TestSignRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://email.us-east-1.amazonaws.com/", bytes.NewBuffer([]byte(`{"test":"data"}`)))
	req.Header.Set("Host", "email.us-east-1.amazonaws.com")
	req.Header.Set("Content-Type", "application/json")

	err := SignRequest(req, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "ses", []byte(`{"test":"data"}`))

	if err != nil {
		t.Errorf("SignRequest failed: %v", err)
	}

	if req.Header.Get("Authorization") == "" {
		t.Error("Authorization header not set")
	}

	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date header not set")
	}
}

// TestGetCanonicalHeaders tests header canonicalization
func TestGetCanonicalHeaders(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com", nil)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-Date", "20150830T123600Z")

	headers := getCanonicalHeaders(req, "20150830T123600Z")

	if !strings.Contains(headers, "host:example.com") {
		t.Error("Headers should include host")
	}

	if !strings.Contains(headers, "x-amz-date:") {
		t.Error("Headers should include x-amz-date")
	}

	if !strings.Contains(headers, "content-type:application/json") {
		t.Error("Headers should include content-type")
	}
}

// TestGetSignedHeaders tests signed header list
func TestGetSignedHeaders(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com", nil)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("X-Custom", "custom")

	headers := getSignedHeaders(req)

	if !strings.Contains(headers, "host") {
		t.Error("Signed headers should include host")
	}

	if !strings.Contains(headers, "content-type") {
		t.Error("Signed headers should include content-type")
	}

	if !strings.Contains(headers, "x-amz-date") {
		t.Error("Signed headers should include x-amz-date")
	}

	if strings.Contains(headers, "x-custom") {
		t.Error("Signed headers should not include custom headers")
	}
}
