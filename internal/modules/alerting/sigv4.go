package alerting

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// SignRequest signs an HTTP request with AWS SigV4.
// Modifies the request by adding Authorization and X-Amz-Date headers.
func SignRequest(req *http.Request, accessKey, secretKey, region, service string, body []byte) error {
	t := time.Now().UTC()
	timestamp := t.Format("20060102T150405Z")
	datestamp := t.Format("20060102")

	// Step 1: Create a canonical request
	canonicalRequest := createCanonicalRequest(req, body, timestamp)

	// Step 2: Create a string to sign
	hashedCanonical := hashSHA256(canonicalRequest)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
		timestamp, datestamp, region, service, hashedCanonical)

	// Step 3: Calculate the signature
	kSecret := []byte("AWS4" + secretKey)
	kDate := hmacSHA256(kSecret, datestamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := fmt.Sprintf("%x", hmacSHA256(kSigning, stringToSign))

	// Step 4: Add the authorization header
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)
	signedHeaders := getSignedHeaders(req)
	authorizationHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)

	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("X-Amz-Date", timestamp)

	return nil
}

// createCanonicalRequest creates the canonical request string for signing.
func createCanonicalRequest(req *http.Request, body []byte, timestamp string) string {
	method := req.Method
	canonicalURI := getCanonicalURI(req)
	canonicalQueryString := getCanonicalQueryString(req)
	canonicalHeaders := getCanonicalHeaders(req, timestamp)
	signedHeaders := getSignedHeaders(req)
	payloadHash := hashSHA256(string(body))

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash)
}

// getCanonicalURI returns the canonical URI path.
func getCanonicalURI(req *http.Request) string {
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	// URI encode but don't encode forward slashes
	return uriEncode(path)
}

// getCanonicalQueryString returns the canonical query string.
func getCanonicalQueryString(req *http.Request) string {
	params := req.URL.Query()
	if len(params) == 0 {
		return ""
	}

	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, fmt.Sprintf("%s=%s", uriEncode(k), uriEncode(v)))
		}
	}

	return strings.Join(parts, "&")
}

// getCanonicalHeaders returns canonical headers for signing.
func getCanonicalHeaders(req *http.Request, timestamp string) string {
	req.Header.Set("X-Amz-Date", timestamp)

	// Only sign relevant headers
	headerMap := make(map[string]string)
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		// Include host and x-amz-* headers
		if lk == "host" || strings.HasPrefix(lk, "x-amz-") || lk == "content-type" {
			if len(v) > 0 {
				headerMap[lk] = strings.TrimSpace(v[0])
			}
		}
	}

	// Sort and format
	var keys []string
	for k := range headerMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%s", k, headerMap[k]))
	}

	return strings.Join(parts, "\n") + "\n"
}

// getSignedHeaders returns the list of signed header names.
func getSignedHeaders(req *http.Request) string {
	headerMap := make(map[string]bool)
	for k := range req.Header {
		lk := strings.ToLower(k)
		if lk == "host" || strings.HasPrefix(lk, "x-amz-") || lk == "content-type" {
			headerMap[lk] = true
		}
	}

	var keys []string
	for k := range headerMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return strings.Join(keys, ";")
}

// uriEncode performs URI encoding with the AWS SigV4 rules.
func uriEncode(s string) string {
	result := ""
	for _, c := range s {
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			result += string(c)
		case c == '/':
			result += "/"
		default:
			result += fmt.Sprintf("%%%02X", c)
		}
	}
	return result
}

// hashSHA256 returns the SHA256 hash of a string as hex.
func hashSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// hmacSHA256 returns the HMAC-SHA256 of a message with a key.
func hmacSHA256(key []byte, message string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}
