package alerting

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// cwSignedRequest holds the signed request components.
type cwSignedRequest struct {
	Headers map[string]string
	Body    string
}

// cwSignRequest creates an AWS SigV4-signed CloudWatch Logs request.
// Returns headers to add to the HTTP request.
func cwSignRequest(method, endpoint, accessKey, secretKey, region, target string, body []byte) (*cwSignedRequest, error) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	service := "logs"

	// Step 1: Create canonical request
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")

	payloadHash := cwSHA256Hex(body)

	canonicalHeaders := map[string]string{
		"content-type": "application/x-amz-json-1.1",
		"host":         host,
		"x-amz-date":   amzDate,
		"x-amz-target": target,
	}

	canonicalHeadersStr := ""
	headerNames := make([]string, 0)
	for k := range canonicalHeaders {
		headerNames = append(headerNames, k)
	}
	sort.Strings(headerNames)

	for _, k := range headerNames {
		canonicalHeadersStr += fmt.Sprintf("%s:%s\n", k, canonicalHeaders[k])
	}

	signedHeaders := strings.Join(headerNames, ";")

	canonicalRequest := fmt.Sprintf(
		"%s\n/\n\n%s\n%s\n%s",
		method,
		canonicalHeadersStr,
		signedHeaders,
		payloadHash,
	)

	// Step 2: Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	canonicalRequestHash := cwSHA256Hex([]byte(canonicalRequest))

	stringToSign := fmt.Sprintf(
		"AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		canonicalRequestHash,
	)

	// Step 3: Calculate signature
	kDate := cwHMAC([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := cwHMAC(kDate, []byte(region))
	kService := cwHMAC(kRegion, []byte(service))
	kSigning := cwHMAC(kService, []byte("aws4_request"))

	signature := hex.EncodeToString(cwHMAC(kSigning, []byte(stringToSign)))

	// Step 4: Create authorization header
	authorizationHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey,
		credentialScope,
		signedHeaders,
		signature,
	)

	headers := map[string]string{
		"Authorization": authorizationHeader,
		"Content-Type":  "application/x-amz-json-1.1",
		"X-Amz-Date":    amzDate,
		"X-Amz-Target":  target,
		"Host":          host,
	}

	return &cwSignedRequest{
		Headers: headers,
		Body:    string(body),
	}, nil
}

// cwHMAC computes HMAC-SHA256.
func cwHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// cwSHA256Hex computes SHA256 and returns hex-encoded result.
func cwSHA256Hex(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
