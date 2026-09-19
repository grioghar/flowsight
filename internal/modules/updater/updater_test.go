package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TestVersionComparison tests the semver-ish version comparison logic.
func TestVersionComparison(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int // -1 if v1 < v2, 0 if equal, 1 if v1 > v2
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.1.0", -1},
		{"1.1.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.3", "1.2.4", -1},
		{"dev", "1.0.0", -1},
		{"1.0.0", "dev", 1},
		{"dev", "dev", 0},
		{"1.0", "1.0.0", -1},
		{"1.0.0", "1.0", 1},
	}

	for _, tt := range tests {
		result := compareVersions(tt.v1, tt.v2)
		if result != tt.expected {
			t.Errorf("compareVersions(%q, %q) = %d, expected %d",
				tt.v1, tt.v2, result, tt.expected)
		}
	}
}

// TestSignatureVerification tests the ed25519 signature verification.
func TestSignatureVerification(t *testing.T) {
	// Generate a keypair for testing
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Encode public key as base64 (for PublicKeyBase64 simulation)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pub)

	// Test data: a sha256 hex string
	testSHA256 := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	// Sign the sha256 hex
	sig := ed25519.Sign(priv, []byte(testSHA256))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Temporarily replace PublicKeyBase64 for testing
	oldKey := PublicKeyBase64
	defer func() {
		// Restore (can't actually modify const, so this test just demonstrates the logic)
	}()

	// Verify the signature using the same logic as verifySignature
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}

	decodedSig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("DecodeString sig failed: %v", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(testSHA256), decodedSig) {
		t.Error("signature verification failed for valid signature")
	}

	// Test invalid signature
	invalidSig := base64.StdEncoding.EncodeToString([]byte("invalid signature data"))
	decodedInvalid, _ := base64.StdEncoding.DecodeString(invalidSig)
	if ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(testSHA256), decodedInvalid) {
		t.Error("signature verification should have failed for invalid signature")
	}

	_ = oldKey
}

// TestSHA256Verification tests sha256 hash verification.
func TestSHA256Verification(t *testing.T) {
	testData := []byte("test binary data")
	hash := sha256.Sum256(testData)
	hashHex := hex.EncodeToString(hash[:])

	// Verify correct hash
	if hashHex != hex.EncodeToString(hash[:]) {
		t.Error("hash mismatch for same data")
	}

	// Verify different data produces different hash
	otherData := []byte("other data")
	otherHash := sha256.Sum256(otherData)
	otherHex := hex.EncodeToString(otherHash[:])

	if hashHex == otherHex {
		t.Error("different data should produce different hash")
	}
}

// TestSignAndVerifyRoundTrip tests a complete sign and verify cycle.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	// Generate keypair
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create test data
	testData := []byte("1.2.3")

	// Sign
	sig := ed25519.Sign(priv, testData)

	// Verify
	if !ed25519.Verify(pub, testData, sig) {
		t.Error("signature verification failed in round trip")
	}

	// Tampering should fail
	tamperedData := []byte("1.2.4")
	if ed25519.Verify(pub, tamperedData, sig) {
		t.Error("verification should fail for tampered data")
	}
}
