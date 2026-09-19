// flowsight-sign is a helper to generate ed25519 keypairs and sign release sha256 hashes.
//
// Usage:
//
//	flowsight-sign gen                 Generate a new keypair
//	flowsight-sign sign -key file -sha256 hex    Sign a sha256 hash
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: flowsight-sign gen | sign -key file -sha256 hex\n")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "gen":
		doGen()
	case "sign":
		doSign()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func doGen() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	fmt.Println("Public key (for updater.go PublicKeyBase64):")
	fmt.Println(pubB64)
	fmt.Println()
	fmt.Println("Private key (keep secret, for release pipeline):")
	fmt.Println(privB64)
}

func doSign() {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "path to private key file (base64-encoded)")
	sha256Hex := fs.String("sha256", "", "sha256 hash hex string to sign")
	fs.Parse(os.Args[2:])

	if *keyFile == "" || *sha256Hex == "" {
		fmt.Fprintf(os.Stderr, "usage: flowsight-sign sign -key file -sha256 hex\n")
		os.Exit(1)
	}

	// Read and decode private key
	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading key file: %v\n", err)
		os.Exit(1)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding private key: %v\n", err)
		os.Exit(1)
	}

	priv := ed25519.PrivateKey(privKeyBytes)

	// Validate sha256 hex format
	if _, err := hex.DecodeString(*sha256Hex); err != nil {
		fmt.Fprintf(os.Stderr, "error: sha256 is not valid hex: %v\n", err)
		os.Exit(1)
	}

	// Sign the sha256 hex string
	sig := ed25519.Sign(priv, []byte(*sha256Hex))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	fmt.Println(sigB64)
}
