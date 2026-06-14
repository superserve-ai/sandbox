// Command gen-secrets-signing-key writes a base64-encoded Ed25519
// 32-byte private seed to stdout — the value SECRETS_SIGNING_KEY expects.
// Pipe it directly into whatever secret store the deployment uses;
// nothing is written to disk by this command.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate ed25519 key:", err)
		os.Exit(1)
	}
	// No trailing newline — most secret stores treat stdin bytes literally.
	if _, err := fmt.Print(base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		fmt.Fprintln(os.Stderr, "write seed:", err)
		os.Exit(1)
	}
}
