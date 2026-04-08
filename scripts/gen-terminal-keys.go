//go:build ignore

// gen-terminal-keys generates a fresh Ed25519 keypair for the web terminal
// feature and prints both halves base64-encoded. Run once per environment:
//
//	go run scripts/gen-terminal-keys.go
//
// Output:
//
//	PRIVATE: <base64-64-bytes>
//	PUBLIC:  <base64-32-bytes>
//
// Then:
//   - Put PRIVATE in GCP Secret Manager as the control plane's
//     `terminal-token-private-key-<env>` secret.
//   - Put PUBLIC in the bare metal edge proxy's /etc/superserve/proxy.env
//     as TERMINAL_TOKEN_PUBLIC_KEY=<value>.
//
// The script is non-interactive and outputs nothing else, so piping the
// output into files or secret managers is safe. It uses crypto/rand so
// every run produces a different, unrelated keypair — there is no shared
// state with prior runs.
//
// Why a throwaway Go program instead of openssl:
//   - Ed25519 key formats differ between tools (openssl produces PEM,
//     we want raw bytes base64-encoded to match how auth.NewSigner and
//     auth.NewVerifier parse them).
//   - No extra binary dependency — Go is already required to build the
//     project.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ed25519.GenerateKey:", err)
		os.Exit(1)
	}
	fmt.Println("PRIVATE:", base64.StdEncoding.EncodeToString(priv))
	fmt.Println("PUBLIC: ", base64.StdEncoding.EncodeToString(pub))
}
