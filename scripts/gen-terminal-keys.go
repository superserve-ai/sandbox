//go:build ignore

// gen-terminal-keys generates a fresh Ed25519 keypair for the web terminal
// feature.
//
// Usage
//
//	# Print to stdout — convenient for piping
//	go run scripts/gen-terminal-keys.go | gpg --symmetric > keys.gpg
//
//	# Or write each half to a file (recommended — keeps the private
//	# key out of terminal scrollback and tmux history)
//	go run scripts/gen-terminal-keys.go --out=./keys
//
// With --out, the script writes two files:
//
//	<out>.private  (mode 0600)  base64-encoded 64-byte Ed25519 private key
//	<out>.public   (mode 0644)  base64-encoded 32-byte Ed25519 public key
//
// Files always have a trailing newline so they can be passed straight to
// `gcloud secrets versions add --data-file=` without an extra newline
// landing in the secret value (we use base64.RawStdEncoding-compatible
// `\n` stripping on the consume side).
//
// Without --out, the script prints both halves to stdout in
// `KEY: <base64>` format. The private key is on the FIRST line so a
// careless paste of `head -1` doesn't accidentally hand someone the
// public key when they wanted the private one. Pipe it; do not paste it.
//
// The script is otherwise non-interactive and uses crypto/rand, so every
// run produces a different, unrelated keypair.
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
	"flag"
	"fmt"
	"os"
)

func main() {
	out := flag.String("out", "", "if set, write keys to <out>.private and <out>.public instead of stdout")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ed25519.GenerateKey:", err)
		os.Exit(1)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	if *out == "" {
		// Stdout path. Private first so 'head -1' doesn't surprise.
		fmt.Println("PRIVATE:", privB64)
		fmt.Println("PUBLIC: ", pubB64)
		return
	}

	// File path. Write private with restrictive perms; the public file
	// is fine at the default 0644 because the value is non-secret.
	privFile := *out + ".private"
	pubFile := *out + ".public"
	if err := os.WriteFile(privFile, []byte(privB64+"\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write private:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(pubFile, []byte(pubB64+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write public:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (0600) and %s (0644)\n", privFile, pubFile)
}
