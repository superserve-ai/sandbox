// Command gen-secretsproxy-ca writes a fresh CA cert (0644) + key (0600)
// to the paths given by -cert and -key.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/superserve-ai/sandbox/internal/secretsproxy"
)

func main() {
	certPath := flag.String("cert", "", "output path for the PEM certificate (required)")
	keyPath := flag.String("key", "", "output path for the PEM private key (required)")
	flag.Parse()
	if *certPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "both -cert and -key are required")
		os.Exit(2)
	}
	certPEM, keyPEM, err := secretsproxy.GenerateCA()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate CA:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*certPath, certPEM, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write cert:", err)
		os.Exit(1)
	}
	// Force final mode regardless of umask — a restrictive umask can
	// otherwise leave the key unreadable by the daemon at runtime.
	if err := os.Chmod(*certPath, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "chmod cert:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*keyPath, keyPEM, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write key:", err)
		os.Exit(1)
	}
	if err := os.Chmod(*keyPath, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "chmod key:", err)
		os.Exit(1)
	}
}
