package secretsproxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// farFuture is an expiry well beyond any test's clock, so LRU-eviction tests
// exercise capacity, not the leaf-expiry check.
var farFuture = time.Now().Add(1000 * time.Hour)

func TestNewCAGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := NewCA(certPath, keyPath, 16)
	if err != nil {
		t.Fatal(err)
	}
	if ca.RootPEM() == nil || !strings.Contains(string(ca.RootPEM()), "BEGIN CERTIFICATE") {
		t.Fatal("RootPEM did not return a PEM block")
	}

	// Files should exist with the expected modes.
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Errorf("cert file mode = %o, want 0644", certInfo.Mode().Perm())
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestNewCAReloadsExistingMaterial(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	first, err := NewCA(certPath, keyPath, 16)
	if err != nil {
		t.Fatal(err)
	}
	firstPEM := string(first.RootPEM())

	// Second invocation must reuse the on-disk material — restart safety.
	second, err := NewCA(certPath, keyPath, 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(second.RootPEM()) != firstPEM {
		t.Errorf("CA was regenerated on reload; sandboxes that trust the old CA would break")
	}
}

func TestNewCAFailsLoudOnMixedPresence(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Bootstrap to get real material.
	if _, err := NewCA(certPath, keyPath, 16); err != nil {
		t.Fatal(err)
	}
	// Delete the key but leave the cert.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA(certPath, keyPath, 16); err == nil {
		t.Fatal("expected error on mixed cert-present / key-missing state — silent regen would orphan sandboxes")
	}
}

func TestMintLeafProducesValidServerCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 16)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Certificate) < 2 {
		t.Fatal("leaf should chain to the CA (2+ DER blocks)")
	}

	// Parse the leaf and verify CN/DNS SAN.
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject.CommonName != "api.openai.com" {
		t.Errorf("CN = %q, want api.openai.com", parsed.Subject.CommonName)
	}
	dnsFound := false
	for _, n := range parsed.DNSNames {
		if n == "api.openai.com" {
			dnsFound = true
		}
	}
	if !dnsFound {
		t.Errorf("DNS SAN missing api.openai.com, got %v", parsed.DNSNames)
	}

	// And the leaf must verify against the CA we minted from.
	roots := x509.NewCertPool()
	rootParsed, err := x509.ParseCertificate(leaf.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(rootParsed)
	if _, err := parsed.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "api.openai.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf failed CA verify: %v", err)
	}
}

func TestMintLeafForIPLiteral(t *testing.T) {
	// IP literals must be encoded as IP SAN, not DNS SAN.
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 16)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.MintLeaf("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSNames) != 0 {
		t.Errorf("DNS SAN should be empty for IP literal, got %v", parsed.DNSNames)
	}
	if len(parsed.IPAddresses) != 1 || !parsed.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP SAN want [127.0.0.1], got %v", parsed.IPAddresses)
	}
}

func TestMintLeafCachesHits(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 16)
	if err != nil {
		t.Fatal(err)
	}
	leaf1, err := ca.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := ca.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	// Same pointer — second call hit the cache rather than re-minting.
	if leaf1 != leaf2 {
		t.Errorf("expected cache hit to return same cert; got distinct pointers (cache miss)")
	}
	if ca.cache.len() != 1 {
		t.Errorf("cache should have 1 entry after two requests for same SNI, got %d", ca.cache.len())
	}
}

// TestMintLeafRemintsExpiredCacheEntry guards the leaf-cache expiry bug: a hot
// SNI never falls out of the LRU, so without an age check the cache would serve
// the same leaf past its 72h validity forever (observed as CERT_HAS_EXPIRED
// through the proxy). Advancing the clock past the renew window must force a
// re-mint, not a stale hit.
func TestMintLeafRemintsExpiredCacheEntry(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 16)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	ca.cache.now = func() time.Time { return base }

	leaf1, err := ca.MintLeaf("api.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Still inside the leaf's life, minus the renew window: cache hit.
	ca.cache.now = func() time.Time { return base.Add(leafLifetime - leafRenewBefore - time.Minute) }
	if leaf2, err := ca.MintLeaf("api.example.com"); err != nil {
		t.Fatal(err)
	} else if leaf1 != leaf2 {
		t.Errorf("expected cache hit before the renew window; got a re-mint")
	}

	// Inside the renew window (about to expire): must re-mint, not serve stale.
	ca.cache.now = func() time.Time { return base.Add(leafLifetime - leafRenewBefore/2) }
	leaf3, err := ca.MintLeaf("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if leaf1 == leaf3 {
		t.Errorf("expected re-mint within the renew window; cache served the stale leaf")
	}
	if ca.cache.len() != 1 {
		t.Errorf("re-mint should replace the entry in place, got %d entries", ca.cache.len())
	}
}

func TestMintLeafConcurrentSafe(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 64)
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{
		"api.openai.com", "api.anthropic.com", "api.github.com",
		"api.stripe.com", "slack.com", "api.linear.app",
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 256)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			host := hosts[n%len(hosts)]
			if _, err := ca.MintLeaf(host); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent MintLeaf: %v", err)
	}
	if ca.cache.len() != len(hosts) {
		t.Errorf("expected cache to hold %d distinct hosts, got %d", len(hosts), ca.cache.len())
	}
}

func TestLeafCacheEvictsLRU(t *testing.T) {
	c := newLeafCache(2)
	c.set("a", &tls.Certificate{}, farFuture)
	c.set("b", &tls.Certificate{}, farFuture)
	c.set("c", &tls.Certificate{}, farFuture) // evicts a

	if _, ok := c.get("a"); ok {
		t.Errorf("a should have been evicted as LRU")
	}
	if _, ok := c.get("b"); !ok {
		t.Errorf("b should still be cached")
	}
	if _, ok := c.get("c"); !ok {
		t.Errorf("c should still be cached")
	}
}

func TestLeafCachePromotesOnGet(t *testing.T) {
	c := newLeafCache(2)
	c.set("a", &tls.Certificate{}, farFuture)
	c.set("b", &tls.Certificate{}, farFuture)
	// Touch a so it's no longer the LRU; b should evict next.
	if _, ok := c.get("a"); !ok {
		t.Fatal("a missing before LRU promotion")
	}
	c.set("c", &tls.Certificate{}, farFuture) // should evict b, not a
	if _, ok := c.get("a"); !ok {
		t.Errorf("a was unexpectedly evicted after being touched")
	}
	if _, ok := c.get("b"); ok {
		t.Errorf("b should have been evicted as the new LRU")
	}
}

func TestLeafCacheZeroCapacityDefaults(t *testing.T) {
	// A 0 capacity would otherwise immediately evict every entry; we
	// expect a sensible default so callers can pass 0 safely.
	c := newLeafCache(0)
	c.set("a", &tls.Certificate{}, farFuture)
	if _, ok := c.get("a"); !ok {
		t.Errorf("zero-capacity cache should have fallen back to a default")
	}
}

func TestMintLeafRejectsAttackerControlledSNI(t *testing.T) {
	// Overlong or control-character SNIs must be rejected before they touch
	// the LRU cache, so an attacker can't grind it with many unique inputs.
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), 32)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sni  string
	}{
		{"empty", ""},
		{"too long", strings.Repeat("a.", 200)},                         // 400 bytes
		{"control character", "evil.example.com\x00.actual.example.com"}, // null injection
		{"newline", "host\nhost2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ca.MintLeaf(c.sni); err == nil {
				t.Errorf("MintLeaf(%q) should have rejected, got nil error", c.sni)
			}
		})
	}

	// Sanity: a normal hostname still works.
	if _, err := ca.MintLeaf("api.example.com"); err != nil {
		t.Errorf("MintLeaf for normal host failed: %v", err)
	}
}
