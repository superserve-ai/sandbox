// Package secretsproxy is the in-host MITM enforcement daemon: it terminates
// TLS, applies the allowlist + credential-injection pipeline, and forwards upstream.
package secretsproxy

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA mints leaf certificates on demand for each intercepted hostname.
type CA struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootPEM  []byte
	cache    *leafCache
}

const (
	leafLifetime = 72 * time.Hour
	rootLifetime = 10 * 365 * 24 * time.Hour

	// leafRenewBefore re-mints a cached leaf this long before it expires, so a
	// hot SNI that never falls out of the LRU can't be served a stale cert (and
	// so a cert can't expire mid-connection). Comfortably larger than any single
	// request, negligible waste against the 72h lifetime.
	leafRenewBefore = 1 * time.Hour
)

// NewCA loads the CA from disk or generates a new one and persists the key with mode 0600.
func NewCA(caCertPath, caKeyPath string, cacheSize int) (*CA, error) {
	certPEM, errCert := os.ReadFile(caCertPath)
	keyPEM, errKey := os.ReadFile(caKeyPath)

	switch {
	case errCert == nil && errKey == nil:
		return loadCA(certPEM, keyPEM, cacheSize)
	case errors.Is(errCert, os.ErrNotExist) && errors.Is(errKey, os.ErrNotExist):
		return generateAndPersistCA(caCertPath, caKeyPath, cacheSize)
	default:
		// One file present, one missing → fail loud rather than orphan trust.
		if errCert != nil {
			return nil, fmt.Errorf("read CA cert: %w", errCert)
		}
		return nil, fmt.Errorf("read CA key: %w", errKey)
	}
}

func loadCA(certPEM, keyPEM []byte, cacheSize int) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CA cert PEM is missing or wrong type")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil || kblock.Type != "EC PRIVATE KEY" {
		return nil, errors.New("CA key PEM is missing or wrong type (want EC PRIVATE KEY)")
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{
		rootCert: cert,
		rootKey:  key,
		rootPEM:  certPEM,
		cache:    newLeafCache(cacheSize),
	}, nil
}

// GenerateCA mints a fresh ECDSA P-256 self-signed CA and returns the PEM pair.
func GenerateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Superserve Sandbox Proxy CA",
			Organization: []string{"Superserve"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(rootLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("self-sign CA: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func generateAndPersistCA(caCertPath, caKeyPath string, cacheSize int) (*CA, error) {
	certPEM, keyPEM, err := GenerateCA()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(caCertPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir CA cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(caKeyPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir CA key dir: %w", err)
	}
	if err := os.WriteFile(caCertPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(caKeyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}
	return loadCA(certPEM, keyPEM, cacheSize)
}

// RootPEM returns the CA certificate in PEM form.
func (ca *CA) RootPEM() []byte { return ca.rootPEM }

// MintLeaf returns a TLS leaf cert for sni, generating + caching on miss. Concurrency-safe.
func (ca *CA) MintLeaf(sni string) (*tls.Certificate, error) {
	if err := validateSNI(sni); err != nil {
		return nil, err
	}
	if c, ok := ca.cache.get(sni); ok {
		return c, nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := ca.cache.now().Add(leafLifetime)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    ca.cache.now().Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(sni); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{sni}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.rootCert, &leafKey.PublicKey, ca.rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", sni, err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{der, ca.rootCert.Raw},
		PrivateKey:  leafKey,
	}
	ca.cache.set(sni, cert, notAfter)
	return cert, nil
}

// validateSNI bounds the LRU-cache attack surface: cap at the DNS-name max
// (253 bytes), reject control chars, allow IP literals through.
func validateSNI(sni string) error {
	if sni == "" {
		return fmt.Errorf("sni: empty")
	}
	if len(sni) > 253 {
		return fmt.Errorf("sni: %d bytes exceeds DNS-name max of 253", len(sni))
	}
	if net.ParseIP(sni) != nil {
		return nil
	}
	for i := 0; i < len(sni); i++ {
		c := sni[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("sni: control character at byte %d", i)
		}
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("rand serial: %w", err)
	}
	return n, nil
}

// leafCache is a fixed-size LRU keyed by SNI hostname.
type leafCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	order    *list.List
	// now is the clock, injectable for tests. Both minting (leaf validity) and
	// cache expiry read it, so a test can advance one clock past a leaf's life.
	now func() time.Time
}

type leafCacheEntry struct {
	sni      string
	cert     *tls.Certificate
	notAfter time.Time
}

func newLeafCache(capacity int) *leafCache {
	if capacity <= 0 {
		capacity = 1024
	}
	return &leafCache{
		capacity: capacity,
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
		now:      time.Now,
	}
}

// get returns a cached leaf only while it stays valid past the renew window. A
// leaf within leafRenewBefore of expiry is treated as a miss so the caller
// re-mints — without this the LRU would serve a hot SNI's expired cert forever
// (evicting only under capacity pressure, never on age).
func (c *leafCache) get(sni string) (*tls.Certificate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[sni]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*leafCacheEntry)
	if !c.now().Add(leafRenewBefore).Before(entry.notAfter) {
		// Concurrent connections in the renew window each re-mint (set is
		// last-writer-wins) until the first fresh cert lands — a handful of
		// extra sub-ms signs once per 72h per SNI, not worth coalescing.
		return nil, false
	}
	c.order.MoveToFront(el)
	return entry.cert, true
}

func (c *leafCache) set(sni string, cert *tls.Certificate, notAfter time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[sni]; ok {
		entry := el.Value.(*leafCacheEntry)
		entry.cert = cert
		entry.notAfter = notAfter
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&leafCacheEntry{sni: sni, cert: cert, notAfter: notAfter})
	c.items[sni] = el
	if c.order.Len() > c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*leafCacheEntry).sni)
		}
	}
}

func (c *leafCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
