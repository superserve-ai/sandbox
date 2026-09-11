package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/rs/zerolog"
	"net/netip"
	"os"
	"strings"
)

type PeerTLSConfig struct {
	CertFile, KeyFile, CAFile, ExpectedSPIFFE string
	Log                                       zerolog.Logger
}

// LoadClient constructs client credentials with server authentication enabled.
func (c PeerTLSConfig) LoadClient() (*tls.Config, error) {
	base, err := c.Load()
	if err != nil {
		return nil, err
	}
	// SPIFFE authenticates the URI rather than the dial target. Verify the
	// chain explicitly because gRPC fills ServerName from that target.
	return &tls.Config{Certificates: base.Certificates, RootCAs: base.ClientCAs, MinVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, // Chain and URI verification are mandatory below.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing peer certificate")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: base.ClientCAs, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return fmt.Errorf("verify peer certificate chain: %w", err)
			}
			for _, u := range state.PeerCertificates[0].URIs {
				if u.String() == c.ExpectedSPIFFE {
					return nil
				}
			}
			return fmt.Errorf("unauthorized peer identity")
		},
	}, nil
}

func (c PeerTLSConfig) Load() (*tls.Config, error) {
	if strings.TrimSpace(c.ExpectedSPIFFE) == "" {
		return nil, fmt.Errorf("expected peer SPIFFE URI is required")
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("invalid peer CA")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13, VerifyConnection: func(state tls.ConnectionState) error {
		// VerifyConnection is intentionally diagnostic-only: the standard TLS
		// verifier remains authoritative, while this records transports that
		// reached the callback without a trusted client chain.
		if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
			if c.Log.GetLevel() != zerolog.NoLevel {
				c.Log.Warn().Msg("peer TLS authentication failed: untrusted client certificate")
			}
		}
		return nil
	}, VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			if c.Log.GetLevel() != zerolog.NoLevel {
				c.Log.Warn().Msg("peer TLS authentication failed: missing client certificate")
			}
			return fmt.Errorf("missing client certificate")
		}
		crt, e := x509.ParseCertificate(raw[0])
		if e != nil {
			if c.Log.GetLevel() != zerolog.NoLevel {
				c.Log.Warn().Err(e).Msg("peer TLS authentication failed: invalid client certificate")
			}
			return e
		}
		for _, u := range crt.URIs {
			if u.String() == c.ExpectedSPIFFE {
				return nil
			}
		}
		if c.Log.GetLevel() != zerolog.NoLevel {
			c.Log.Warn().Str("expected_spiffe", c.ExpectedSPIFFE).Msg("peer TLS authentication failed: unauthorized identity")
		}
		return fmt.Errorf("unauthorized peer identity")
	}}, nil
}

func PrivateBind(addr string) bool {
	parsed, err := netip.ParseAddrPort(addr)
	if err != nil {
		return false
	}
	ip := parsed.Addr()
	// A peer listener must be bound to a concrete RFC1918/ULA private address.
	// Check the parsed address rather than textual prefixes so expanded IPv6
	// wildcard forms and other non-routable special addresses cannot slip
	// through the guard.
	if parsed.Port() == 0 || !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	return ip.IsPrivate()
}
