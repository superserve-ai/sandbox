package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/api"
)

func writeRenewalFixture(t *testing.T, path string, value any) renewalEvidenceFile {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	return renewalEvidenceFile{Path: path, SHA256: hex.EncodeToString(hash[:])}
}

func renewalLoaderFixture(t *testing.T) (renewalStartupConfig, renewalEvidenceManifest) {
	t.Helper()
	dir := t.TempDir()
	live := false
	scope := renewalProviderScope{Merchant: "acct_example", Live: &live, APIVersion: "2026-05-27.dahlia"}
	m := renewalEvidenceManifest{Contract: api.RenewalBoundaryContractVersion, ReviewedSource: renewalReviewedSource, Scope: scope}
	m.Receipt = writeRenewalFixture(t, filepath.Join(dir, "receipt.json"), map[string]string{"source": renewalReviewedSource})
	m.Acceptance.Accepted, m.Acceptance.Contract, m.Acceptance.ReviewedSource, m.Acceptance.Scope = true, m.Contract, m.ReviewedSource, scope
	m.Acceptance.Disposition = writeRenewalFixture(t, filepath.Join(dir, "disposition.json"), map[string]string{
		"provider_evidence_status": "PASS/closed for exact renewal source" + renewalReviewedSource,
		"evidence":                 m.Receipt.Path,
	})
	for path, hash := range renewalCoveredSource {
		m.SourceCoverage = append(m.SourceCoverage, renewalEvidenceFile{Path: path, SHA256: hash})
	}
	terms := api.ProviderPairTerms{FeePriceID: "price_monthly", FeeProductID: "example_product", FeeAmount: 120000, FeeMonths: 1, Currency: "usd"}
	for _, key := range []string{"cpu", "memory", "storage", "rounding"} {
		r := api.StripeCheckoutResourceTerms{ResourceKey: key, PriceID: "price_" + key, UnitAmountDecimal: "1", MeterID: "meter_" + key, EventName: "event_" + key}
		if key == "rounding" {
			terms.Rounding = r
		} else {
			terms.Resources = append(terms.Resources, r)
		}
	}
	return renewalStartupConfig{Scope: scope, Monthly: terms, MonthlyVersion: 1, EvidenceDirectory: dir}, m
}

func installRenewalFixture(t *testing.T, cfg renewalStartupConfig, m renewalEvidenceManifest) string {
	t.Helper()
	cfg.EvidenceManifest = writeRenewalFixture(t, filepath.Join(cfg.EvidenceDirectory, "manifest.json"), m)
	path := filepath.Join(cfg.EvidenceDirectory, "config.json")
	writeRenewalFixture(t, path, cfg)
	t.Setenv("BILLING_RENEWAL_CHOICES_ENABLED", "true")
	t.Setenv("BILLING_RENEWAL_CHOICES_CONFIG", path)
	return path
}

func TestRenewalLoaderEvidence(t *testing.T) {
	for name, change := range map[string]func(*renewalStartupConfig, *renewalEvidenceManifest){
		"valid":              func(*renewalStartupConfig, *renewalEvidenceManifest) {},
		"unaccepted":         func(_ *renewalStartupConfig, m *renewalEvidenceManifest) { m.Acceptance.Accepted = false },
		"other merchant":     func(c *renewalStartupConfig, _ *renewalEvidenceManifest) { c.Scope.Merchant = "acct_other" },
		"other mode":         func(c *renewalStartupConfig, _ *renewalEvidenceManifest) { live := true; c.Scope.Live = &live },
		"missing mode":       func(c *renewalStartupConfig, _ *renewalEvidenceManifest) { c.Scope.Live = nil },
		"other version":      func(c *renewalStartupConfig, _ *renewalEvidenceManifest) { c.Scope.APIVersion = "unsupported" },
		"other source":       func(_ *renewalStartupConfig, m *renewalEvidenceManifest) { m.ReviewedSource = strings.Repeat("a", 40) },
		"coverage missing":   func(_ *renewalStartupConfig, m *renewalEvidenceManifest) { m.SourceCoverage = m.SourceCoverage[1:] },
		"coverage duplicate": func(_ *renewalStartupConfig, m *renewalEvidenceManifest) { m.SourceCoverage[1] = m.SourceCoverage[0] },
		"coverage changed": func(_ *renewalStartupConfig, m *renewalEvidenceManifest) {
			m.SourceCoverage[0].SHA256 = strings.Repeat("a", 64)
		},
		"receipt tampered": func(_ *renewalStartupConfig, m *renewalEvidenceManifest) {
			writeRenewalFixture(t, m.Receipt.Path, map[string]string{"source": "other"})
		},
		"disposition tampered": func(_ *renewalStartupConfig, m *renewalEvidenceManifest) {
			writeRenewalFixture(t, m.Acceptance.Disposition.Path, map[string]string{"provider_evidence_status": "pending"})
		},
		"disposition pending": func(_ *renewalStartupConfig, m *renewalEvidenceManifest) {
			m.Acceptance.Disposition = writeRenewalFixture(t, m.Acceptance.Disposition.Path, map[string]string{"provider_evidence_status": "pending", "evidence": m.Receipt.Path})
		},
		"other receipt accepted": func(_ *renewalStartupConfig, m *renewalEvidenceManifest) {
			m.Acceptance.Disposition = writeRenewalFixture(t, m.Acceptance.Disposition.Path, map[string]string{"provider_evidence_status": "PASS/closed for exact renewal source" + renewalReviewedSource, "evidence": "/other/receipt.json"})
		},
		"wrong period":       func(c *renewalStartupConfig, _ *renewalEvidenceManifest) { c.Monthly.FeeMonths = 12 },
		"incomplete mapping": func(c *renewalStartupConfig, _ *renewalEvidenceManifest) { c.Monthly.Resources = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, manifest := renewalLoaderFixture(t)
			change(&cfg, &manifest)
			installRenewalFixture(t, cfg, manifest)
			loaded, err := loadRenewalChoices(os.Getenv)
			if name != "valid" {
				if err == nil || loaded.Enabled || loaded.Boundary.Accepted {
					t.Fatal("invalid evidence accepted", err)
				}
				return
			}
			if err != nil || !loaded.Enabled || !loaded.Boundary.Accepted || loaded.Boundary.ReceiptDigest != manifest.Receipt.SHA256 {
				t.Fatal("valid evidence rejected", err)
			}
		})
	}
}

func TestRenewalLoaderDisabledDoesNotReadConfiguration(t *testing.T) {
	for _, flag := range []string{"", "false", "invalid"} {
		cfg, err := loadRenewalChoices(func(key string) string {
			if key != "BILLING_RENEWAL_CHOICES_ENABLED" {
				t.Fatal("disabled startup accessed configuration")
			}
			return flag
		})
		if cfg.Enabled || (flag == "invalid") != (err != nil) {
			t.Fatal(flag, cfg, err)
		}
	}
}

func TestRenewalLoaderRejectsChangedManifest(t *testing.T) {
	cfg, manifest := renewalLoaderFixture(t)
	installRenewalFixture(t, cfg, manifest)
	manifest.Acceptance.Accepted = false
	writeRenewalFixture(t, filepath.Join(cfg.EvidenceDirectory, "manifest.json"), manifest)
	if _, err := loadRenewalChoices(os.Getenv); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatal(err)
	}
}

func TestRenewalCoveredComposition(t *testing.T) {
	for path, expected := range renewalCoveredSource {
		data, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != expected {
			t.Fatalf("review renewal evidence coverage for changed source %s", path)
		}
	}
}

type renewalStartupRecorder struct {
	calls []string
	err   error
}

func (r *renewalStartupRecorder) ConfigureRenewalChoices(context.Context, api.RenewalChoiceConfig) error {
	r.calls = append(r.calls, "configure")
	return r.err
}
func (r *renewalStartupRecorder) StartRenewalChoiceService(context.Context) {
	r.calls = append(r.calls, "start")
}

func TestRenewalStartupOnlyStartsAfterConfiguration(t *testing.T) {
	cfg, manifest := renewalLoaderFixture(t)
	installRenewalFixture(t, cfg, manifest)
	for _, failure := range []bool{true, false} {
		r := &renewalStartupRecorder{}
		if failure {
			r.err = errors.New("storage unavailable")
		}
		err := startRenewalChoices(t.Context(), r)
		if failure {
			if err == nil || strings.Join(r.calls, ",") != "configure" {
				t.Fatal(r.calls, err)
			}
		} else if err != nil || strings.Join(r.calls, ",") != "configure,start" {
			t.Fatal(r.calls, err)
		}
	}
}

func TestRenewalStartupFailureKeepsAPIAvailable(t *testing.T) {
	t.Setenv("BILLING_RENEWAL_CHOICES_ENABLED", "true")
	t.Setenv("BILLING_RENEWAL_CHOICES_CONFIG", "/nonexistent/renewal.json")
	h := &api.Handlers{}
	if err := startRenewalChoices(t.Context(), h); err == nil || h.RenewalChoices != nil {
		t.Fatal(err)
	}
	r := api.SetupRouter(t.Context(), h, nil)
	for _, path := range []string{"/internal/yc/account/renewals/status", "/internal/yc/account/renewals/submit"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if w.Code != http.StatusForbidden && w.Code != http.StatusServiceUnavailable {
			t.Fatalf("unavailable route %s: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatal("renewal failure stopped API")
	}
}

type blockedRenewalStartup struct {
	entered    chan struct{}
	release    chan struct{}
	configured bool
	started    bool
	err        error
}

func (b *blockedRenewalStartup) ConfigureRenewalChoices(context.Context, api.RenewalChoiceConfig) error {
	close(b.entered)
	<-b.release
	b.configured = b.err == nil
	return b.err
}
func (b *blockedRenewalStartup) StartRenewalChoiceService(context.Context) { b.started = true }

func TestRenewalStartupPreflightDoesNotBlockOtherRoutes(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			cfg, m := renewalLoaderFixture(t)
			installRenewalFixture(t, cfg, m)
			b := &blockedRenewalStartup{entered: make(chan struct{}), release: make(chan struct{})}
			if fail {
				b.err = errors.New("provider unavailable")
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/internal/yc/account/renewals/") {
					// These plain reads deliberately rely on the production publication
					// barrier, so -race detects a handler exposed before initialization.
					if b.configured != !fail || b.started != !fail {
						t.Error("partial initialization exposed")
					}
					if fail {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
				}
				w.WriteHeader(http.StatusOK)
			})
			gate := newRenewalStartupHandler(t.Context(), b, next)
			<-b.entered
			for _, path := range []string{"/health", "/unrelated-api"} {
				w := httptest.NewRecorder()
				gate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				if w.Code != http.StatusOK {
					t.Fatal("unrelated route blocked", path, w.Code)
				}
			}
			for _, path := range []string{"/internal/yc/account/renewals/status", "/internal/yc/account/renewals/submit"} {
				w := httptest.NewRecorder()
				gate.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
				if w.Code != http.StatusServiceUnavailable || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("pending route exposed", w.Code)
				}
			}
			close(b.release)
			// Keep issuing requests while publication races with the reader. A gate
			// response has no-store; the downstream handler must eventually be reached.
			deadline := time.After(time.Second)
			for {
				w := httptest.NewRecorder()
				gate.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/internal/yc/account/renewals/status", nil))
				if w.Header().Get("Cache-Control") == "" {
					break
				}
				select {
				case <-deadline:
					t.Fatal("initialization never published")
				default:
					runtime.Gosched()
				}
			}
		})
	}
}
