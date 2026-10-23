package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/api"
)

const renewalReviewedSource = "2a95f28a0dccb4a3f55b2316b91384dd4f144ac3"

// These hashes bind the accepted request/recovery contract to the composed code.
// A behavior change requires reviewing its evidence coverage before updating them.
var renewalCoveredSource = map[string]string{
	"internal/api/billing_renewal_choice_steps.go":             "0fdca29541ca5ce5028379a2955df637070279803079dfdb917732551f2cb668",
	"internal/api/billing_renewal_choice_provider.go":          "bcc0e2daafcb9b4ca541de279484d14c9c166d1e6feb1257867f12e62de43ac3",
	"internal/api/billing_renewal_choice_schedule_verifier.go": "f328fcbe959d7f4d3928625cfdfbf32414b5b2ab93d951c07079edbde9662332",
	"internal/api/billing_renewal_choice_schedule_receipt.go":  "c10037a6fd4a220256a361373d1b1832d33cefdd7b4f97a828b7586cb00c7173",
	"internal/api/billing_renewal_choice_boundary.go":          "6012922d748fa663f36045fa7d3d2c0f4c614d0dcda2bf6b8f54dfafea9d2590",
	"internal/api/billing_renewal_choice_successor.go":         "5a21ad06b34aa2068430189c12039dceeadcd6004aaa8d049a7b71f34f0b8914",
}

type renewalEvidenceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type renewalProviderScope struct {
	Merchant   string `json:"merchant"`
	Live       *bool  `json:"live"`
	APIVersion string `json:"api_version"`
}

func (s renewalProviderScope) matches(other renewalProviderScope) bool {
	return s.Live != nil && other.Live != nil && *s.Live == *other.Live && s.Merchant != "" && s.Merchant == other.Merchant && s.APIVersion != "" && s.APIVersion == other.APIVersion
}

type renewalStartupConfig struct {
	Scope             renewalProviderScope  `json:"scope"`
	Monthly           api.ProviderPairTerms `json:"monthly"`
	MonthlyVersion    int                   `json:"monthly_version"`
	EvidenceManifest  renewalEvidenceFile   `json:"evidence_manifest"`
	EvidenceDirectory string                `json:"evidence_directory"`
}

type renewalEvidenceManifest struct {
	Contract       string                `json:"contract"`
	ReviewedSource string                `json:"reviewed_source"`
	Scope          renewalProviderScope  `json:"scope"`
	Receipt        renewalEvidenceFile   `json:"receipt"`
	SourceCoverage []renewalEvidenceFile `json:"source_coverage"`
	Acceptance     struct {
		Accepted       bool                 `json:"accepted"`
		Contract       string               `json:"contract"`
		ReviewedSource string               `json:"reviewed_source"`
		Scope          renewalProviderScope `json:"scope"`
		Disposition    renewalEvidenceFile  `json:"disposition"`
	} `json:"bounded_contract_acceptance"`
}

// Only trusted deployment configuration supplies these paths and the manifest
// digest. HTTP requests cannot provide evidence or change this startup decision.
func loadRenewalChoices(getenv func(string) string) (api.RenewalChoiceConfig, error) {
	var disabled api.RenewalChoiceConfig
	switch getenv("BILLING_RENEWAL_CHOICES_ENABLED") {
	case "", "false":
		return disabled, nil
	case "true":
	default:
		return disabled, errors.New("invalid renewal enable flag")
	}
	var cfg renewalStartupConfig
	if err := readRenewalJSON(getenv("BILLING_RENEWAL_CHOICES_CONFIG"), "", &cfg); err != nil {
		return disabled, fmt.Errorf("renewal configuration: %w", err)
	}
	var manifest renewalEvidenceManifest
	if !renewalDigestValid(cfg.EvidenceManifest.SHA256) || !filepath.IsAbs(cfg.EvidenceDirectory) {
		return disabled, errors.New("renewal evidence configuration incomplete")
	}
	if err := readRenewalJSON(cfg.EvidenceManifest.Path, cfg.EvidenceManifest.SHA256, &manifest); err != nil {
		return disabled, fmt.Errorf("renewal evidence manifest: %w", err)
	}
	a := manifest.Acceptance
	if !a.Accepted || manifest.Contract != api.RenewalBoundaryContractVersion || a.Contract != manifest.Contract || manifest.ReviewedSource != renewalReviewedSource || a.ReviewedSource != manifest.ReviewedSource || !cfg.Scope.matches(manifest.Scope) || !cfg.Scope.matches(a.Scope) {
		return disabled, errors.New("renewal evidence acceptance or scope mismatch")
	}
	if len(manifest.SourceCoverage) != len(renewalCoveredSource) {
		return disabled, errors.New("renewal source coverage incomplete")
	}
	seen := make(map[string]bool, len(renewalCoveredSource))
	for _, covered := range manifest.SourceCoverage {
		if seen[covered.Path] || renewalCoveredSource[covered.Path] != covered.SHA256 || !renewalDigestValid(covered.SHA256) {
			return disabled, errors.New("renewal source coverage mismatch")
		}
		seen[covered.Path] = true
	}
	// The original artifact identities remain in the manifest/disposition. The
	// deployment mounts their unchanged bytes together under one local directory.
	readEvidence := func(ref renewalEvidenceFile, value any) error {
		if ref.Path == "" || !renewalDigestValid(ref.SHA256) {
			return errors.New("renewal evidence reference incomplete")
		}
		return readRenewalJSON(filepath.Join(cfg.EvidenceDirectory, filepath.Base(ref.Path)), ref.SHA256, value)
	}
	var receipt struct {
		Source string `json:"source"`
	}
	if err := readEvidence(manifest.Receipt, &receipt); err != nil {
		return disabled, fmt.Errorf("renewal evidence receipt: %w", err)
	}
	var disposition struct {
		ProviderEvidenceStatus string `json:"provider_evidence_status"`
		Evidence               string `json:"evidence"`
	}
	if err := readEvidence(a.Disposition, &disposition); err != nil {
		return disabled, fmt.Errorf("renewal evidence disposition: %w", err)
	}
	if receipt.Source != manifest.ReviewedSource || disposition.ProviderEvidenceStatus != "PASS/closed for exact renewal source"+manifest.ReviewedSource || disposition.Evidence != manifest.Receipt.Path {
		return disabled, errors.New("renewal receipt is not the accepted reviewed source")
	}
	if cfg.MonthlyVersion < 1 || cfg.Monthly.FeeMonths != 1 {
		return disabled, errors.New("renewal Monthly catalog configuration incomplete")
	}
	if _, err := cfg.Monthly.Digest(); err != nil {
		return disabled, errors.New("renewal Monthly mapping invalid")
	}
	return api.RenewalChoiceConfig{
		Enabled: true, Merchant: cfg.Scope.Merchant, Live: *cfg.Scope.Live, APIVersion: cfg.Scope.APIVersion,
		Monthly: cfg.Monthly, MonthlyVersion: cfg.MonthlyVersion,
		Boundary: api.RenewalBoundaryEvidence{
			Accepted: true, Contract: manifest.Contract, ReviewedSource: manifest.ReviewedSource,
			ReceiptDigest: manifest.Receipt.SHA256, Merchant: cfg.Scope.Merchant, Live: *cfg.Scope.Live, APIVersion: cfg.Scope.APIVersion,
		},
	}, nil
}

func renewalDigestValid(digest string) bool {
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size && digest == strings.ToLower(digest)
}

func readRenewalJSON(path, digest string, value any) error {
	const limit = 1 << 20
	if !filepath.IsAbs(path) {
		return errors.New("absolute evidence/configuration path required")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return errors.New("evidence/configuration file unavailable or too large")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("evidence/configuration file unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) > limit {
		return errors.New("evidence/configuration file unreadable or too large")
	}
	hash := sha256.Sum256(data)
	if digest != "" && hex.EncodeToString(hash[:]) != digest {
		return errors.New("evidence digest mismatch")
	}
	if err := json.Unmarshal(data, value); err != nil {
		return errors.New("invalid evidence/configuration JSON")
	}
	return nil
}

type renewalStartup interface {
	ConfigureRenewalChoices(context.Context, api.RenewalChoiceConfig) error
	StartRenewalChoiceService(context.Context)
}

func startRenewalChoices(ctx context.Context, h renewalStartup) error {
	cfg, err := loadRenewalChoices(os.Getenv)
	if err != nil || !cfg.Enabled {
		return err
	}
	if err := h.ConfigureRenewalChoices(ctx, cfg); err != nil {
		return err
	}
	h.StartRenewalChoiceService(ctx)
	return nil
}

// Renewal initialization may wait on provider/storage checks. Only renewal
// routes wait for publication; unrelated requests never read RenewalChoices.
// Receiving from ready establishes publication before any renewal handler read.
func newRenewalStartupHandler(ctx context.Context, h renewalStartup, next http.Handler) http.Handler {
	ready := make(chan struct{})
	go func() {
		defer close(ready)
		if err := startRenewalChoices(ctx, h); err != nil {
			log.Error().Err(err).Msg("renewal choices unavailable; other services remain active")
		}
	}()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/internal/yc/account/renewals/") {
			select {
			case <-ready:
			default:
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":{"code":"renewal_unavailable","message":"Renewal choices are unavailable."}}`)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
