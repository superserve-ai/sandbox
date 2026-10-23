package api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const RenewalBoundaryContractVersion = "schedule-original-boundary-v1"
const renewalBoundaryReviewedSource = "2a95f28a0dccb4a3f55b2316b91384dd4f144ac3"

var renewalChoiceConfigurationMu sync.Mutex

// RenewalBoundaryEvidence is an assertion from trusted startup composition.
// Its loader must verify the receipt bytes against ReceiptDigest and confirm
// review acceptance, scope and source coverage before setting Accepted. This
// constructor checks that assertion's scope; it does not verify artifact bytes.
// Customer input and successful provider GETs cannot supply this authority.
type RenewalBoundaryEvidence struct {
	Accepted       bool
	Contract       string
	ReviewedSource string
	ReceiptDigest  string
	Merchant       string
	Live           bool
	APIVersion     string
}

type RenewalChoiceConfig struct {
	Enabled        bool
	Merchant       string
	Live           bool
	APIVersion     string
	Monthly        ProviderPairTerms
	MonthlyVersion int
	Boundary       RenewalBoundaryEvidence
}

type renewalFinancialGuards interface {
	FinalizeAcceptedOfferFinancial(context.Context, YCAcceptanceRecord, string, uuid.UUID, string, time.Time, func(context.Context, pgx.Tx, YCFinancialAuthorization) error) error
	WithAcceptedOfferRemoval(context.Context, YCAcceptanceRecord, uuid.UUID, uuid.UUID, func(context.Context, pgx.Tx) error) error
}

// ConfigureRenewalChoices must run before serving requests or starting workers.
// It performs bounded read-only validation and publishes the service only on
// success. Reconfiguration of a registered service is deliberately unsupported.
func (h *Handlers) ConfigureRenewalChoices(ctx context.Context, cfg RenewalChoiceConfig) error {
	renewalChoiceConfigurationMu.Lock()
	defer renewalChoiceConfigurationMu.Unlock()
	if h == nil || h.RenewalChoices != nil {
		return errRenewalConflict
	}
	if !cfg.Enabled {
		return nil
	}
	if h.Pool == nil || !h.YCOfferAcceptance.available() || h.YCOfferAcceptance.Pool != h.Pool || h.YCOfferAcceptance.Shared != h.PromotionAuthPool || h.ProviderPairEntitlementAuthority == nil {
		return errRenewalDisabled
	}
	guards, ok := any(h).(renewalFinancialGuards)
	if !ok {
		return errRenewalDisabled
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok || client == nil || client.httpClient == nil || strings.TrimSpace(client.secretKey) == "" || cfg.APIVersion != renewalStripeVersion || client.apiVersion != cfg.APIVersion || !strings.HasPrefix(cfg.Merchant, "acct_") || cfg.MonthlyVersion < 1 {
		return errRenewalDisabled
	}
	evidence := cfg.Boundary
	if !evidence.Accepted || evidence.Contract != RenewalBoundaryContractVersion || evidence.ReviewedSource != renewalBoundaryReviewedSource || !validPairDigest(evidence.ReceiptDigest) || evidence.Merchant != cfg.Merchant || evidence.Live != cfg.Live || evidence.APIVersion != cfg.APIVersion {
		return errRenewalDisabled
	}
	// Copy the slice before validation so later caller configuration changes
	// cannot replace the mapping used by admission and successor activation.
	monthly := cfg.Monthly
	monthly.Resources = append([]StripeCheckoutResourceTerms(nil), monthly.Resources...)
	digest, err := monthly.Digest()
	if err != nil {
		return errRenewalDisabled
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err = loadRenewalChoiceTerms(checkCtx, h.Pool, "monthly", cfg.MonthlyVersion, monthly); err != nil {
		return fmt.Errorf("renewal catalog unavailable: %w", err)
	}
	// These reads also reject a target that has not prepared renewal storage and
	// the common financial fence. They create no journal or authorization rows.
	if _, err = h.Pool.Exec(checkCtx, `SELECT 1 FROM billing_renewal_choice LIMIT 0; SELECT 1 FROM billing_offer_financial_fence LIMIT 0`); err != nil {
		return fmt.Errorf("renewal storage unavailable: %w", err)
	}
	identity := ProviderPairIdentity{Merchant: cfg.Merchant, Live: cfg.Live, APIVersion: cfg.APIVersion, ProviderTermsDigest: digest}
	if err = h.VerifyProviderPairTerms(checkCtx, identity, monthly); err != nil {
		return fmt.Errorf("renewal provider configuration unavailable: %w", err)
	}
	if err = checkCtx.Err(); err != nil {
		return err
	}
	verifier := &stripeRenewalScheduleVerifier{Pool: h.Pool, Client: client}
	live := cfg.Live
	authority := &acceptedRenewalAuthority{
		Admission: &YCAcceptedProvisioningAdmission{Service: h.YCOfferAcceptance, Handlers: h},
		Verifier:  verifier, Monthly: &monthly, MonthlyVersion: cfg.MonthlyVersion,
		Merchant: cfg.Merchant, Live: &live,
	}
	h.RenewalChoices = &renewalChoiceService{
		Enabled: true, Store: postgresRenewalChoiceStore{Pool: h.Pool}, Authority: authority,
		Provider:   &renewalScheduleProvider{Client: client, Merchant: cfg.Merchant, Verifier: verifier, BoundaryWritesVerified: true},
		Successors: &acceptedRenewalSuccessors{Authority: authority, Handlers: h, Client: client, Finalize: guards.FinalizeAcceptedOfferFinancial, Remove: guards.WithAcceptedOfferRemoval},
	}
	return nil
}
