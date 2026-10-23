package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ycAcceptedDecimal = regexp.MustCompile(`^[0-9]+([.][0-9]{1,12})?$`)

var errYCAcceptanceUnavailable = errors.New("acceptance adapter unavailable")
var errYCAcceptanceConflict = errors.New("accepted offer or authority requires review")

type YCAcceptanceAuthority struct {
	ClaimID          uuid.UUID `json:"claim_id"`
	ClaimCreatedAt   time.Time `json:"claim_created_at"`
	UserID           uuid.UUID `json:"user_id"`
	TeamID           uuid.UUID `json:"team_id"`
	HomeRegion       string    `json:"home_region"`
	Company          string    `json:"company_identity"`
	ApprovalID       uuid.UUID `json:"approval_id"`
	ApprovalRevision int64     `json:"approval_revision"`
	OfferKey         string    `json:"offer_key"`
	OfferVersion     int       `json:"offer_version"`
}

func (a YCAcceptanceAuthority) equal(b YCAcceptanceAuthority) bool {
	if !a.ClaimCreatedAt.Equal(b.ClaimCreatedAt) {
		return false
	}
	a.ClaimCreatedAt, b.ClaimCreatedAt = time.Time{}, time.Time{}
	return a == b
}

type YCAcceptanceRate struct {
	ID       uuid.UUID `json:"id"`
	Resource string    `json:"resource"`
	Unit     string    `json:"unit"`
	PriceUSD string    `json:"price_usd"`
	Currency string    `json:"currency"`
}

type YCAcceptanceTerms struct {
	OfferKey               string             `json:"offer_key"`
	OfferVersion           int                `json:"offer_version"`
	Currency               string             `json:"currency"`
	TermMonths             int                `json:"term_months"`
	ChargeAmountCents      int64              `json:"charge_amount_cents"`
	ChargeIntervalMonths   int                `json:"charge_interval_months"`
	InitialFeeWaived       bool               `json:"initial_fee_waived"`
	MonthlyAllowanceCents  []int64            `json:"monthly_allowance_cents"`
	Rollover               bool               `json:"rollover"`
	Proration              bool               `json:"proration"`
	PaymentRequirement     string             `json:"payment_requirement"`
	RateCardKey            string             `json:"rate_card_key"`
	ResourceRates          []YCAcceptanceRate `json:"resource_rates"`
	DefaultSuccessorFamily string             `json:"default_successor_family"`
}

type YCAcceptanceDisclosure struct {
	Terms        YCAcceptanceTerms `json:"terms"`
	RenewalTerms YCAcceptanceTerms `json:"renewal_terms"`
	PricingAt    time.Time         `json:"pricing_at"`
}

// Catalog must resolve an explicit approved version and preserve the disclosed
// resource prices when assigning. It may never substitute the current version.
type YCAcceptanceCatalog interface {
	Resolve(context.Context, YCAcceptanceAuthority) (YCAcceptanceDisclosure, error)
	Assign(context.Context, YCAcceptanceRecord) (uuid.UUID, error)
}

type YCAcceptanceProvisioning interface {
	Enqueue(context.Context, uuid.UUID, uuid.UUID) (uuid.UUID, error)
	Status(context.Context, uuid.UUID, uuid.UUID) (YCAcceptanceProvisioningStatus, error)
}
type YCAcceptanceProvisioningStatus struct {
	OperationID    uuid.UUID `json:"operation_id"`
	State          string    `json:"state"`
	Ready          bool      `json:"ready"`
	Held           bool      `json:"held"`
	Revoked        bool      `json:"revoked"`
	ControlPending bool      `json:"control_pending"`
}

type YCAcceptanceRecord struct {
	FinancialAuthority *YCFinancialState `json:"financial_authority"`
	YCAcceptanceAuthority
	ID                 uuid.UUID         `json:"acceptance_id"`
	RequestID          *uuid.UUID        `json:"request_id"`
	Terms              YCAcceptanceTerms `json:"terms"`
	RenewalTerms       YCAcceptanceTerms `json:"renewal_terms"`
	TermsDigest        string            `json:"terms_digest"`
	RenewalTermsDigest string            `json:"renewal_terms_digest"`
	PricingAt          time.Time         `json:"pricing_at"`
	AcceptedAt         *time.Time        `json:"accepted_at"`
	AssignmentID       *uuid.UUID        `json:"assignment_id"`
	OperationID        *uuid.UUID        `json:"operation_id"`
	State              string            `json:"state"`
	Ready              bool              `json:"ready"`
	Held               bool              `json:"held"`
	Revoked            bool              `json:"revoked"`
	ControlPending     bool              `json:"control_pending"`
}

// Absent real adapters keep admission closed. Tests may inject local adapters;
// that does not constitute integrated provider or rollout evidence.
type YCOfferAcceptanceService struct {
	Pool, Shared *pgxpool.Pool
	Region       string
	Catalog      YCAcceptanceCatalog
	Provisioning YCAcceptanceProvisioning
	Authorize    func(context.Context, uuid.UUID, uuid.UUID) error
}

func ycAcceptanceDigest(v any) string {
	b, _ := json.Marshal(v)
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}

func (d YCAcceptanceDisclosure) validate(a YCAcceptanceAuthority) error {
	if d.Terms.OfferKey != a.OfferKey || d.Terms.OfferVersion != a.OfferVersion || d.PricingAt.IsZero() {
		return errYCAcceptanceConflict
	}
	for _, t := range []YCAcceptanceTerms{d.Terms, d.RenewalTerms} {
		if t.OfferKey == "" || t.OfferVersion < 1 || t.Currency != "usd" || t.TermMonths < 1 || t.TermMonths > 24 || len(t.MonthlyAllowanceCents) != t.TermMonths || t.ChargeAmountCents < 0 || (t.ChargeIntervalMonths != 1 && t.ChargeIntervalMonths != 12) || t.RateCardKey == "" || len(t.ResourceRates) != 3 || t.Rollover || t.Proration || (t.PaymentRequirement != "eligible_credit_or_verified_payment" && t.PaymentRequirement != "verified_payment") || (t.DefaultSuccessorFamily != "pro_annual" && t.DefaultSuccessorFamily != "pro_monthly") {
			return errYCAcceptanceConflict
		}
		for _, amount := range t.MonthlyAllowanceCents {
			if amount <= 0 {
				return errYCAcceptanceConflict
			}
		}
		seen := map[uuid.UUID]bool{}
		resources := map[string]bool{}
		for _, rate := range t.ResourceRates {
			if rate.ID == uuid.Nil || seen[rate.ID] || (rate.Resource != "vcpu" && rate.Resource != "memory_gib" && rate.Resource != "storage_gib") || resources[rate.Resource] || rate.Unit != "second" || len(rate.PriceUSD) > 32 || !ycAcceptedDecimal.MatchString(rate.PriceUSD) || rate.Currency != "USD" {
				return errYCAcceptanceConflict
			}
			seen[rate.ID] = true
			resources[rate.Resource] = true
		}
	}
	return nil
}
