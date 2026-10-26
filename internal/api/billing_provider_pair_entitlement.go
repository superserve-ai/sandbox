package api

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

// ProviderPairEntitlementAuthority is supplied by the financial-authority adapter.
// It reads current committed shared authority before opening the regional tx,
// validates the exact binding/phase/permission, then locks team/account -> the
// finalized permanent target fence. It calls action only while authority is valid
// and holds the fence through commit. No network I/O belongs in action.
type ProviderPairEntitlementAuthority interface {
	WithProviderPairAuthority(context.Context, ContractProviderBinding, func(context.Context, pgx.Tx) error) error
}

func (h *Handlers) withProviderPairEntitlementAuthority(ctx context.Context, binding ContractProviderBinding, action func(context.Context, pgx.Tx) error) error {
	if h.ProviderPairEntitlementAuthority == nil {
		return errors.New("paired entitlement financial authority adapter unavailable")
	}
	return h.ProviderPairEntitlementAuthority.WithProviderPairAuthority(ctx, binding, func(ctx context.Context, tx pgx.Tx) error {
		if tx == nil {
			return errors.New("paired entitlement requires regional authority transaction")
		}
		saved, err := loadContractProviderBinding(ctx, tx, binding.ContractID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(saved, binding) {
			return errors.New("paired entitlement binding changed")
		}
		var allowed bool
		if err = tx.QueryRow(ctx, `SELECT c.status='active' AND (c.ends_at IS NULL OR c.ends_at>clock_timestamp())
   AND NOT EXISTS(SELECT 1 FROM billing_provider_pair_revocation r WHERE r.contract_id=c.id)
   FROM billing_commercial_contract c WHERE c.id=$1 AND c.team_id=$2 FOR UPDATE`, binding.ContractID, binding.Identity.TeamID).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return errors.New("paired entitlement authority is inactive or revoked")
		}
		// The adapter has proved current shared authority and the permanent finalized
		// fence. Refresh only observation freshness; never extend the frozen term.
		if _, err = tx.Exec(ctx, `UPDATE billing_provider_pair_waiver SET authority_checked_at=clock_timestamp(),authority_valid_until=least(ends_at,clock_timestamp()+interval '30 seconds')
   WHERE contract_id=$1 AND team_id=$2 AND revoked_at IS NULL AND starts_at<=clock_timestamp() AND ends_at>clock_timestamp()`, binding.ContractID, binding.Identity.TeamID); err != nil {
			return err
		}
		return action(ctx, tx)
	})
}

func (h *Handlers) prepareProviderPairEntitlement(ctx context.Context, b ContractProviderBinding, params db.BeginImmediateUsageEntitlementIssuanceParams, prices []map[string]string) (db.BillingUsageEntitlement, error) {
	var e db.BillingUsageEntitlement
	err := h.withProviderPairEntitlementAuthority(ctx, b, func(ctx context.Context, tx pgx.Tx) error {
		q := h.DB.WithTx(tx)
		var err error
		e, err = q.ClaimCurrentUsageEntitlement(ctx, db.ClaimCurrentUsageEntitlementParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID})
		if errors.Is(err, pgx.ErrNoRows) {
			e, err = q.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: b.Identity.TeamID, Kind: "metered_usage"})
		}
		if err != nil {
			return err
		}
		if e.ContractID != b.ContractID {
			return errors.New("current allowance belongs to a different contract")
		}
		if e.State == "pending" {
			params.EntitlementID = e.ID
			e, err = q.BeginImmediateUsageEntitlementIssuance(ctx, params)
			if err != nil {
				return err
			}
			_, err = entitlementGrantForm(e.RequestPayload, prices)
			return err
		}
		if e.State == "uncertain" {
			e, err = q.GetReplayableUsageEntitlement(ctx, db.GetReplayableUsageEntitlementParams{TeamID: b.Identity.TeamID, EntitlementID: e.ID})
		}
		return err
	})
	return e, err
}

func (h *Handlers) observeProviderPairDebt(ctx context.Context, c db.BillingCommercialContract, debt string) error {
	var observed time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); err != nil {
		return err
	}
	evidence, _ := json.Marshal(map[string]string{"unpaid_invoice": debt})
	overdue := true
	_, err := h.DB.ObserveCommercialCollection(ctx, db.ObserveCommercialCollectionParams{TeamID: c.TeamID, ContractID: c.ID, ExpectedRevision: c.Revision, HasOverdueBalance: &overdue, CheckedAt: pgtype.Timestamptz{Time: observed, Valid: true}, ValidUntil: pgtype.Timestamptz{Time: observed.Add(30 * time.Second), Valid: true}, Evidence: evidence})
	return err
}

// Existing grants already proved their immutable scope and prior close at issuance.
// Refresh only current payment, debt, and financial authority; funding reconciliation
// remains responsible for the live grant inventory and remaining balance.
func (h *Handlers) refreshIssuedProviderPair(ctx context.Context, b ContractProviderBinding, c db.BillingCommercialContract, e db.BillingUsageEntitlement, client *stripeHTTPClient) error {
	if e.ContractID != b.ContractID || e.State != "issued" {
		return errors.New("issued paired allowance differs from contract")
	}
	token := uuid.New()
	if _, err := h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: b.CustomerID, Token: token}); err != nil {
		return err
	}
	defer func() {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: b.CustomerID, Token: token})
	}()
	if c.OfferKey != "yc_2026" && c.ChargeKind != "sponsored_entitlement" {
		var invoice string
		if err := h.Pool.QueryRow(ctx, `SELECT p.invoice_id FROM billing_contract_payment p JOIN billing_commercial_contract c ON c.id=p.contract_id WHERE p.contract_id=$1 AND billing_payment_authorizes_entitlement(c,p,$2,$3) ORDER BY p.service_period_start DESC,p.invoice_id LIMIT 1`, b.ContractID, e.PeriodStart, e.PeriodEnd).Scan(&invoice); err != nil {
			return err
		}
		payment, verifyErr := client.verifyProviderPairPayment(ctx, b, invoice)
		if verifyErr == nil {
			var same bool
			if err := h.Pool.QueryRow(ctx, `SELECT service_period_start=$3 AND service_period_end=$4 AND payment_reference=$5 FROM billing_contract_payment WHERE contract_id=$1 AND invoice_id=$2`, b.ContractID, invoice, time.Unix(payment.Start, 0), time.Unix(payment.End, 0), payment.Reference).Scan(&same); err != nil {
				return err
			}
			if !same {
				verifyErr = &proPaymentReviewError{reason: "paired payment changed its immutable receipt period or settlement identity"}
			}
		}
		if err := h.observeProPaymentReview(ctx, b.Identity.TeamID, invoice, payment, verifyErr); err != nil {
			return err
		}
		if verifyErr != nil {
			return verifyErr
		}
	}
	debt, err := client.entitlementDebt(ctx, b.CustomerID)
	if err != nil {
		return err
	}
	if debt != "" {
		// Contradictory debt must withdraw clean evidence even if positive
		// financial authority is temporarily unavailable.
		return h.observeProviderPairDebt(ctx, c, debt)
	}
	return h.withProviderPairEntitlementAuthority(ctx, b, func(ctx context.Context, tx pgx.Tx) error {
		q := h.DB.WithTx(tx)
		current, err := q.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: b.Identity.TeamID, Kind: c.EntitlementKind})
		if err != nil {
			return err
		}
		if current.ID != e.ID || current.ContractID != b.ContractID || current.State != "issued" {
			return errors.New("current paired allowance changed during refresh")
		}
		if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: b.CustomerID, Token: token}); err != nil {
			return err
		}
		contract, err := q.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID})
		if err != nil {
			return err
		}
		var observed time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); err != nil {
			return err
		}
		evidence, _ := json.Marshal(map[string]any{"gate": "finalized_invoice_gate_v1", "period_start": e.PeriodStart, "period_end": e.PeriodEnd, "closing_invoice_verified": true, "unpaid_invoice": debt})
		overdue := debt != ""
		_, err = q.ObserveCommercialCollection(ctx, db.ObserveCommercialCollectionParams{TeamID: b.Identity.TeamID, ContractID: b.ContractID, ExpectedRevision: contract.Revision, HasOverdueBalance: &overdue, CheckedAt: pgtype.Timestamptz{Time: observed, Valid: true}, ValidUntil: pgtype.Timestamptz{Time: observed.Add(30 * time.Second), Valid: true}, Evidence: evidence})
		return err
	})
}
