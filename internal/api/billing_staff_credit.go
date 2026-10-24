package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

var (
	errStaffCreditConflict   = errors.New("staff credit conflicts with an earlier request")
	errStaffCreditNoCustomer = errors.New("team has no billing customer")
	errStaffCreditReview     = errors.New("the Stripe credit grant for this request does not match it; operator review required")
)

type staffCreditConflictError struct{ reason string }

func (e staffCreditConflictError) Error() string { return e.reason }
func (e staffCreditConflictError) Unwrap() error { return errStaffCreditConflict }

func staffCreditConflict(reason string) error { return staffCreditConflictError{reason} }

type staffCreditRequest struct {
	Key         string `json:"idempotency_key"`
	AmountCents int64  `json:"amount_cents"`
	Reason      string `json:"reason"`
}

type staffCredit struct {
	ID          uuid.UUID  `json:"id"`
	Key         string     `json:"idempotency_key"`
	AmountCents int64      `json:"amount_cents"`
	Reason      string     `json:"reason"`
	RequestedBy uuid.UUID  `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	State       string     `json:"state"`
	GrantID     *string    `json:"stripe_credit_grant_id"`
	IssuedAt    *time.Time `json:"issued_at"`
	LastError   *string    `json:"last_error"`
	customer    string
}

const staffCreditColumns = `id,idempotency_key,amount_cents,reason,requested_by,requested_at,state,stripe_credit_grant_id,issued_at,last_error,customer_id`

func scanStaffCredit(row pgx.Row) (staffCredit, error) {
	var s staffCredit
	err := row.Scan(&s.ID, &s.Key, &s.AmountCents, &s.Reason, &s.RequestedBy, &s.RequestedAt, &s.State, &s.GrantID, &s.IssuedAt, &s.LastError, &s.customer)
	return s, err
}

// CreateStaffCreditGrant grants a team one-off usage credit. The credit applies
// to metered usage only, never to plan fees, and works on any plan.
func (h *Handlers) CreateStaffCreditGrant(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	req, err := decodeStaffCreditRequest(http.MaxBytesReader(c.Writer, c.Request.Body, 8192))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	credit, err := h.grantStaffCredit(c.Request.Context(), team, actor, req)
	switch {
	case errors.Is(err, errStaffCreditConflict), errors.Is(err, errStaffCreditNoCustomer), errors.Is(err, errStaffCreditReview):
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	case err != nil && credit.ID != uuid.Nil:
		log.Error().Err(err).Str("team_id", team.String()).Str("staff_credit_id", credit.ID.String()).Msg("staff credit grant pending")
		respondErrorMsg(c, "unavailable", "the credit was recorded but Stripe did not confirm it; retry with the same idempotency key", http.StatusServiceUnavailable)
		return
	case err != nil:
		log.Error().Err(err).Str("team_id", team.String()).Msg("staff credit grant failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, credit)
}

// usageLedgerPeriodClosing includes the enrolled commercial calendar because
// delayed measurement can create a period after a grant would become effective.
func (h *Handlers) usageLedgerPeriodClosing(ctx context.Context, team uuid.UUID, reader db.DBTX) (bool, error) {
	var enrolledAt, through time.Time
	var anchor *time.Time
	err := reader.QueryRow(ctx, `SELECT i.enrolled_at,a.commercial_billing_anchor,clock_timestamp()+interval '5 minutes'
 FROM billing_invoice_account i JOIN team_billing_account a USING(team_id) WHERE i.team_id=$1`, team).Scan(&enrolledAt, &anchor, &through)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if anchor == nil {
		return true, nil
	}
	at := enrolledAt
	if at.Before(*anchor) {
		at = *anchor
	}
	var starts, ends []time.Time
	for at.Before(through) {
		start, end, ok := billing.AnniversaryPeriod(*anchor, at)
		if !ok {
			return true, nil
		}
		if end.After(through) {
			break
		}
		starts = append(starts, start)
		ends = append(ends, end)
		at = end
	}
	rows, err := reader.Query(ctx, `WITH candidates AS (
 SELECT period_start,period_end FROM team_billing_period WHERE team_id=$1 AND period_end>$2 AND period_end<=$3
 UNION SELECT * FROM unnest($4::timestamptz[],$5::timestamptz[])
 ) SELECT p.period_start,p.period_end FROM candidates p
 WHERE NOT EXISTS(SELECT 1 FROM billing_invoice_close c WHERE c.team_id=$1 AND c.period_start=p.period_start AND c.period_end=p.period_end AND c.state='released')`, team, enrolledAt, through, starts, ends)
	if err != nil {
		return false, err
	}
	periods, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (billing.ExportPeriod, error) {
		p := billing.ExportPeriod{TeamID: team}
		return p, row.Scan(&p.Start, &p.End)
	})
	if err != nil {
		return false, err
	}
	for _, p := range periods {
		a, _, err := h.invoiceAccountForPeriod(ctx, p, reader)
		if err != nil {
			return true, nil
		}
		path, err := h.invoiceCreditPath(ctx, p, a, reader)
		if err != nil || path == invoiceCreditsLedger {
			return true, err
		}
	}
	return false, nil
}

func decodeStaffCreditRequest(body io.Reader) (staffCreditRequest, error) {
	var req staffCreditRequest
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return req, errors.New("invalid credit grant; staff credit takes idempotency_key, amount_cents and reason and never expires")
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if strings.TrimSpace(req.Key) == "" || len(req.Key) > 200 || req.AmountCents < 1 || req.AmountCents > 100000000 || req.Reason == "" || len(req.Reason) > 2000 {
		return req, errors.New("idempotency_key, amount_cents (1 to 100000000) and reason are required")
	}
	return req, nil
}

func (h *Handlers) ListStaffCreditGrants(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	if _, ok = h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	rows, err := h.Pool.Query(c.Request.Context(), `SELECT `+staffCreditColumns+` FROM billing_staff_credit_grant WHERE team_id=$1 ORDER BY requested_at DESC LIMIT 50`, team)
	if err == nil {
		var credits []staffCredit
		credits, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (staffCredit, error) { return scanStaffCredit(row) })
		if err == nil {
			if credits == nil {
				credits = []staffCredit{}
			}
			c.JSON(http.StatusOK, gin.H{"credits": credits})
			return
		}
	}
	log.Error().Err(err).Str("team_id", team.String()).Msg("list staff credit grants failed")
	respondError(c, ErrInternal)
}

// grantStaffCredit records the intent durably, then issues or adopts the one
// Stripe grant that carries the row's id. Repeating a request is safe.
func (h *Handlers) grantStaffCredit(ctx context.Context, team, actor uuid.UUID, req staffCreditRequest) (staffCredit, error) {
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return staffCredit{}, errors.New("staff credit requires the Stripe provider")
	}
	var customer *string
	err := h.Pool.QueryRow(ctx, `SELECT stripe_customer_id FROM team_billing_account WHERE team_id=$1`, team).Scan(&customer)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && customer == nil {
		return staffCredit{}, errStaffCreditNoCustomer
	}
	if err != nil {
		return staffCredit{}, err
	}
	if _, err = h.Pool.Exec(ctx, `INSERT INTO billing_staff_credit_grant(team_id,idempotency_key,customer_id,amount_cents,reason,requested_by)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(team_id,idempotency_key) DO NOTHING`, team, req.Key, *customer, req.AmountCents, req.Reason, actor); err != nil {
		return staffCredit{}, err
	}
	credit, err := scanStaffCredit(h.Pool.QueryRow(ctx, `SELECT `+staffCreditColumns+` FROM billing_staff_credit_grant WHERE team_id=$1 AND idempotency_key=$2`, team, req.Key))
	if err != nil {
		return staffCredit{}, err
	}
	if credit.AmountCents != req.AmountCents || credit.Reason != req.Reason {
		return staffCredit{}, staffCreditConflict("idempotency key was used for a different credit")
	}
	if credit.State == "issued" {
		return credit, nil
	}
	// Only a new grant needs these checks; one already created for this request
	// is adopted even if the team's customer has changed.
	grant, err := client.issueStaffCredit(ctx, credit, func() error { return h.beginStaffCreditAttempt(ctx, team, credit) })
	if err != nil {
		_, _ = h.Pool.Exec(context.WithoutCancel(ctx), `UPDATE billing_staff_credit_grant SET last_error=$2 WHERE id=$1 AND state='pending'`, credit.ID, err.Error())
		return credit, err
	}
	evidence, err := json.Marshal(grant)
	if err != nil {
		return credit, err
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_staff_credit_grant SET state='issued',stripe_credit_grant_id=$2,issued_at=clock_timestamp(),issuance_evidence=$3,last_error=NULL WHERE id=$1 AND state='pending'`, credit.ID, grant.ID, evidence); err != nil {
		return credit, err
	}
	return scanStaffCredit(h.Pool.QueryRow(ctx, `SELECT `+staffCreditColumns+` FROM billing_staff_credit_grant WHERE id=$1`, credit.ID))
}

// beginStaffCreditAttempt confirms under the account lock that the team still
// bills the credit's customer and no period is ending or closing, then stamps
// the attempt; the customer binding trigger then refuses to replace that
// customer until the provider call has had time to finish.
func (h *Handlers) beginStaffCreditAttempt(ctx context.Context, team uuid.UUID, credit staffCredit) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var customer *string
	err = tx.QueryRow(ctx, `SELECT stripe_customer_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, team).Scan(&customer)
	if errors.Is(err, pgx.ErrNoRows) {
		return errStaffCreditNoCustomer
	}
	if err != nil {
		return err
	}
	if customer == nil || *customer != credit.customer {
		return staffCreditConflict("team's billing customer changed since the credit was requested")
	}
	closing, err := h.usageLedgerPeriodClosing(ctx, team, tx)
	if err != nil {
		return err
	}
	if closing {
		return staffCreditConflict("required invoice periods are not fully measured and released; complete invoice reconciliation before retrying")
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_staff_credit_grant SET attempts=attempts+1,attempted_at=clock_timestamp() WHERE id=$1 AND state='pending'`, credit.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// issueStaffCredit adopts the grant already carrying this credit's id, or
// creates it. Searching first keeps a retry after Stripe's idempotency window
// from granting twice.
func (c *stripeHTTPClient) issueStaffCredit(ctx context.Context, credit staffCredit, beforeCreate func() error) (entitlementGrant, error) {
	grant, found, err := c.findStaffCreditGrant(ctx, credit)
	if err != nil || found {
		return grant, err
	}
	if err = beforeCreate(); err != nil {
		return grant, err
	}
	form := url.Values{
		"customer":                   {credit.customer},
		"name":                       {"Superserve credit"},
		"category":                   {"promotional"},
		"amount[type]":               {"monetary"},
		"amount[monetary][currency]": {"usd"},
		"amount[monetary][value]":    {strconv.FormatInt(credit.AmountCents, 10)},
		"applicability_config[scope][price_type]": {"metered"},
		"priority":                     {"50"},
		"metadata[staff_credit_grant]": {credit.ID.String()},
	}
	if err = c.doForm(ctx, http.MethodPost, "/v1/billing/credit_grants", form, &grant, "staff-credit:"+credit.ID.String()); err != nil {
		return grant, err
	}
	return grant, validStaffCreditGrant(grant, credit)
}

func (c *stripeHTTPClient) findStaffCreditGrant(ctx context.Context, credit staffCredit) (entitlementGrant, bool, error) {
	after := ""
	for page := 0; page < 20; page++ {
		var list struct {
			Data    []entitlementGrant `json:"data"`
			HasMore bool               `json:"has_more"`
		}
		q := url.Values{"customer": {credit.customer}, "limit": {"100"}}
		if after != "" {
			q.Set("starting_after", after)
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+q.Encode(), nil, &list, ""); err != nil {
			return entitlementGrant{}, false, err
		}
		for _, g := range list.Data {
			if g.Metadata["staff_credit_grant"] == credit.ID.String() {
				return g, true, validStaffCreditGrant(g, credit)
			}
		}
		if !list.HasMore || len(list.Data) == 0 {
			return entitlementGrant{}, false, nil
		}
		after = list.Data[len(list.Data)-1].ID
	}
	return entitlementGrant{}, false, errors.New("credit grant inventory exceeds the search bound; operator review required")
}

func validStaffCreditGrant(g entitlementGrant, credit staffCredit) error {
	if g.ID == "" || g.Customer != credit.customer || g.Category != "promotional" || g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value != credit.AmountCents ||
		g.VoidedAt != 0 || g.Priority != 50 || g.ExpiresAt != 0 || g.Applicability.Scope.PriceType != "metered" || len(g.Applicability.Scope.Prices) != 0 ||
		g.Metadata["staff_credit_grant"] != credit.ID.String() {
		return fmt.Errorf("%w: grant %s", errStaffCreditReview, g.ID)
	}
	return nil
}

// issuedStaffCredits lists the Stripe grants issued as staff credit for a
// customer; code that treats unknown live grants as conflicts recognizes them.
func (h *Handlers) issuedStaffCredits(ctx context.Context, reader db.DBTX, customer string) (map[string]staffCredit, error) {
	rows, err := reader.Query(ctx, `SELECT `+staffCreditColumns+` FROM billing_staff_credit_grant WHERE customer_id=$1 AND state='issued'`, customer)
	if err != nil {
		return nil, err
	}
	credits, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (staffCredit, error) { return scanStaffCredit(row) })
	staff := make(map[string]staffCredit, len(credits))
	for _, credit := range credits {
		staff[*credit.GrantID] = credit
	}
	return staff, err
}

// isStaffCredit recognizes a grant only while it still carries the terms it
// was issued with.
func isStaffCredit(g entitlementGrant, staff map[string]staffCredit) bool {
	credit, ok := staff[g.ID]
	if !ok {
		return false
	}
	g.VoidedAt = 0
	return validStaffCreditGrant(g, credit) == nil
}
