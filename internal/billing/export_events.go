package billing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var exportDecimalPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]{1,12})?$`)

var ErrExportRecoveryRequired = errors.New("billing export requires reconciliation or operator recovery")

// ExportStore owns reservations, not measurement. Callers supply a normalized
// cumulative quantity from authoritative measurement, never a precomputed delta.
type ExportStore struct{ Pool *pgxpool.Pool }

type ExportPeriod struct {
	TeamID uuid.UUID
	Start  time.Time
	End    time.Time
}

type ExportPayload struct {
	Identifier     string `json:"identifier"`
	IdempotencyKey string `json:"idempotency_key"`
	EventName      string `json:"event_name"`
	CustomerID     string `json:"customer_id"`
	Quantity       string `json:"quantity"`
	Timestamp      int64  `json:"timestamp"`
}

type ExportEvent struct {
	ID           uuid.UUID `json:"id"`
	AllocationID uuid.UUID `json:"allocation_id"`
	ExportPayload
	Status     string    `json:"status"`
	LeaseToken uuid.UUID `json:"-"`
}

type ExportTotals struct {
	Reserved  string `json:"reserved"`
	Submitted string `json:"submitted"`
	Pending   string `json:"pending"`
	Rejected  string `json:"rejected"`
}

// MeterUsageQuantity normalizes cumulative persisted usage once, before exact
// reservation subtraction. Memory and storage usage are stored in MiB-seconds.
func MeterUsageQuantity(usage pgtype.Numeric, resource string) (string, error) {
	value, err := exactDecimalFromNumeric(usage)
	if err != nil {
		return "", err
	}
	if value.rat.Sign() < 0 {
		return "", fmt.Errorf("billing export quantity must be non-negative")
	}
	var divisor int64
	switch resource {
	case "vcpu":
		divisor = 3600
	case "memory_gib", "storage_gib":
		divisor = 1024 * 3600
	default:
		return "", fmt.Errorf("unknown billing resource %q", resource)
	}
	return value.DivInt64(divisor).rat.FloatString(12), nil
}

// DecimalDelta subtracts exact decimal reservations from the once-normalized
// cumulative quantity. Rounding each new increment would change the period bill.
func DecimalDelta(cumulative, reserved string) (string, error) {
	if !exportDecimalPattern.MatchString(cumulative) || !exportDecimalPattern.MatchString(reserved) {
		return "", fmt.Errorf("quantity must be a non-negative decimal with at most 12 places")
	}
	total, ok := new(big.Rat).SetString(cumulative)
	if !ok || total.Sign() < 0 {
		return "", fmt.Errorf("invalid cumulative quantity")
	}
	used, ok := new(big.Rat).SetString(reserved)
	if !ok || used.Sign() < 0 {
		return "", fmt.Errorf("invalid reserved quantity")
	}
	delta := new(big.Rat).Sub(total, used)
	if delta.Sign() < 0 {
		return "", ErrExportRecoveryRequired
	}
	// Both operands are normalized to at most 12 decimal places, including
	// adopted external quantities. Reject precision loss instead of rounding it.
	result := delta.FloatString(12)
	exact, _ := new(big.Rat).SetString(result)
	if exact.Cmp(delta) != 0 {
		return "", fmt.Errorf("quantity exceeds 12 decimal places")
	}
	return result, nil
}

// meterQuantityPrefix preserves the exact normalized delta while limiting each
// payload to 15 digits. At most an integer event and a fractional event are
// needed for ordinary billing quantities; no rounding is performed here.
func meterQuantityPrefix(delta string) (string, error) {
	if !exportDecimalPattern.MatchString(delta) {
		return "", fmt.Errorf("invalid meter quantity")
	}
	if len(strings.ReplaceAll(delta, ".", "")) <= 15 {
		return delta, nil
	}
	trimmed := strings.TrimRight(strings.TrimRight(delta, "0"), ".")
	if !strings.Contains(delta, ".") {
		trimmed = delta
	}
	if len(strings.ReplaceAll(trimmed, ".", "")) <= 15 {
		return trimmed, nil
	}
	whole := strings.SplitN(delta, ".", 2)[0]
	if len(whole) > 15 {
		return "", fmt.Errorf("meter quantity exceeds bounded exact split; operator recovery required")
	}
	return whole, nil
}

func lockExportPeriod(ctx context.Context, tx pgx.Tx, p ExportPeriod) error {
	immutable, err := lockExportRecoveryPeriod(ctx, tx, p)
	if err != nil {
		return err
	}
	if immutable {
		return ErrExportRecoveryRequired
	}
	return nil
}

// Recovery changes delivery of existing coverage, never the frozen period totals.
func lockExportRecoveryPeriod(ctx context.Context, tx pgx.Tx, p ExportPeriod) (bool, error) {
	var status string
	var immutable bool
	err := tx.QueryRow(ctx, `SELECT status, finalized_at IS NOT NULL OR exported_at IS NOT NULL
        FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3
        FOR UPDATE`, p.TeamID, p.Start, p.End).Scan(&status, &immutable)
	if err != nil {
		return false, err
	}
	if status == "blocked" {
		return false, ErrExportRecoveryRequired
	}
	return immutable, nil
}

// Enroll serializes with the old writer. Existing live attempts require an
// explicit handover; silently inventing their coverage could duplicate usage.
func (s ExportStore) Enroll(ctx context.Context, p ExportPeriod) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var status string
	var finalized, exported, enrolled bool
	if err = tx.QueryRow(ctx, `SELECT status, finalized_at IS NOT NULL, exported_at IS NOT NULL,
        EXISTS(SELECT 1 FROM billing_incremental_period i WHERE i.team_id=p.team_id
            AND i.period_start=p.period_start AND i.period_end=p.period_end)
        FROM team_billing_period p WHERE team_id=$1 AND period_start=$2 AND period_end=$3
        FOR UPDATE`, p.TeamID, p.Start, p.End).Scan(&status, &finalized, &exported, &enrolled); err != nil {
		return err
	}
	if enrolled {
		return tx.Commit(ctx)
	}
	if finalized || status == "blocked" {
		return ErrExportRecoveryRequired
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_usage_export
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3
          AND status NOT IN ('skipped_shadow','skipped_zero','skipped_disabled'))`, p.TeamID, p.Start, p.End).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrExportRecoveryRequired
	}
	if exported || status == "exported" {
		// Shadow completion records no provider coverage. Reopen only an
		// unfinalized shadow-only period, under the same lock as legacy writers.
		var shadowOnly bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_usage_export
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status='skipped_shadow')
            AND NOT EXISTS(SELECT 1 FROM billing_usage_export
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status<>'skipped_shadow')`,
			p.TeamID, p.Start, p.End).Scan(&shadowOnly); err != nil {
			return err
		}
		if !shadowOnly {
			return ErrExportRecoveryRequired
		}
		if _, err = tx.Exec(ctx, `UPDATE team_billing_usage SET exported_at=NULL,updated_at=now()
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND finalized_at IS NULL`,
			p.TeamID, p.Start, p.End); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE team_billing_period
            SET status=CASE WHEN approved_at IS NOT NULL THEN 'approved' ELSE 'validating' END,
                exported_at=NULL,updated_at=now()
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_incremental_period(team_id,period_start,period_end)
        VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.TeamID, p.Start, p.End)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s ExportStore) Totals(ctx context.Context, p ExportPeriod, resource string) (ExportTotals, error) {
	var t ExportTotals
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(sum(e.quantity),0)::text,
        COALESCE(sum(e.quantity) FILTER(WHERE e.status IN ('submitted','adopted')),0)::text,
        COALESCE(sum(e.quantity) FILTER(WHERE e.status IN ('pending','uncertain','recovery_required')),0)::text,
        COALESCE(sum(e.quantity) FILTER(WHERE e.status='rejected'),0)::text
        FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id AND e.active
        WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND a.resource_type=$4`,
		p.TeamID, p.Start, p.End, resource).Scan(&t.Reserved, &t.Submitted, &t.Pending, &t.Rejected)
	return t, err
}

// MeterEventName keeps a resource on the meter of its persisted period events,
// including adopted and rejected events whose coverage still belongs to the period.
func (s ExportStore) MeterEventName(ctx context.Context, p ExportPeriod, resource, configured string) (string, error) {
	return periodMeterEventName(ctx, s.Pool, p, resource, configured)
}

func periodMeterEventName(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, p ExportPeriod, resource, configured string) (string, error) {
	var first, last *string
	err := q.QueryRow(ctx, `SELECT min(e.event_name),max(e.event_name)
        FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id
        WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND a.resource_type=$4`,
		p.TeamID, p.Start, p.End, resource).Scan(&first, &last)
	if err != nil {
		return "", err
	}
	if first == nil {
		return configured, nil
	}
	if *first != *last {
		return "", ErrExportRecoveryRequired
	}
	return *first, nil
}

func (s ExportStore) Reserve(ctx context.Context, p ExportPeriod, resource, cumulative string, through time.Time, payload ExportPayload) (*ExportEvent, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = lockExportPeriod(ctx, tx, p); err != nil {
		return nil, err
	}
	// Recheck under the period lock so concurrent writers with different
	// configurations cannot split the first reservations across meters.
	payload.EventName, err = periodMeterEventName(ctx, tx, p, resource, payload.EventName)
	if err != nil {
		return nil, err
	}
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT feature_enabled('billing_export_enabled',$1)
        AND ($2 <> 'storage' OR feature_enabled('billing_storage_billing_enabled',$1))`, p.TeamID, resource).Scan(&enabled)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, fmt.Errorf("billing export is disabled")
	}
	var reserved string
	err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT coverage_end FROM billing_export_allocation
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4
        ORDER BY coverage_end DESC LIMIT 1),0)::text`, p.TeamID, p.Start, p.End, resource).Scan(&reserved)
	if err != nil {
		return nil, err
	}
	delta, err := DecimalDelta(cumulative, reserved)
	if err != nil {
		return nil, err
	}
	if delta == "0.000000000000" {
		return nil, nil
	}
	payloadQuantity, err := meterQuantityPrefix(delta)
	if err != nil {
		return nil, err
	}
	used, _ := new(big.Rat).SetString(reserved)
	increment, _ := new(big.Rat).SetString(payloadQuantity)
	coverageEnd := new(big.Rat).Add(used, increment).FloatString(12)
	var allocation uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO billing_export_allocation(team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through)
        VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7) RETURNING id`, p.TeamID, p.Start, p.End, resource, reserved, coverageEnd, through).Scan(&allocation)
	if err != nil {
		return nil, err
	}
	event := ExportEvent{ID: uuid.New(), AllocationID: allocation, Status: "pending", ExportPayload: payload}
	event.Identifier = "usage-" + event.ID.String()
	event.IdempotencyKey = event.Identifier
	event.Quantity = payloadQuantity
	if err = insertExportEvent(ctx, tx, event, "export", nil, nil); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &event, nil
}

func insertExportEvent(ctx context.Context, tx pgx.Tx, e ExportEvent, source string, evidence *string, replaces *uuid.UUID) error {
	_, err := tx.Exec(ctx, `INSERT INTO billing_export_event(id,allocation_id,identifier,idempotency_key,event_name,customer_id,
        quantity,quantity_payload,event_timestamp,source,evidence,replaces,status)
        VALUES($1,$2,$3,$4,$5,$6,$7::text::numeric,$7::text,$8,$9,$10,$11,$12)`, e.ID, e.AllocationID, e.Identifier, e.IdempotencyKey,
		e.EventName, e.CustomerID, e.Quantity, e.Timestamp, source, evidence, replaces, e.Status)
	return err
}

// Claim persists first_attempt_at before network I/O. The 23-hour cutoff leaves
// a margin inside Stripe's guaranteed 24-hour identifier retention window.
// Expiry locks at most 100 events per call; claims also exclude the remaining
// expired backlog so batching cannot extend the retry window.
func (s ExportStore) Claim(ctx context.Context, p ExportPeriod) (*ExportEvent, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	immutable, err := lockExportRecoveryPeriod(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	// Locked tuple addresses are valid within this statement and keep the update
	// bounded even when the planner would prefer a hash join over all events.
	_, err = tx.Exec(ctx, `WITH expired AS (
        SELECT e.ctid AS row_tid FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
        WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3
        AND e.active AND e.status IN ('pending','uncertain') AND e.first_attempt_at <= now()-interval '23 hours'
        AND (e.lease_until IS NULL OR e.lease_until <= now())
        ORDER BY e.first_attempt_at,e.id LIMIT 100 FOR UPDATE OF e SKIP LOCKED)
        UPDATE billing_export_event e SET status='recovery_required',updated_at=now(),last_error='retry window expired'
        WHERE e.ctid=ANY(ARRAY(SELECT row_tid FROM expired))`, p.TeamID, p.Start, p.End)
	if err != nil {
		return nil, err
	}
	token := uuid.New()
	row := tx.QueryRow(ctx, `WITH candidate AS (
        SELECT e.id FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
        WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND e.active
        AND (NOT $5 OR e.replaces IS NOT NULL OR a.correction_id IS NOT NULL)
        AND e.source='export' AND e.status IN ('pending','uncertain') AND e.next_attempt_at<=now()
        AND (e.first_attempt_at IS NULL OR e.first_attempt_at>now()-interval '23 hours')
        AND (e.lease_until IS NULL OR e.lease_until<=now())
        AND feature_enabled('billing_export_enabled',a.team_id)
        AND (a.resource_type<>'storage' OR feature_enabled('billing_storage_billing_enabled',a.team_id))
        ORDER BY e.created_at,e.id LIMIT 1 FOR UPDATE OF e SKIP LOCKED)
        UPDATE billing_export_event e SET status='uncertain',first_attempt_at=COALESCE(first_attempt_at,now()),
          lease_token=$4,lease_until=now()+interval '2 minutes',attempt_count=attempt_count+1,updated_at=now()
        FROM candidate c WHERE e.id=c.id
        RETURNING e.id,e.allocation_id,e.identifier,e.idempotency_key,e.event_name,e.customer_id,e.quantity_payload,e.event_timestamp,e.status`, p.TeamID, p.Start, p.End, token, immutable)
	var e ExportEvent
	err = row.Scan(&e.ID, &e.AllocationID, &e.Identifier, &e.IdempotencyKey, &e.EventName, &e.CustomerID, &e.Quantity, &e.Timestamp, &e.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	e.LeaseToken = token
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &e, nil
}

func (s ExportStore) Acknowledge(ctx context.Context, e ExportEvent, submitErr error) error {
	status := "submitted"
	var message *string
	if submitErr != nil {
		status = "uncertain"
		m := submitErr.Error()
		message = &m
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE billing_export_event SET status=$3,last_error=$4,
        submitted_at=CASE WHEN $3='submitted' THEN now() ELSE submitted_at END,
        next_attempt_at=now()+least(interval '6 hours',interval '5 minutes'*power(2,least(attempt_count,6)))
            +interval '1 second'*(get_byte(uuid_send(id),0)%60),
        lease_token=NULL,lease_until=NULL,updated_at=now()
        WHERE id=$1 AND lease_token=$2 AND active AND status='uncertain'`, e.ID, e.LeaseToken, status, message)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrExportRecoveryRequired
	}
	return err
}

// Reject is event-specific and wins over a concurrent acknowledgement, but not
// reviewed recovery evidence. Callbacks for resolved events preserve period state.
func (s ExportStore) Reject(ctx context.Context, identifier, key, customerID, eventName, message string) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	handled, err := s.RejectTx(ctx, tx, identifier, key, customerID, eventName, message)
	if err != nil || !handled {
		return handled, err
	}
	return true, tx.Commit(ctx)
}

// RejectTx keeps rejection and webhook completion atomic in the caller's transaction.
// The caller owns commit and rollback; no additional pool connection is acquired.
func (s ExportStore) RejectTx(ctx context.Context, tx pgx.Tx, identifier, key, customerID, eventName, message string) (bool, error) {
	var p ExportPeriod
	var eventID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT e.id,a.team_id,a.period_start,a.period_end FROM billing_export_event e
        JOIN billing_export_allocation a ON a.id=e.allocation_id
        WHERE ($1<>'' OR $2<>'') AND ($1='' OR e.identifier=$1)
          AND ($2='' OR e.idempotency_key=$2)
          AND ($3='' OR e.customer_id=$3) AND ($4='' OR e.event_name=$4)`,
		identifier, key, customerID, eventName).Scan(&eventID, &p.TeamID, &p.Start, &p.End)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var finalized bool
	err = tx.QueryRow(ctx, `SELECT finalized_at IS NOT NULL FROM team_billing_period
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 FOR UPDATE`, p.TeamID, p.Start, p.End).Scan(&finalized)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE billing_export_event SET status='rejected',last_error=$2,
        lease_token=NULL,lease_until=NULL,updated_at=now()
        WHERE id=$1 AND active AND recovery_outcome IS NULL`, eventID, message)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		_, err = tx.Exec(ctx, `UPDATE billing_export_event SET last_error=
            CASE WHEN recovery_outcome='accepted' THEN 'rejection callback contradicts reviewed acceptance: ' || $2
                 ELSE $2 END,updated_at=now() WHERE id=$1`, eventID, message)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	if !finalized {
		_, err = tx.Exec(ctx, `UPDATE team_billing_period SET status='exporting',exported_at=NULL,updated_at=now()
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status='exported'`, p.TeamID, p.Start, p.End)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// ResolveRecovery records reviewed event-specific provider evidence without resubmission.
// Rejected resolutions retain coverage until RecoverRejected creates a replacement.
func (s ExportStore) ResolveRecovery(ctx context.Context, id uuid.UUID, outcome, evidence string) error {
	if (outcome != "accepted" && outcome != "rejected") || strings.TrimSpace(evidence) == "" {
		return fmt.Errorf("accepted or rejected outcome and reviewed provider evidence are required")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var p ExportPeriod
	err = tx.QueryRow(ctx, `SELECT a.team_id,a.period_start,a.period_end FROM billing_export_event e
        JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE e.id=$1`, id).Scan(&p.TeamID, &p.Start, &p.End)
	if err != nil {
		return err
	}
	if _, err = lockExportRecoveryPeriod(ctx, tx, p); err != nil {
		return err
	}
	status := "rejected"
	if outcome == "accepted" {
		status = "submitted"
	}
	tag, err := tx.Exec(ctx, `UPDATE billing_export_event SET status=$2,
        recovery_outcome=$3,recovery_evidence=$4,lease_token=NULL,lease_until=NULL,updated_at=now()
        WHERE id=$1 AND active AND status='recovery_required' AND source='export'`, id, status, outcome, evidence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrExportRecoveryRequired
	}
	return tx.Commit(ctx)
}

func (s ExportStore) RecoverRejected(ctx context.Context, id uuid.UUID, evidence string) error {
	if evidence == "" {
		return fmt.Errorf("reviewed recovery evidence is required")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var p ExportPeriod
	err = tx.QueryRow(ctx, `SELECT a.team_id,a.period_start,a.period_end FROM billing_export_event e
        JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE e.id=$1`, id).Scan(&p.TeamID, &p.Start, &p.End)
	if err != nil {
		return err
	}
	if _, err = lockExportRecoveryPeriod(ctx, tx, p); err != nil {
		return err
	}
	var e ExportEvent
	err = tx.QueryRow(ctx, `SELECT id,allocation_id,identifier,idempotency_key,event_name,customer_id,quantity_payload,event_timestamp,status
        FROM billing_export_event WHERE id=$1 AND active AND status='rejected'
          AND recovery_outcome IS DISTINCT FROM 'accepted' FOR UPDATE`, id).
		Scan(&e.ID, &e.AllocationID, &e.Identifier, &e.IdempotencyKey, &e.EventName, &e.CustomerID, &e.Quantity, &e.Timestamp, &e.Status)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_export_event SET active=false WHERE id=$1`, id); err != nil {
		return err
	}
	e.ID = uuid.New()
	e.Identifier = "usage-" + e.ID.String()
	e.IdempotencyKey = e.Identifier
	e.Status = "pending"
	if err = insertExportEvent(ctx, tx, e, "export", &evidence, &id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AdoptedExport is an externally submitted event, verified against live provider
// totals and a reviewed complete event inventory by the operator endpoint.
type AdoptedExport struct {
	Resource string    `json:"resource"`
	Through  time.Time `json:"measured_through"`
	ExportPayload
}

func (e AdoptedExport) ValidateBoundary(p ExportPeriod) error {
	// Match export attribution to the last second of the complete meter minute
	// preceding coverage. Aggregate provider equality cannot verify this boundary.
	if !e.Through.After(p.Start) || e.Through.After(p.End) ||
		e.Timestamp != e.Through.Truncate(time.Minute).Add(-time.Second).Unix() ||
		e.Timestamp < p.Start.Unix() {
		return fmt.Errorf("adoption measurement boundary does not match period and semantic timestamp")
	}
	return nil
}

func (s ExportStore) Adopt(ctx context.Context, p ExportPeriod, events []AdoptedExport, evidence string) error {
	if len(events) == 0 || len(events) > 100 || evidence == "" {
		return fmt.Errorf("bounded event inventory and reviewed evidence are required")
	}
	for _, event := range events {
		if err := event.ValidateBoundary(p); err != nil {
			return err
		}
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockExportPeriod(ctx, tx, p); err != nil {
		return err
	}
	var enabled bool
	if err = tx.QueryRow(ctx, `SELECT feature_enabled('billing_export_enabled',$1)`, p.TeamID).Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		return fmt.Errorf("disable export before manual handover")
	}
	identifiers := make([]string, 0, len(events))
	seen := make(map[string]bool, len(events))
	for _, event := range events {
		if event.Identifier == "" || seen[event.Identifier] {
			return fmt.Errorf("invalid or duplicate inventory identifier")
		}
		seen[event.Identifier] = true
		identifiers = append(identifiers, event.Identifier)
	}
	// Legacy rows have no stored timestamp or measurement boundary. Those come
	// from the reviewed provider inventory; every persisted payload field must
	// still match. Unsettled attempts cannot be inferred from aggregate totals.
	rows, err := tx.Query(ctx, `SELECT resource_type,stripe_meter_event_identifier,
        stripe_event_name,COALESCE(stripe_customer_id,''),value::text,
        COALESCE(stripe_idempotency_key,''),status FROM billing_usage_export
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3
          AND status NOT IN ('skipped_shadow','skipped_zero','skipped_disabled')
        ORDER BY id LIMIT 101`, p.TeamID, p.Start, p.End)
	if err != nil {
		return err
	}
	legacyCount := 0
	for rows.Next() {
		var resource, identifier, eventName, customer, quantity, key, status string
		if err = rows.Scan(&resource, &identifier, &eventName, &customer, &quantity, &key, &status); err != nil {
			rows.Close()
			return err
		}
		legacyCount++
		matched := false
		for _, event := range events {
			if event.Identifier != identifier {
				continue
			}
			storedQuantity, storedOK := new(big.Rat).SetString(quantity)
			inventoryQuantity, inventoryOK := new(big.Rat).SetString(event.Quantity)
			matched = storedOK && inventoryOK && storedQuantity.Cmp(inventoryQuantity) == 0 &&
				event.Resource == resource && event.EventName == eventName && event.CustomerID == customer &&
				(key == "" || event.IdempotencyKey == key) && (status == "sent" || status == "accepted")
			break
		}
		if !matched || legacyCount > 100 {
			rows.Close()
			return fmt.Errorf("legacy exports require a complete matching settled inventory before handover")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// The period lock also fences legacy writes. Enrollment and adopted
	// coverage commit together, so no allocator can see an empty handover.
	if _, err = tx.Exec(ctx, `INSERT INTO billing_incremental_period(team_id,period_start,period_end)
        VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.TeamID, p.Start, p.End); err != nil {
		return err
	}
	// Existing reservations must be settled and included before external usage
	// can extend coverage; otherwise adoption could count the same usage twice.
	var incomplete bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_export_event e
        JOIN billing_export_allocation a ON a.id=e.allocation_id
        WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND e.active
          AND (e.status NOT IN ('submitted','adopted') OR NOT (e.identifier=ANY($4::text[]))))`,
		p.TeamID, p.Start, p.End, identifiers).Scan(&incomplete); err != nil {
		return err
	}
	if incomplete {
		return fmt.Errorf("inventory must include all active events; resolve pending or rejected reservations before adoption")
	}
	for _, manual := range events {
		name, err := periodMeterEventName(ctx, tx, p, manual.Resource, manual.EventName)
		if err != nil {
			return err
		}
		if name != manual.EventName {
			return fmt.Errorf("inventory meter differs from persisted period meter: %w", ErrExportRecoveryRequired)
		}
		var existing ExportPayload
		var resource string
		var through time.Time
		var active bool
		var status string
		err = tx.QueryRow(ctx, `SELECT e.identifier,e.idempotency_key,e.event_name,e.customer_id,e.quantity_payload,e.event_timestamp,a.resource_type,a.measured_through,e.active,e.status
            FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
            WHERE e.identifier=$1 AND a.team_id=$2 AND a.period_start=$3 AND a.period_end=$4`, manual.Identifier, p.TeamID, p.Start, p.End).
			Scan(&existing.Identifier, &existing.IdempotencyKey, &existing.EventName, &existing.CustomerID, &existing.Quantity, &existing.Timestamp, &resource, &through, &active, &status)
		if err == nil {
			if !active || (status != "submitted" && status != "adopted") || existing != manual.ExportPayload || resource != manual.Resource || !through.Equal(manual.Through) {
				return fmt.Errorf("inventory event differs from settled immutable evidence")
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		quantity, err := DecimalDelta(manual.Quantity, "0")
		if err != nil {
			return err
		}
		if quantity == "0.000000000000" {
			return fmt.Errorf("adopted quantity must be positive")
		}
		var allocation uuid.UUID
		err = tx.QueryRow(ctx, `INSERT INTO billing_export_allocation(team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through)
            SELECT $1,$2,$3,$4,COALESCE(max(coverage_end),0),COALESCE(max(coverage_end),0)+$5::numeric,$6
            FROM billing_export_allocation WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4 RETURNING id`,
			p.TeamID, p.Start, p.End, manual.Resource, manual.Quantity, manual.Through).Scan(&allocation)
		if err != nil {
			return err
		}
		e := ExportEvent{ID: uuid.New(), AllocationID: allocation, Status: "adopted", ExportPayload: manual.ExportPayload}
		if err = insertExportEvent(ctx, tx, e, "adopted", &evidence, nil); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
