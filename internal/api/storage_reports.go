package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/telemetry"
)

const (
	storageReportBatchSize          = 32
	storageReportChunkSize          = 500
	storageReportPoll               = 5 * time.Second
	storageReportMaxAttempts        = 8
	storageReportHandoffMaxAttempts = 8
	storageReportChunkTimeout       = 2 * time.Second
)

var (
	errStorageReportStaleIncarnation = errors.New("stale host incarnation")
	errStorageReportInvalidPayload   = errors.New("invalid storage report payload")
)

type storageReportMeasurement struct {
	SandboxID      string `json:"sandbox_id"`
	AllocatedBytes int64  `json:"allocated_bytes"`
}

type storageReportRequest struct {
	IncarnationID string                     `json:"incarnation_id"`
	ReportID      string                     `json:"report_id"`
	Measurements  []storageReportMeasurement `json:"measurements"`
}

func (h *Handlers) enqueueStorageReport(ctx context.Context, hostID, incarnation string, reportID uuid.UUID, measurements []storageReportMeasurement) error {
	if h.Pool == nil {
		return fmt.Errorf("storage report pool is unavailable")
	}
	if reportID == uuid.Nil {
		return fmt.Errorf("storage report ID is required")
	}
	var inc any
	if incarnation != "" {
		parsed, err := uuid.Parse(incarnation)
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("invalid heartbeat incarnation")
		}
		inc = parsed
	}
	payload, err := json.Marshal(measurements)
	if err != nil {
		return err
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Receipt time is allocated inside the same boundary used by direct
	// ingestion and promotion, so no older receipt can commit behind them.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, hostID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO legacy_host_storage_report(host_id, requested_incarnation_id, report_id, received_at, payload)
		VALUES ($1, $2, $3, clock_timestamp(), $4::jsonb)
		ON CONFLICT (host_id, report_id) DO NOTHING`, hostID, inc, reportID, payload)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) enqueueStorageReportWithRetry(ctx context.Context, hostID, incarnation string, reportID uuid.UUID, measurements []storageReportMeasurement) error {
	var err error
	for attempt := 0; attempt < storageReportHandoffMaxAttempts; attempt++ {
		if err = h.enqueueStorageReport(ctx, hostID, incarnation, reportID, measurements); err == nil {
			return nil
		}
		if attempt+1 == storageReportHandoffMaxAttempts {
			break
		}
		delay := time.Second << min(attempt, 5)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("legacy storage handoff failed after %d attempts: %w", storageReportHandoffMaxAttempts, err)
}

// HostStorageReport accepts a separately acknowledged, idempotent telemetry
// report. It only inserts the durable report row; interval writes are owned by
// the background worker and therefore cannot delay or fail a heartbeat.
func (h *Handlers) HostStorageReport(c *gin.Context) {
	hostID := c.Param("host_id")
	var req storageReportRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	incarnationID, err := uuid.Parse(req.IncarnationID)
	if err != nil || incarnationID == uuid.Nil {
		respondErrorMsg(c, "bad_request", "incarnation_id must be a nonzero UUID", http.StatusBadRequest)
		return
	}
	reportID, err := uuid.Parse(req.ReportID)
	if err != nil || reportID == uuid.Nil {
		respondErrorMsg(c, "bad_request", "report_id must be a nonzero UUID", http.StatusBadRequest)
		return
	}
	if len(req.Measurements) > maxHostStorageSamples {
		respondErrorMsg(c, "bad_request", "too many storage measurements", http.StatusBadRequest)
		return
	}
	seen := make(map[uuid.UUID]struct{}, len(req.Measurements))
	for _, m := range req.Measurements {
		sandboxID, err := uuid.Parse(m.SandboxID)
		if err != nil || m.AllocatedBytes < 0 {
			respondErrorMsg(c, "bad_request", "invalid storage measurement", http.StatusBadRequest)
			return
		}
		if _, duplicate := seen[sandboxID]; duplicate {
			respondErrorMsg(c, "bad_request", "duplicate storage measurement", http.StatusBadRequest)
			return
		}
		seen[sandboxID] = struct{}{}
		// The worker rounds bytes to a signed 32-bit MiB value. Reject values
		// before they are durably accepted so that conversion cannot overflow.
		if m.AllocatedBytes > maxHostStorageAllocatedBytes {
			respondErrorMsg(c, "bad_request", "storage measurement is too large", http.StatusBadRequest)
			return
		}
	}
	if h.Pool == nil {
		respondErrorMsg(c, "service_unavailable", "storage reports are not configured", http.StatusServiceUnavailable)
		return
	}
	payload, err := json.Marshal(req.Measurements)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	// Sequence allocation must serialize across direct reports and legacy
	// promotion without holding the heartbeat row through payload hashing.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, hostID); err != nil {
		respondError(c, ErrInternal)
		return
	}
	// Reject obviously stale reports before inserting; the locking check below
	// fences an incarnation change that races with payload persistence.
	var current pgtype.UUID
	if err := tx.QueryRow(ctx, `SELECT incarnation_id FROM host WHERE id=$1`, hostID).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
		return
	} else if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if !current.Valid || uuid.UUID(current.Bytes) != incarnationID {
		respondErrorMsg(c, "conflict", "storage report belongs to a stale host incarnation", http.StatusConflict)
		return
	}
	if err := promoteLegacyStorageReportsForDirect(ctx, tx, hostID, incarnationID); err != nil {
		respondError(c, ErrInternal)
		return
	}
	var seq int64
	var received time.Time
	var samePayload bool
	err = tx.QueryRow(ctx, `
		SELECT ingest_seq, received_at,
		       payload_hash = encode(digest($4::jsonb::text, 'sha256'),'hex')
		FROM host_storage_report
		WHERE host_id=$1 AND incarnation_id=$2 AND report_id=$3`, hostID, incarnationID, reportID, payload).Scan(&seq, &received, &samePayload)
	if err == nil {
		if !h.fenceStorageReportIncarnation(c, tx, hostID, incarnationID) {
			return
		}
		if !samePayload {
			respondErrorMsg(c, "conflict", "report_id was already used with a different payload", http.StatusConflict)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			respondError(c, ErrInternal)
			return
		}
		c.JSON(http.StatusOK, gin.H{"report_id": reportID, "ingest_seq": seq, "received_at": received})
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(ingest_seq),0)+1 FROM host_storage_report WHERE host_id=$1 AND incarnation_id=$2`, hostID, incarnationID).Scan(&seq); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload)
		VALUES ($1,$2,$3,$4,clock_timestamp(),$5::jsonb)
		RETURNING received_at`, hostID, incarnationID, reportID, seq, payload).Scan(&received); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if !h.fenceStorageReportIncarnation(c, tx, hostID, incarnationID) {
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"report_id": reportID, "ingest_seq": seq, "received_at": received})
}

// promoteLegacyStorageReportsForDirect drains the compatibility stream before
// assigning a sequence to a direct report. Both streams use the same host
// advisory lock, so an older legacy receipt can never be sequenced after a
// newer direct receipt. Binding the incarnation removes the reason to defer
// an older handoff, so its retry delay must not let the direct report pass it.
func promoteLegacyStorageReportsForDirect(ctx context.Context, tx pgx.Tx, hostID string, incarnationID uuid.UUID) error {
	for {
		var requestedIncarnation pgtype.UUID
		var reportID uuid.UUID
		var receivedAt time.Time
		var payload []byte
		err := tx.QueryRow(ctx, `
			SELECT requested_incarnation_id, report_id, received_at, payload
			FROM legacy_host_storage_report
			WHERE host_id=$1
			ORDER BY received_at, report_id
			FOR UPDATE SKIP LOCKED LIMIT 1`, hostID,
		).Scan(&requestedIncarnation, &reportID, &receivedAt, &payload)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if requestedIncarnation.Valid && uuid.UUID(requestedIncarnation.Bytes) != incarnationID {
			if _, err := tx.Exec(ctx, `DELETE FROM legacy_host_storage_report WHERE host_id=$1 AND report_id=$2`, hostID, reportID); err != nil {
				return err
			}
			continue
		}
		var seq int64
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(MAX(ingest_seq),0)+1
			FROM host_storage_report
			WHERE host_id=$1 AND incarnation_id=$2`, hostID, incarnationID).Scan(&seq); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload)
			VALUES ($1,$2,$3,$4,$5,$6::jsonb)
			ON CONFLICT (host_id, incarnation_id, report_id) DO NOTHING`, hostID, incarnationID, reportID, seq, receivedAt, payload); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM legacy_host_storage_report WHERE host_id=$1 AND report_id=$2`, hostID, reportID); err != nil {
			return err
		}
	}
}

func (h *Handlers) fenceStorageReportIncarnation(c *gin.Context, tx pgx.Tx, hostID string, incarnationID uuid.UUID) bool {
	var current pgtype.UUID
	if err := tx.QueryRow(c.Request.Context(), `SELECT incarnation_id FROM host WHERE id=$1 FOR UPDATE`, hostID).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "not_found", "host not found", http.StatusNotFound)
		return false
	} else if err != nil {
		respondError(c, ErrInternal)
		return false
	}
	if !current.Valid || uuid.UUID(current.Bytes) != incarnationID {
		respondErrorMsg(c, "conflict", "storage report belongs to a stale host incarnation", http.StatusConflict)
		return false
	}
	return true
}

// StartStorageReportWorker applies reports in short, independently retryable
// transactions. A five-second poll and exponential retry capped at one minute
// bound normal telemetry lag without adding work to sandbox activation paths.
func StartStorageReportWorker(ctx context.Context, pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(storageReportPoll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for i := 0; i < storageReportBatchSize; i++ {
					promoteLegacyStorageReport(ctx, pool)
					if !processOneStorageReport(ctx, pool) {
						break
					}
				}
			}
		}
	}()
}

func promoteLegacyStorageReport(ctx context.Context, pool *pgxpool.Pool) bool {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='250ms'`); err != nil {
		return false
	}
	var hostID string
	var requestedIncarnation pgtype.UUID
	var reportID uuid.UUID
	var receivedAt time.Time
	var payload []byte
	err = tx.QueryRow(ctx, `
		SELECT r.host_id
		FROM legacy_host_storage_report r
		WHERE r.next_attempt_at <= statement_timestamp()
		  AND NOT EXISTS (
			SELECT 1 FROM legacy_host_storage_report prior
			WHERE prior.host_id=r.host_id
			  AND (prior.received_at, prior.report_id) < (r.received_at, r.report_id)
		  )
		ORDER BY r.received_at, r.report_id
		LIMIT 1`).Scan(&hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		return false
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, hostID); err != nil {
		return false
	}
	err = tx.QueryRow(ctx, `
		SELECT requested_incarnation_id, report_id, received_at, payload
		FROM legacy_host_storage_report r
		WHERE host_id=$1 AND next_attempt_at <= statement_timestamp()
		  AND NOT EXISTS (
			SELECT 1 FROM legacy_host_storage_report prior
			WHERE prior.host_id=r.host_id
			  AND (prior.received_at, prior.report_id) < (r.received_at, r.report_id)
		  )
		ORDER BY received_at, report_id
		FOR UPDATE SKIP LOCKED LIMIT 1`, hostID,
	).Scan(&requestedIncarnation, &reportID, &receivedAt, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		return false
	}

	var currentIncarnation pgtype.UUID
	if err := tx.QueryRow(ctx, `SELECT incarnation_id FROM host WHERE id=$1`, hostID).Scan(&currentIncarnation); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_, _ = tx.Exec(ctx, `DELETE FROM legacy_host_storage_report WHERE host_id=$1 AND report_id=$2`, hostID, reportID)
			return tx.Commit(ctx) == nil
		}
		return false
	}
	if requestedIncarnation.Valid && !currentIncarnation.Valid {
		_, err = tx.Exec(ctx, `
			UPDATE legacy_host_storage_report
			SET attempts=attempts+1, next_attempt_at=now()+interval '30 seconds', last_error='requested incarnation is not bound'
			WHERE host_id=$1 AND report_id=$2`, hostID, reportID)
		if err != nil {
			return false
		}
		return tx.Commit(ctx) == nil
	}
	if requestedIncarnation.Valid && (!currentIncarnation.Valid || requestedIncarnation.Bytes != currentIncarnation.Bytes) {
		log.Warn().Str("host_id", hostID).Str("report_id", reportID.String()).
			Msg("dropping stale legacy storage handoff")
		_, _ = tx.Exec(ctx, `DELETE FROM legacy_host_storage_report WHERE host_id=$1 AND report_id=$2`, hostID, reportID)
		return tx.Commit(ctx) == nil
	}
	// A legacy host can remain unbound indefinitely. The nil UUID is reserved
	// for this temporary compatibility stream; current-incarnation reports
	// always use the host's non-nil identity.
	incarnationID := uuid.Nil
	if currentIncarnation.Valid {
		incarnationID = uuid.UUID(currentIncarnation.Bytes)
	}
	var ingestSeq int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(ingest_seq),0)+1
		FROM host_storage_report
		WHERE host_id=$1 AND incarnation_id=$2`, hostID, incarnationID).Scan(&ingestSeq); err != nil {
		return false
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_storage_report(host_id, incarnation_id, report_id, ingest_seq, received_at, payload)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb)
		ON CONFLICT (host_id, incarnation_id, report_id) DO NOTHING`, hostID, incarnationID, reportID, ingestSeq, receivedAt, payload); err != nil {
		return false
	}
	var fencedIncarnation pgtype.UUID
	if err := tx.QueryRow(ctx, `SELECT incarnation_id FROM host WHERE id=$1 FOR UPDATE`, hostID).Scan(&fencedIncarnation); err != nil || fencedIncarnation != currentIncarnation {
		return false
	}
	if _, err := tx.Exec(ctx, `DELETE FROM legacy_host_storage_report WHERE host_id=$1 AND report_id=$2`, hostID, reportID); err != nil {
		return false
	}
	return tx.Commit(ctx) == nil
}

func processOneStorageReport(ctx context.Context, pool *pgxpool.Pool) bool {
	var hostID string
	var incarnationID, reportID uuid.UUID
	var payload []byte
	var receivedAt time.Time
	var nextIndex int
	var processingGeneration int64
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='250ms'`); err != nil {
		return false
	}
	// retry_exhausted is an unresolved, recoverable marker. Its persisted
	// cooldown keeps an outage from permanently blocking this incarnation.
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT host_id, incarnation_id, report_id FROM host_storage_report
			WHERE (state IN ('pending', 'retry_exhausted') OR (state='processing' AND next_attempt_at < now()-interval '1 minute'))
			  AND next_attempt_at <= now()
			  AND NOT EXISTS (
				SELECT 1 FROM host_storage_report prior
				WHERE prior.host_id=host_storage_report.host_id
				  AND prior.incarnation_id=host_storage_report.incarnation_id
				  AND prior.ingest_seq < host_storage_report.ingest_seq
				  AND prior.state NOT IN ('processed', 'terminal')
			  )
			ORDER BY received_at
			FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE host_storage_report r
		SET state='processing', next_attempt_at=now(), processing_generation=r.processing_generation+1
		FROM candidate c WHERE r.host_id=c.host_id AND r.incarnation_id=c.incarnation_id AND r.report_id=c.report_id
		RETURNING r.host_id, r.incarnation_id, r.report_id, r.received_at, r.payload, r.next_measurement_index, r.processing_generation`).Scan(&hostID, &incarnationID, &reportID, &receivedAt, &payload, &nextIndex, &processingGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		return false
	}
	if err := tx.Commit(ctx); err != nil {
		return false
	}

	var measurements []storageReportMeasurement
	if err := json.Unmarshal(payload, &measurements); err != nil {
		return finishStorageReport(ctx, pool, hostID, incarnationID, reportID, processingGeneration, fmt.Errorf("%w: decode payload: %v", errStorageReportInvalidPayload, err), true)
	}
	if nextIndex > len(measurements) {
		return finishStorageReport(ctx, pool, hostID, incarnationID, reportID, processingGeneration, errStorageReportInvalidPayload, true)
	}
	end := nextIndex + storageReportChunkSize
	if end > len(measurements) {
		end = len(measurements)
	}
	if err := applyStorageReport(ctx, pool, hostID, incarnationID, reportID, processingGeneration, receivedAt, measurements[nextIndex:end], end, len(measurements)); err != nil {
		return finishStorageReport(ctx, pool, hostID, incarnationID, reportID, processingGeneration, err, storageReportErrorIsTerminal(err))
	}
	return true
}

func applyStorageReport(ctx context.Context, pool *pgxpool.Pool, hostID string, incarnationID, reportID uuid.UUID, processingGeneration int64, receivedAt time.Time, measurements []storageReportMeasurement, nextIndex, totalMeasurements int) error {
	// The chunk holds sandbox rows shared with lifecycle mutations. Bound its
	// total lifetime as well as individual lock waits; a timed-out chunk retries.
	ctx, cancel := context.WithTimeout(ctx, storageReportChunkTimeout)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		rollbackCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(rollbackCtx)
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='250ms'`); err != nil {
		return err
	}
	ids := make([]uuid.UUID, 0, len(measurements))
	disk := make([]int32, 0, len(measurements))
	for _, m := range measurements {
		id, err := uuid.Parse(m.SandboxID)
		if err != nil {
			return fmt.Errorf("%w: sandbox_id %q: %v", errStorageReportInvalidPayload, m.SandboxID, err)
		}
		if m.AllocatedBytes < 0 || m.AllocatedBytes > maxHostStorageAllocatedBytes {
			return fmt.Errorf("%w: allocated_bytes out of range", errStorageReportInvalidPayload)
		}
		ids = append(ids, id)
		disk = append(disk, int32((m.AllocatedBytes+(1<<20)-1)>>20))
	}
	// Match lifecycle lock order, then take a fresh statement snapshot for the
	// interval changes. Destruction may have committed while this lock waited.
	// NO KEY UPDATE also avoids blocking foreign-key checks on the sandbox.
	if _, err := tx.Exec(ctx, `
		SELECT id FROM sandbox
		WHERE id=ANY($1::uuid[]) AND host_id=$2
		ORDER BY id FOR NO KEY UPDATE`, ids, hostID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		WITH measurements AS MATERIALIZED (
			SELECT unnest($1::uuid[]) AS sandbox_id, unnest($2::int[]) AS disk_mib
		), eligible AS MATERIALIZED (
			SELECT s.id, s.team_id, s.destroyed_at, m.disk_mib FROM measurements m
			JOIN sandbox s ON s.id=m.sandbox_id
			WHERE s.host_id=$3
			  AND s.created_at <= $4::timestamptz
			  -- A worker can lag sandbox destruction. Reports are eligible based
			  -- on the sandbox lifetime at receipt, not processing time.
			  AND (s.destroyed_at IS NULL OR s.destroyed_at > $4::timestamptz)
			  AND feature_enabled('billing_metrics_write', s.team_id)
			  -- A report received before a later activation is stale for that
			  -- sandbox. Do not close or reopen an interval across that boundary.
			  AND NOT EXISTS (
				SELECT 1 FROM sandbox_storage_interval future
				WHERE future.sandbox_id=s.id
				  AND future.team_id=s.team_id
				  AND future.started_at > $4::timestamptz
			)
		), current_intervals AS MATERIALIZED (
			SELECT e.id, e.team_id, e.destroyed_at, e.disk_mib,
			       i.id AS interval_id, i.disk_mib AS current_disk_mib
			FROM eligible e
			LEFT JOIN sandbox_storage_interval i
			  ON i.sandbox_id=e.id
			 AND i.team_id=e.team_id
			 AND i.started_at <= $4::timestamptz
			 AND (i.ended_at IS NULL OR i.ended_at > $4::timestamptz)
		), closed AS (
			UPDATE sandbox_storage_interval i SET ended_at=$4::timestamptz, end_reason='measurement'
			FROM current_intervals e WHERE i.id=e.interval_id
			  AND i.disk_mib IS DISTINCT FROM e.disk_mib
			RETURNING i.sandbox_id, i.team_id
		)
		INSERT INTO sandbox_storage_interval(sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason)
		SELECT e.id, e.team_id, e.disk_mib, $4::timestamptz,
		       e.destroyed_at,
		       CASE WHEN e.destroyed_at IS NULL THEN NULL ELSE 'deleted' END
		FROM current_intervals e
		LEFT JOIN closed c ON c.sandbox_id=e.id AND c.team_id=e.team_id
		WHERE e.interval_id IS NULL OR e.current_disk_mib IS DISTINCT FROM e.disk_mib
		ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING`, ids, disk, hostID, receivedAt)
	if err != nil {
		return err
	}
	// Do the identity fence after the interval CTE, not before it. The row lock
	// is held until commit, so taking it up front would make every heartbeat
	// wait behind a fleet-sized storage write. If the host was rebound while
	// this transaction was applying intervals, the check fails and the whole
	// transaction (including the interval changes) rolls back. A concurrent
	// heartbeat only overlaps the short final check and commit.
	var current pgtype.UUID
	if err := tx.QueryRow(ctx, `SELECT incarnation_id FROM host WHERE id=$1 FOR UPDATE`, hostID).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: host not found", errStorageReportStaleIncarnation)
		}
		return err
	}
	if incarnationID == uuid.Nil {
		if current.Valid {
			return errStorageReportStaleIncarnation
		}
	} else if !current.Valid || uuid.UUID(current.Bytes) != incarnationID {
		return errStorageReportStaleIncarnation
	}
	// Advance the durable cursor in the same transaction as interval changes.
	// A crash cannot leave applied measurements to be replayed without the
	// corresponding report progress. The generation fences a worker whose
	// expired lease was claimed again, even if the new owner is processing.
	state := "pending"
	if nextIndex == totalMeasurements {
		state = "processed"
	}
	var progressErr error
	var progressRows int64
	if state == "processed" {
		var tag pgconn.CommandTag
		tag, progressErr = tx.Exec(ctx, `
			UPDATE host_storage_report
			SET state='processed', next_measurement_index=$4, processed_at=now(), last_error=NULL, payload=NULL
			WHERE host_id=$1 AND incarnation_id=$2 AND report_id=$3 AND state='processing'
			  AND processing_generation=$5`, hostID, incarnationID, reportID, nextIndex, processingGeneration)
		progressRows = tag.RowsAffected()
	} else {
		var tag pgconn.CommandTag
		tag, progressErr = tx.Exec(ctx, `
			UPDATE host_storage_report
			SET state='pending', next_measurement_index=$4, next_attempt_at=now(), last_error=NULL
			WHERE host_id=$1 AND incarnation_id=$2 AND report_id=$3 AND state='processing'
			  AND processing_generation=$5`, hostID, incarnationID, reportID, nextIndex, processingGeneration)
		progressRows = tag.RowsAffected()
	}
	if progressErr != nil {
		return fmt.Errorf("advance report progress: %w", progressErr)
	}
	if progressRows != 1 {
		return fmt.Errorf("advance report progress: expected one report row, updated %d", progressRows)
	}
	return tx.Commit(ctx)
}

func finishStorageReport(ctx context.Context, pool *pgxpool.Pool, hostID string, incarnationID, reportID uuid.UUID, processingGeneration int64, processErr error, discard bool) bool {
	if processErr == nil {
		tag, err := pool.Exec(ctx, `UPDATE host_storage_report SET state='processed', processed_at=now(), last_error=NULL, payload=NULL WHERE host_id=$1 AND incarnation_id=$2 AND report_id=$3 AND state='processing' AND processing_generation=$4`, hostID, incarnationID, reportID, processingGeneration)
		return err == nil && tag.RowsAffected() == 1
	}
	var state string
	var attempts int
	retryExhausted := false
	if !discard {
		err := pool.QueryRow(ctx, `
			UPDATE host_storage_report
			SET state=CASE WHEN attempts + 1 >= $5 THEN 'retry_exhausted' ELSE 'pending' END,
			    attempts=attempts+1,
			    next_attempt_at=now()+LEAST(make_interval(secs=>power(2, LEAST(attempts,6))::int), interval '1 minute'),
			    last_error=$4
			WHERE host_id=$1 AND incarnation_id=$2 AND report_id=$3 AND state='processing'
			  AND processing_generation=$6
			RETURNING state, attempts`, hostID, incarnationID, reportID, processErr.Error(), storageReportMaxAttempts, processingGeneration).Scan(&state, &attempts)
		if err != nil {
			return false
		}
		retryExhausted = state == "retry_exhausted"
	}
	if discard {
		if state == "" {
			if err := pool.QueryRow(ctx, `
				UPDATE host_storage_report
				SET state='terminal', attempts=attempts+1, last_error=$4, payload=NULL
				WHERE host_id=$1 AND incarnation_id=$2 AND report_id=$3 AND state='processing'
				  AND processing_generation=$5
				RETURNING attempts`, hostID, incarnationID, reportID, processErr.Error(), processingGeneration).Scan(&attempts); err != nil {
				return false
			}
		}
	}
	log.Error().Err(processErr).Str("host_id", hostID).Str("report_id", reportID.String()).Int("attempts", attempts).
		Bool("terminal", discard).Bool("retry_exhausted", retryExhausted).Msg("storage measurement processing failed")
	if recorder, ok := currentTelemetryRecorder().(telemetry.StorageReportFailureRecorder); ok {
		result := "error"
		if discard {
			result = "terminal"
		}
		recorder.RecordStorageReportFailure(ctx, telemetry.StorageReportFailure{Result: result})
	}
	return true
}

// storageReportErrorIsTerminal identifies failures that cannot be fixed by
// retrying the same immutable report. Other database and network failures are
// retried with bounded backoff; retry_exhausted is a recoverable marker rather
// than a terminal state so billing cannot treat unapplied data as settled.
func storageReportErrorIsTerminal(err error) bool {
	if err == nil {
		return false
	}
	// Database constraints can reflect deployment skew or a repairable schema
	// failure, not bad input. Only explicitly validated report failures discard
	// the durable payload and stop blocking billing completeness.
	return errors.Is(err, errStorageReportStaleIncarnation) || errors.Is(err, errStorageReportInvalidPayload)
}
