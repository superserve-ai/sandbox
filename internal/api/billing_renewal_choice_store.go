package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresRenewalChoiceStore struct{ Pool *pgxpool.Pool }

type postgresRenewalChoiceTx struct {
	ctx      context.Context
	tx       pgx.Tx
	journal  renewalChoiceJournal
	revision int64
	now      time.Time
}

func (s postgresRenewalChoiceStore) Transact(ctx context.Context, key renewalChoiceKey, f func(renewalChoiceTransaction) error) error {
	if s.Pool == nil || !validRenewalKey(key) {
		return errRenewalDisabled
	}
	key.Boundary = key.Boundary.UTC()
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.WithTx(ctx, tx, key, f); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Financial finalization already holds account and target-fence locks. Joining
// that transaction keeps activation and the journal marker atomic.
func (s postgresRenewalChoiceStore) WithTx(ctx context.Context, tx pgx.Tx, key renewalChoiceKey, f func(renewalChoiceTransaction) error) error {
	if tx == nil || !validRenewalKey(key) {
		return errRenewalDisabled
	}
	key.Boundary = key.Boundary.UTC()
	var err error
	// Account-first ordering matches other billing writers. Authority adapters may
	// then inspect regional assignment/acceptance rows. Shared dispatch guards
	// and provider calls run only after this transaction has committed.
	var team uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, key.Team).Scan(&team); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_renewal_choice(team_id,assignment_id,intended_boundary) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, key.Team, key.Assignment, key.Boundary); err != nil {
		return err
	}
	t := &postgresRenewalChoiceTx{ctx: ctx, tx: tx}
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT revision,snapshot FROM billing_renewal_choice WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3 FOR UPDATE`, key.Team, key.Assignment, key.Boundary).Scan(&t.revision, &raw); err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&t.now); err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &t.journal); err != nil {
		return err
	}
	if t.revision == 0 {
		t.journal = renewalChoiceJournal{Key: key, Successor: renewalSuccessorID(key)}
	} else if t.journal.Revision != t.revision || t.journal.Key.Team != key.Team || t.journal.Key.Assignment != key.Assignment || !t.journal.Key.Boundary.Equal(key.Boundary) {
		return fmt.Errorf("invalid renewal journal identity: %w", errRenewalConflict)
	}
	return f(t)
}

func (t *postgresRenewalChoiceTx) SQL() pgx.Tx                    { return t.tx }
func (t *postgresRenewalChoiceTx) Now() time.Time                 { return t.now }
func (t *postgresRenewalChoiceTx) Journal() *renewalChoiceJournal { return &t.journal }
func (t *postgresRenewalChoiceTx) Find(id uuid.UUID) (*renewalChoiceOperation, error) {
	k := t.journal.Key
	var raw []byte
	err := t.tx.QueryRow(t.ctx, `SELECT request FROM billing_renewal_choice_request WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3 AND request_id=$4`, k.Team, k.Assignment, k.Boundary, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var op renewalChoiceOperation
	if err = json.Unmarshal(raw, &op); err != nil {
		return nil, err
	}
	return &op, nil
}
func (t *postgresRenewalChoiceTx) Insert(op renewalChoiceOperation) error {
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	k := t.journal.Key
	_, err = t.tx.Exec(t.ctx, `INSERT INTO billing_renewal_choice_request(team_id,assignment_id,intended_boundary,request_id,operation_id,request) VALUES($1,$2,$3,$4,$5,$6)`, k.Team, k.Assignment, k.Boundary, op.Request.ID, op.ID, raw)
	return err
}
func (t *postgresRenewalChoiceTx) Save(event string) error {
	k := t.journal.Key
	t.journal.Revision = t.revision + 1
	raw, err := json.Marshal(t.journal)
	if err != nil {
		return err
	}
	tag, err := t.tx.Exec(t.ctx, `UPDATE billing_renewal_choice SET revision=$4,snapshot=$5,updated_at=clock_timestamp() WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3 AND revision=$6`, k.Team, k.Assignment, k.Boundary, t.journal.Revision, raw, t.revision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errRenewalConflict
	}
	if _, err = t.tx.Exec(t.ctx, `INSERT INTO billing_renewal_choice_event(team_id,assignment_id,intended_boundary,revision,event,snapshot) VALUES($1,$2,$3,$4,$5,$6)`, k.Team, k.Assignment, k.Boundary, t.journal.Revision, event, raw); err != nil {
		return err
	}
	t.revision = t.journal.Revision
	return nil
}
