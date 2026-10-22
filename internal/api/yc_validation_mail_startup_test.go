package api

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

func TestYCValidationMailStartupNeverPollsBroadOperations(t *testing.T) {
	dsn := os.Getenv("YC_CLAIM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL URL required")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	name := "validation_mail_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE TABLE calls(kind text, op text, args jsonb);
CREATE FUNCTION yc_claim_rpc(op text,p jsonb) RETURNS jsonb LANGUAGE plpgsql AS $$ BEGIN INSERT INTO calls VALUES('confirmation',op,p); RETURN '{}'::jsonb; END $$;
CREATE FUNCTION yc_claim_approval_mail_rpc(op text,p jsonb) RETURNS jsonb LANGUAGE plpgsql AS $$ BEGIN INSERT INTO calls VALUES('approval',op,p); RETURN '{}'::jsonb; END $$;`)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("YC_EMAIL_API_KEY", "test-key-never-sent")
	t.Setenv("YC_EMAIL_FROM", "sender@example.test")
	t.Setenv("YC_CONSOLE_URL", "https://console.example.test")
	t.Setenv("YC_STAGING_VALIDATION_RUN_ID", "")
	claim := uuid.New()
	t.Setenv("YC_STAGING_VALIDATION_CLAIM_ID", claim.String())
	workers, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, state := range []ycclaims.CaptureValidation{
		{}, // Unsupported factory still sees the explicit environment intent.
		{Requested: true},
		{Requested: true, ExpiresAt: time.Now().Add(time.Minute)},
		{Requested: true, Verifier: ycclaims.VerifyCapture, ExpiresAt: time.Now().Add(-time.Minute)},
	} {
		h := &Handlers{PromotionAuthPool: pool, YCClaimValidation: state}
		h.StartYCClaimMail(workers)
	}
	// One validated worker proves the polling loop runs. No outbox job means
	// no external provider call; every operation is recorded in the test DB.
	valid := &Handlers{PromotionAuthPool: pool, YCClaimValidation: ycclaims.CaptureValidation{Requested: true, Verifier: ycclaims.VerifyCapture, ExpiresAt: time.Now().Add(time.Minute)}}
	valid.StartYCClaimMail(workers)
	deadline := time.Now().Add(8 * time.Second)
	for {
		var scoped, broad int
		err = pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE kind='approval' AND op='lease-for-claim' AND args->>'claim_id'=$1),count(*) FILTER(WHERE kind='confirmation' OR op='lease') FROM calls`, claim.String()).Scan(&scoped, &broad)
		if err != nil {
			t.Fatal(err)
		}
		if broad != 0 {
			t.Fatal("validation started broad mail/maintenance", broad)
		}
		if scoped > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scoped approval worker did not poll")
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
}
