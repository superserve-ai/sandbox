// Command qm-api serves the hosted-QM control API and, as a Cloud Run Job,
// runs the tenant provisioner:
//
//	qm-api                       serve /v1/qm (default)
//	qm-api provision --team T --tenant ID --mode provision|deprovision [--attempt N]
//
// Both modes read the same environment; see internal/qm.LoadConfig.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/qm"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	multi := zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
		&sentrylog.Writer{},
	)
	log.Logger = zerolog.New(multi).With().Timestamp().Caller().Logger()

	var err error
	if len(os.Args) > 1 && os.Args[1] == "provision" {
		err = runProvision(os.Args[2:])
	} else {
		err = runServe()
	}
	if err != nil {
		// Scrubbed: a step error can echo a connection string or key a
		// cloud API was handed, and this line reaches Sentry.
		log.Fatal().Str("error", provisioner.ScrubString(err.Error())).Msg("qm-api exited with error")
	}
}

// deps is everything both modes share once configured.
type deps struct {
	cfg        qm.Config
	pool       *pgxpool.Pool
	store      tenantstore.Store
	closeStore func()
	secrets    secrets.Store
	runner     *provisioner.Runner
}

func (d *deps) close() {
	d.closeStore()
	d.pool.Close()
}

// setup connects to the database first and everything else after, and
// returns the partially built deps alongside a later error so the job can
// still record a failure against the tenant it was started for. That
// includes a config error: an unusable config usually still names the
// database, and the tenant the job was started for is better told than left
// in flight until the stale reclaim.
func setup(ctx context.Context) (*deps, error) {
	cfg, cfgErr := qm.LoadConfig()
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("load config: %w", cfgErr)
	}
	pool, err := connectDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	store, err := tenantstore.NewPostgres(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	d := &deps{cfg: cfg, pool: pool, store: store, closeStore: store.Close}
	if cfgErr != nil {
		return d, fmt.Errorf("load config: %w", cfgErr)
	}

	// After the store, so that every later setup failure is one the job can
	// still record against the tenant it was started for.
	if cfg.SentryDSN != "" {
		if err := sentry.Init(sentry.ClientOptions{Dsn: cfg.SentryDSN, EnableLogs: true}); err != nil {
			return d, fmt.Errorf("sentry init: %w", err)
		}
	}

	var secretStore secrets.Store
	switch cfg.SecretsBackend {
	case qm.SecretsBackendMemory:
		log.Warn().Msg("QM_SECRETS_BACKEND=memory: secrets are not persisted")
		secretStore = secrets.NewFake()
	default:
		secretStore, err = secrets.NewGCP(ctx, cfg.GCPProject)
		if err != nil {
			return d, err
		}
	}
	d.secrets = secretStore

	env := provisioner.Env{
		Project:    cfg.GCPProject,
		Region:     cfg.ProvisionerRegion,
		BaseDomain: cfg.BaseDomain,
		Image:      cfg.TenantImage,
		Stub:       cfg.ProvisionerStub,
	}
	if env.Stub {
		log.Warn().Msg("QM_PROVISIONER_STUB=1: cloud-touching steps record placeholders instead of creating resources")
	}
	d.runner = &provisioner.Runner{
		Store: d.store,
		Env:   env,
		Steps: steps.All(steps.Clients{Secrets: secretStore}),
		Log:   log.Logger,
	}
	// Refuse a configuration whose plan would stop partway: by the time a
	// run reaches an unimplemented step the tenant already has a model key
	// in Secret Manager and a half-built stack behind it, so the failure
	// belongs at startup, where it blocks the deploy instead.
	if err := provisioner.PlanReady(d.runner.Steps, env); err != nil {
		return d, err
	}
	return d, nil
}

func connectDB(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	// Same reasoning as the control plane: the Supabase transaction pooler
	// does not keep named prepared statements across transactions.
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	poolCfg.ConnConfig.ConnectTimeout = 5 * time.Second
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

func runServe() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := setup(ctx)
	if d != nil {
		defer d.close()
	}
	if err != nil {
		return err
	}
	defer sentry.Flush(2 * time.Second)

	var trigger provisioner.Trigger
	var inProcess *provisioner.InProcess
	switch d.cfg.ProvisionerMode {
	case qm.ProvisionerModeInProcess:
		log.Warn().Msg("QM_PROVISIONER_MODE=inprocess: runs execute inside this process")
		inProcess = &provisioner.InProcess{Runner: d.runner, Log: log.Logger}
		trigger = inProcess
	default:
		trigger, err = provisioner.NewCloudRunJob(ctx, d.cfg.GCPProject, d.cfg.ProvisionerRegion, d.cfg.ProvisionerJob)
		if err != nil {
			return err
		}
	}

	h := &qm.Handlers{Store: d.store, Secrets: d.secrets, Trigger: trigger, Log: log.Logger, StaleAfter: d.cfg.RunStaleAfter}
	router := qm.SetupRouter(h, qm.NewPostgresKeyResolver(d.pool), log.Logger)

	srv := &http.Server{
		Addr:              ":" + d.cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("addr", srv.Addr).Str("base_domain", d.cfg.BaseDomain).Str("provisioner", d.cfg.ProvisionerMode).Msg("starting qm-api")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-quit:
		log.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}
	if inProcess != nil {
		// Let in-flight local runs finish their bookkeeping.
		inProcess.Wait()
	}
	log.Info().Msg("qm-api stopped")
	return nil
}

// runProvision is the Cloud Run Job entrypoint. Exit status is the run's:
// non-zero on a failed step, or when the tenant lock is still held once
// runWithLockRetry has waited it out (so Cloud Run retries this execution
// rather than the intent being left with nothing behind it); zero when the
// tenant has moved on to a newer attempt (nothing to do, nothing wrong).
func runProvision(args []string) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	teamArg := fs.String("team", "", "team id the tenant belongs to")
	tenantArg := fs.String("tenant", "", "tenant id")
	modeArg := fs.String("mode", string(provisioner.ModeProvision), "provision or deprovision")
	// The seq of the intent event that queued this run. qm-api always sends
	// it; 0 (the default) skips the check, for running the job by hand.
	attemptArg := fs.Int64("attempt", 0, "seq of the intent event this run was queued by")
	if err := fs.Parse(args); err != nil {
		return err
	}
	teamID, err := uuid.Parse(*teamArg)
	if err != nil {
		return fmt.Errorf("--team: %w", err)
	}
	tenantID, err := uuid.Parse(*tenantArg)
	if err != nil {
		return fmt.Errorf("--tenant: %w", err)
	}
	mode, ok := provisioner.ParseMode(*modeArg)
	if !ok {
		return fmt.Errorf("--mode must be %s or %s", provisioner.ModeProvision, provisioner.ModeDeprovision)
	}

	// SIGTERM (job cancellation) cancels the run; the runner records the
	// interrupted step as failed so a retry resumes there.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	d, err := setup(ctx)
	if d != nil {
		defer d.close()
	}
	if err != nil {
		// The API already moved the tenant in flight for this run; with the
		// database reachable, leave it retryable rather than stuck. (With
		// the database itself down nothing can be recorded, and the API's
		// stale-run reclaim covers that case.)
		if d != nil {
			provisioner.RecordSetupFailure(ctx, d.store, log.Logger, teamID, tenantID, mode, *attemptArg, err)
		}
		return err
	}
	defer sentry.Flush(2 * time.Second)

	err = runWithLockRetry(ctx, tenantID, func() error {
		return d.runner.Run(ctx, teamID, tenantID, mode, *attemptArg)
	})
	switch {
	case err == nil:
		log.Info().Str("tenant_id", tenantID.String()).Str("mode", string(mode)).Msg("run complete")
		return nil
	case errors.Is(err, provisioner.ErrStaleRun):
		log.Info().Str("tenant_id", tenantID.String()).Msg("tenant is no longer queued for this mode; exiting")
		return nil
	default:
		return err
	}
}

// runWithLockRetry waits out a held tenant lock rather than accepting it as
// done: the holder may be a superseded execution that started a moment
// earlier and is about to exit on its own attempt check, and giving up on
// the first ErrLocked would leave the intent this execution was started for
// with nothing behind it until the stale reclaim.
//
// If the lock is still held once the wait is exhausted, ErrLocked is
// returned rather than swallowed. A wait long enough to usually outlast a
// superseded execution is not long enough to guarantee it — Postgres or the
// network can stall past it — so the caller must not treat a still-locked
// tenant as success: that would leave the intent this execution was queued
// for with nothing behind it (the true holder, if there is one, is working
// a different attempt) until the stale reclaim. Returning the error instead
// makes this job execution fail, which Cloud Run retries; a retry that
// finds the lock free (or the attempt now stale) resolves cleanly, and one
// that finds it still held tries again at Cloud Run's own pace.
func runWithLockRetry(ctx context.Context, tenantID uuid.UUID, attempt func() error) error {
	var err error
	for i := 0; ; i++ {
		err = attempt()
		if !errors.Is(err, tenantstore.ErrLocked) {
			return err
		}
		if i == lockedRunRetries {
			log.Warn().Str("tenant_id", tenantID.String()).Msg("gave up waiting for the tenant lock; leaving this execution retryable")
			return err
		}
		log.Info().Str("tenant_id", tenantID.String()).Int("attempt", i+1).Msg("tenant is locked; waiting for the holder to release it")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockedRunBackoff):
		}
	}
}

// How long a job waits out a tenant lock before leaving this execution
// retryable. A superseded execution releases within a query or two; a real
// run holds it for its whole life, which no wait here would outlast.
//
// Vars rather than consts so tests can shrink lockedRunBackoff instead of
// spending real wall-clock time waiting out a fake lock.
var (
	lockedRunRetries = 5
	lockedRunBackoff = 2 * time.Second
)
