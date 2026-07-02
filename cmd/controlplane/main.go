// Command controlplane starts the Superserve Sandbox control plane API server.
package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/analytics"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	dbq "github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/hostreg"
	"github.com/superserve-ai/sandbox/internal/scheduler"
	"github.com/superserve-ai/sandbox/internal/secrets"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/supervisor"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// vmdRetryServiceConfig retries on UNAVAILABLE only — gRPC guarantees
// such requests never reached the server, so create RPCs can't
// double-execute. Other codes lack this guarantee.
const vmdRetryServiceConfig = `{
  "methodConfig": [{
    "name": [{"service": "superserve.vmd.v1.VMDaemon"}],
    "retryPolicy": {
      "maxAttempts": 5,
      "initialBackoff": "0.2s",
      "maxBackoff": "2s",
      "backoffMultiplier": 2.0,
      "retryableStatusCodes": ["UNAVAILABLE"]
    }
  }]
}`

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	multi := zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
		&sentrylog.Writer{},
	)
	log.Logger = zerolog.New(multi).With().Timestamp().Caller().Logger()

	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("controlplane exited with error")
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log.Info().Str("port", cfg.Port).Str("vmd_address", cfg.VMDAddress).Msg("configuration loaded")

	// Fail closed on a malformed SANDBOX_ID_REGION rather than minting
	// public sandbox IDs the API and proxy would reject.
	if err := api.ValidateSandboxIDRegion(); err != nil {
		return err
	}

	if cfg.SentryDSN != "" {
		if err := sentry.Init(sentry.ClientOptions{Dsn: cfg.SentryDSN, EnableLogs: true}); err != nil {
			return fmt.Errorf("sentry init: %w", err)
		}
		defer sentry.Flush(2 * time.Second)
		log.Info().Msg("sentry initialized")
	}

	// Root context — cancelled on shutdown so background goroutines
	// (rate limiter cleanup, etc.) exit cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL. DB_MAX_CONNS overrides the pool size; unset
	// uses the pgxpool default of max(4, NumCPU).
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	// Supabase's transaction pooler (PgBouncer) does not preserve named
	// prepared statements across transactions — connections are swapped between
	// clients, so a statement prepared on backend B1 is gone on B2. CacheDescribe
	// uses unnamed prepared statements (which don't persist) while still using
	// the extended protocol for typed/binary parameter encoding.
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	if v := os.Getenv("DB_MAX_CONNS"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			poolCfg.MaxConns = int32(n)
		}
	}
	dbPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer dbPool.Close()
	if err := dbPool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	log.Info().Msg("connected to database")

	reconcileSystemTeamQuota(ctx, dbPool, cfg.SystemTeamID)

	// Connect to VMD via gRPC.
	grpcConn, err := grpc.NewClient(cfg.VMDAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(vmdRetryServiceConfig),
	)
	if err != nil {
		return fmt.Errorf("dial VMD gRPC: %w", err)
	}
	defer grpcConn.Close()
	log.Info().Str("address", cfg.VMDAddress).Msg("connected to VMD gRPC")

	// Build handlers and router.
	vmdClient := newGRPCVMDClient(grpcConn)
	queries := dbq.New(dbPool)

	handlers := api.NewHandlers(vmdClient, queries, cfg)
	handlers.Pool = dbPool

	// Product-usage analytics — no-op when POSTHOG_KEY is unset.
	analyticsClient, err := analytics.New(os.Getenv("POSTHOG_KEY"), os.Getenv("POSTHOG_HOST"), log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("init analytics")
	}
	defer analyticsClient.Close()
	handlers.Analytics = analyticsClient

	// /secrets endpoints require KMS_KEY_RESOURCE; otherwise they remain disabled.
	if cfg.KMSKeyResource != "" {
		kmsClient, kerr := kms.NewKeyManagementClient(ctx)
		if kerr != nil {
			log.Warn().Err(kerr).Msg("KMS init failed; /secrets endpoints disabled")
		} else {
			handlers.Encryptor = secrets.NewKMSEncryptor(kmsClient, cfg.KMSKeyResource)
			log.Info().Str("kek", cfg.KMSKeyResource).Msg("KMS encryptor wired for /secrets")
		}
	} else {
		log.Info().Msg("KMS_KEY_RESOURCE empty; /secrets endpoints disabled")
	}

	// Sandbox JWT signer requires SECRETS_SIGNING_KEY; empty disables minting.
	if cfg.SecretsSigningKey != "" {
		signer, serr := api.NewSecretsSigner(cfg.SecretsSigningKey, cfg.SecretsSigningKeyID)
		if serr != nil {
			log.Warn().Err(serr).Msg("SECRETS_SIGNING_KEY init failed; JWT signing disabled")
		} else {
			handlers.Signer = signer
			log.Info().Str("kid", cfg.SecretsSigningKeyID).Msg("JWT signer wired for /internal/jwks and sandbox secrets")
		}
	} else {
		log.Info().Msg("SECRETS_SIGNING_KEY empty; JWT signing disabled (sandboxes with `secrets:` will fail)")
	}

	// Host registry: resolves host_id → VMDClient via DB lookup + gRPC dial.
	// Interceptors below fire onDead on codes.Unavailable so the registry
	// drops stale cached clients.
	dialVMD := func(addr string, onDead func()) (vmdclient.Client, error) {
		// Retry runs inside the invoker; the dead-host interceptor sees the post-retry outcome only.
		conn, err := grpc.NewClient(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultServiceConfig(vmdRetryServiceConfig),
			grpc.WithUnaryInterceptor(deadHostUnaryInterceptor(onDead)),
			grpc.WithStreamInterceptor(deadHostStreamInterceptor(onDead)),
		)
		if err != nil {
			return nil, err
		}
		return newGRPCVMDClient(conn), nil
	}
	handlers.Hosts = hostreg.New(queries, dialVMD)
	handlers.Scheduler = &scheduler.LeastLoaded{DB: queries, DefaultHostID: cfg.DefaultHostID}

	router := api.SetupRouter(ctx, handlers, dbPool)

	// Launch the timeout reaper. This goroutine destroys sandboxes whose
	// `timeout_seconds` hard cap has elapsed, regardless of state. Scoped
	// to ctx so it exits on shutdown.
	handlers.StartTimeoutReaper(ctx, api.DefaultReaperConfig())

	// Launch the template build supervisor. Drives template_build rows
	// through pending → building → snapshotting → ready/failed by calling
	// vmd's BuildTemplate / GetBuildStatus / CancelBuild RPCs.
	buildResolver := func(rctx context.Context, hostID string) (vmdclient.Client, error) {
		if hostID == "" || handlers.Hosts == nil {
			return vmdClient, nil
		}
		c, err := handlers.Hosts.ClientFor(rctx, hostID)
		if err != nil {
			log.Warn().Err(err).Str("host_id", hostID).Msg("supervisor: host lookup failed, using default client")
			return vmdClient, nil
		}
		return c, nil
	}
	supervisor.NewBuildSupervisor(
		supervisor.DefaultBuildSupervisorConfig(cfg.DefaultHostID),
		queries,
		buildResolver,
	).WithAnalytics(analyticsClient).Start(ctx)

	// Launch the host health detector. Marks active hosts as unhealthy
	// when their VMD heartbeat goes stale (>2 min). The scheduler
	// excludes unhealthy hosts from placement.
	go api.StartHostDetector(ctx, queries)

	// Billing dashboard rollups are provisional and recomputable from raw
	// interval rows. Team-level feature flags decide which tenants roll up.
	if billing.HourlyRollupDisabledFromEnv() {
		log.Info().Msg("billing hourly rollup worker disabled (BILLING_HOURLY_ROLLUP_DISABLED set)")
	} else {
		billing.StartHourlyRollupService(ctx, dbPool, queries, billing.DefaultHourlyRollupConfig())
	}

	// Quota watcher: alerts when a team crosses 80% of a resource limit. Fans out
	// to a Slack webhook and an email notifier; each channel is independently
	// gated on its config and skipped when unset.
	var quotaNotifiers []api.QuotaNotifier
	if webhook := os.Getenv("SLACK_QUOTA_ALERT_WEBHOOK"); webhook != "" {
		quotaNotifiers = append(quotaNotifiers, api.NewSlackQuotaNotifier(webhook))
	}
	if apiKey, from := os.Getenv("RESEND_API_KEY"), os.Getenv("QUOTA_EMAIL_FROM"); apiKey != "" && from != "" {
		quotaNotifiers = append(quotaNotifiers, api.NewEmailQuotaNotifier(apiKey, from, queries))
	}
	if len(quotaNotifiers) > 0 {
		go api.StartQuotaWatcher(ctx, queries, quotaNotifiers)
	} else {
		log.Info().Msg("quota watcher disabled (no SLACK_QUOTA_ALERT_WEBHOOK or RESEND_API_KEY/QUOTA_EMAIL_FROM)")
	}

	// Start HTTP server.
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0, // 0 = no timeout; required for streaming exec responses
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("addr", srv.Addr).Msg("starting HTTP server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for shutdown signal.
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

	// Stop background reconcilers before draining HTTP so they don't keep
	// issuing DB queries (which time out and log as errors) while shutting down.
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	log.Info().Msg("shutting down HTTP server")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Info().Msg("controlplane stopped")
	return nil
}

// reconcileSystemTeamQuota lifts the system team's max_sandboxes and
// max_templates so the quota trigger and template-count check never block it.
func reconcileSystemTeamQuota(ctx context.Context, pool *pgxpool.Pool, systemTeamID string) {
	if systemTeamID == "" {
		return
	}
	tag, err := pool.Exec(ctx,
		`UPDATE team
		 SET max_sandboxes = $1,
		     max_templates = $1
		 WHERE id = $2
		   AND (max_sandboxes IS NULL OR max_sandboxes < $1
		     OR max_templates IS NULL OR max_templates < $1)`,
		math.MaxInt32, systemTeamID,
	)
	if err != nil {
		log.Warn().Err(err).Str("system_team_id", systemTeamID).
			Msg("reconcile system team quota failed — system team may be capped at default")
		return
	}
	log.Info().Str("system_team_id", systemTeamID).Int64("rows", tag.RowsAffected()).
		Msg("system team quota reconciled")
}

// ---------------------------------------------------------------------------
// gRPC VMD Client Adapter
// ---------------------------------------------------------------------------

type grpcVMDClient struct {
	conn   *grpc.ClientConn
	client vmdpb.VMDaemonClient
}

func newGRPCVMDClient(conn *grpc.ClientConn) *grpcVMDClient {
	return &grpcVMDClient{
		conn:   conn,
		client: vmdpb.NewVMDaemonClient(conn),
	}
}

func (c *grpcVMDClient) DestroyInstance(ctx context.Context, vmID string, force bool) error {
	_, err := c.client.DestroyVM(ctx, &vmdpb.DestroyVMRequest{
		VmId:  vmID,
		Force: force,
	})
	if err != nil {
		return fmt.Errorf("gRPC DestroyVM: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) PauseInstance(ctx context.Context, vmID, snapshotDir string) (string, string, error) {
	resp, err := c.client.PauseVM(ctx, &vmdpb.PauseVMRequest{
		VmId:        vmID,
		SnapshotDir: snapshotDir,
	})
	if err != nil {
		return "", "", fmt.Errorf("gRPC PauseVM: %w", err)
	}
	return resp.SnapshotPath, resp.MemFilePath, nil
}

func (c *grpcVMDClient) ResumeInstance(ctx context.Context, vmID, snapshotPath, memPath string) (string, uint32, uint32, error) {
	resp, err := c.client.ResumeVM(ctx, &vmdpb.ResumeVMRequest{
		VmId:         vmID,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
	})
	if err != nil {
		return "", 0, 0, fmt.Errorf("gRPC ResumeVM: %w", err)
	}
	var actualVcpu, actualMemMiB uint32
	if rl := resp.GetResourceLimits(); rl != nil {
		actualVcpu = rl.GetVcpuCount()
		actualMemMiB = rl.GetMemoryMib()
	}
	return resp.IpAddress, actualVcpu, actualMemMiB, nil
}

// RestoreSnapshot is the stateless restore path — VMD creates a fresh VM
// instance from the snapshot files, bypassing any in-memory state. For
// sandboxes with secrets the caller passes envVars=nil and pushes env via
// InjectSandboxEnv after minting a JWT against the returned source IP.
func (c *grpcVMDClient) RestoreSnapshot(ctx context.Context, vmID, snapshotPath, memPath, basePath, deltaDir, teamID, ownerID string, envVars map[string]string) (string, uint32, uint32, error) {
	resp, err := c.client.RestoreSnapshot(ctx, &vmdpb.RestoreSnapshotRequest{
		VmId:         vmID,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
		BasePath:     basePath,
		DeltaDir:     deltaDir,
		TeamId:       teamID,
		OwnerId:      ownerID,
		EnvVars:      envVars,
	})
	if err != nil {
		return "", 0, 0, fmt.Errorf("gRPC RestoreSnapshot: %w", err)
	}
	var vcpu, mem uint32
	if rl := resp.GetResourceLimits(); rl != nil {
		vcpu = rl.GetVcpuCount()
		mem = rl.GetMemoryMib()
	}
	return resp.IpAddress, vcpu, mem, nil
}

func (c *grpcVMDClient) InjectSandboxEnv(ctx context.Context, vmID string, envVars map[string]string, secretsJWT string) error {
	_, err := c.client.InjectSandboxEnv(ctx, &vmdpb.InjectSandboxEnvRequest{
		VmId:       vmID,
		EnvVars:    envVars,
		SecretsJwt: secretsJWT,
	})
	if err != nil {
		return fmt.Errorf("gRPC InjectSandboxEnv: %w", err)
	}
	return nil
}

// DeleteSnapshot removes the on-disk snapshot artifacts for a previous pause.
// Idempotent — VMD treats missing files as success. Path traversal is blocked
// VMD-side, so the control plane cannot use this to delete unrelated files.
func (c *grpcVMDClient) DeleteSnapshot(ctx context.Context, vmID, snapshotPath, memPath string) error {
	_, err := c.client.DeleteSnapshot(ctx, &vmdpb.DeleteSnapshotRequest{
		VmId:         vmID,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
	})
	if err != nil {
		return fmt.Errorf("gRPC DeleteSnapshot: %w", err)
	}
	return nil
}

// DeleteSandboxSnapshots removes a sandbox's entire on-disk snapshot directory.
// Idempotent; path traversal and reserved names are blocked VMD-side.
func (c *grpcVMDClient) DeleteSandboxSnapshots(ctx context.Context, vmID string) error {
	_, err := c.client.DeleteSandboxSnapshots(ctx, &vmdpb.DeleteSandboxSnapshotsRequest{VmId: vmID})
	if err != nil {
		return fmt.Errorf("gRPC DeleteSandboxSnapshots: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) ListBuildArtifacts(ctx context.Context) ([]vmdclient.BuildArtifactEntry, error) {
	resp, err := c.client.ListBuildArtifacts(ctx, &vmdpb.ListBuildArtifactsRequest{})
	if err != nil {
		return nil, fmt.Errorf("gRPC ListBuildArtifacts: %w", err)
	}
	out := make([]vmdclient.BuildArtifactEntry, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		out = append(out, vmdclient.BuildArtifactEntry{
			TemplateID: e.GetTemplateId(),
			BuildID:    e.GetBuildId(),
			MTimeUnix:  e.GetMtimeUnix(),
		})
	}
	return out, nil
}

func (c *grpcVMDClient) ListDir(ctx context.Context, instanceID, path string) ([]vmdclient.DirEntry, error) {
	resp, err := c.client.ListDir(ctx, &vmdpb.ListDirRequest{VmId: instanceID, Path: path})
	if err != nil {
		return nil, fmt.Errorf("gRPC ListDir: %w", err)
	}
	out := make([]vmdclient.DirEntry, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		out = append(out, vmdclient.DirEntry{
			Name:         e.GetName(),
			IsDir:        e.GetIsDir(),
			Size:         e.GetSize(),
			ModifiedUnix: e.GetModifiedUnix(),
		})
	}
	return out, nil
}

func (c *grpcVMDClient) DeleteBuildArtifacts(ctx context.Context, templateID, buildID string) error {
	_, err := c.client.DeleteBuildArtifacts(ctx, &vmdpb.DeleteBuildArtifactsRequest{
		TemplateId: templateID,
		BuildId:    buildID,
	})
	if err != nil {
		return fmt.Errorf("gRPC DeleteBuildArtifacts: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) DeleteTemplateArtifacts(ctx context.Context, templateID string) error {
	_, err := c.client.DeleteTemplateArtifacts(ctx, &vmdpb.DeleteTemplateArtifactsRequest{
		TemplateId: templateID,
	})
	if err != nil {
		return fmt.Errorf("gRPC DeleteTemplateArtifacts: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) UpdateSandboxNetwork(ctx context.Context, vmID string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error {
	_, err := c.client.UpdateSandboxNetwork(ctx, &vmdpb.UpdateSandboxNetworkRequest{
		VmId: vmID,
		Egress: &vmdpb.SandboxNetworkEgressConfig{
			AllowedCidrs:   allowedCIDRs,
			DeniedCidrs:    deniedCIDRs,
			AllowedDomains: allowedDomains,
		},
	})
	if err != nil {
		return fmt.Errorf("gRPC UpdateSandboxNetwork: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) InvalidateSecret(ctx context.Context, secretID string) error {
	_, err := c.client.InvalidateSecret(ctx, &vmdpb.InvalidateSecretRequest{SecretId: secretID})
	if err != nil {
		return fmt.Errorf("gRPC InvalidateSecret: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) RevokeSandbox(ctx context.Context, sandboxID string) error {
	_, err := c.client.RevokeSandbox(ctx, &vmdpb.RevokeSandboxRequest{SandboxId: sandboxID})
	if err != nil {
		return fmt.Errorf("gRPC RevokeSandbox: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) InvalidateSandboxRules(ctx context.Context, sandboxID string) error {
	_, err := c.client.InvalidateSandboxRules(ctx, &vmdpb.InvalidateSandboxRulesRequest{SandboxId: sandboxID})
	if err != nil {
		return fmt.Errorf("gRPC InvalidateSandboxRules: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) BuildTemplate(ctx context.Context, req vmdclient.BuildTemplateInput) (string, error) {
	pbReq := &vmdpb.BuildTemplateRequest{
		TemplateId: req.TemplateID,
		From:       req.From,
		StartCmd:   req.StartCmd,
		ReadyCmd:   req.ReadyCmd,
		Vcpu:       req.VCPU,
		MemoryMib:  req.MemoryMiB,
		DiskMib:    req.DiskMiB,
		BuildVmId:  req.BuildVMID,
	}
	for _, step := range req.Steps {
		pstep := &vmdpb.BuildStep{}
		switch {
		case step.Run != nil:
			pstep.Op = &vmdpb.BuildStep_Run{Run: *step.Run}
		case step.Env != nil:
			pstep.Op = &vmdpb.BuildStep_Env{Env: &vmdpb.BuildEnvOp{Key: step.Env.Key, Value: step.Env.Value}}
		case step.Workdir != nil:
			pstep.Op = &vmdpb.BuildStep_Workdir{Workdir: *step.Workdir}
		case step.User != nil:
			pstep.Op = &vmdpb.BuildStep_User{User: &vmdpb.BuildUserOp{Name: step.User.Name, Sudo: step.User.Sudo}}
		}
		pbReq.Steps = append(pbReq.Steps, pstep)
	}
	resp, err := c.client.BuildTemplate(ctx, pbReq)
	if err != nil {
		return "", fmt.Errorf("gRPC BuildTemplate: %w", err)
	}
	return resp.GetBuildVmId(), nil
}

func (c *grpcVMDClient) GetBuildStatus(ctx context.Context, buildVMID string) (vmdclient.BuildStatusResult, error) {
	resp, err := c.client.GetBuildStatus(ctx, &vmdpb.GetBuildStatusRequest{BuildVmId: buildVMID})
	if err != nil {
		return vmdclient.BuildStatusResult{}, fmt.Errorf("gRPC GetBuildStatus: %w", err)
	}
	return vmdclient.BuildStatusResult{
		NotFound:       resp.GetNotFound(),
		Status:         resp.GetStatus(),
		SnapshotPath:   resp.GetSnapshotPath(),
		MemFilePath:    resp.GetMemFilePath(),
		RootfsPath:     resp.GetRootfsPath(),
		BasePath:       resp.GetBasePath(),
		DeltaPath:      resp.GetDeltaPath(),
		ResolvedDigest: resp.GetResolvedDigest(),
		SizeBytes:      resp.GetSizeBytes(),
		ErrorMessage:   resp.GetErrorMessage(),
		StartedAtUnix:  resp.GetStartedAtUnix(),
		EndedAtUnix:    resp.GetEndedAtUnix(),
	}, nil
}

func (c *grpcVMDClient) CancelBuild(ctx context.Context, buildVMID string) error {
	_, err := c.client.CancelBuild(ctx, &vmdpb.CancelBuildRequest{BuildVmId: buildVMID})
	if err != nil {
		return fmt.Errorf("gRPC CancelBuild: %w", err)
	}
	return nil
}

func (c *grpcVMDClient) StreamBuildLogs(ctx context.Context, buildVMID string, onEvent func(vmdclient.BuildLogEvent) error) error {
	stream, err := c.client.StreamBuildLogs(ctx, &vmdpb.StreamBuildLogsRequest{BuildVmId: buildVMID})
	if err != nil {
		return fmt.Errorf("gRPC StreamBuildLogs: %w", err)
	}
	for {
		pbEv, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("recv build log: %w", err)
		}
		if cbErr := onEvent(vmdclient.BuildLogEvent{
			TimestampUnixNanos: pbEv.GetTimestampUnixNanos(),
			Stream:             pbEv.GetStream(),
			Text:               pbEv.GetText(),
			Finished:           pbEv.GetFinished(),
			Status:             pbEv.GetStatus(),
		}); cbErr != nil {
			return cbErr
		}
		if pbEv.GetFinished() {
			return nil
		}
	}
}

// deadHostUnaryInterceptor calls onDead when a unary RPC returns
// codes.Unavailable.
func deadHostUnaryInterceptor(onDead func()) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil && grpcstatus.Code(err) == grpccodes.Unavailable && onDead != nil {
			onDead()
		}
		return err
	}
}

// deadHostStreamInterceptor is the streaming counterpart.
func deadHostStreamInterceptor(onDead func()) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		cs, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			if grpcstatus.Code(err) == grpccodes.Unavailable && onDead != nil {
				onDead()
			}
			return nil, err
		}
		return &deadHostClientStream{ClientStream: cs, onDead: onDead}, nil
	}
}

type deadHostClientStream struct {
	grpc.ClientStream
	onDead func()
}

func (s *deadHostClientStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	if err != nil && grpcstatus.Code(err) == grpccodes.Unavailable && s.onDead != nil {
		s.onDead()
	}
	return err
}
