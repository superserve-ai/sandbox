// Command controlplane starts the Superserve Sandbox control plane API server.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	dbq "github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/hostreg"
	"github.com/superserve-ai/sandbox/internal/scheduler"
	"github.com/superserve-ai/sandbox/internal/supervisor"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Caller().Logger()

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

	// Root context — cancelled on shutdown so background goroutines
	// (rate limiter cleanup, etc.) exit cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL.
	dbPool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer dbPool.Close()
	if err := dbPool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	log.Info().Msg("connected to database")

	// Connect to VMD via gRPC.
	grpcConn, err := grpc.NewClient(cfg.VMDAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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

	// Host registry: resolves host_id → VMDClient via DB lookup + gRPC dial.
	// Interceptors below fire onDead on codes.Unavailable so the registry
	// drops stale cached clients.
	dialVMD := func(addr string, onDead func()) (vmdclient.Client, error) {
		conn, err := grpc.NewClient(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
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
	).Start(ctx)

	// Launch the host health detector. Marks active hosts as unhealthy
	// when their VMD heartbeat goes stale (>2 min). The scheduler
	// excludes unhealthy hosts from placement.
	go api.StartHostDetector(ctx, queries)

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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	log.Info().Msg("shutting down HTTP server")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Info().Msg("controlplane stopped")
	return nil
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

func (c *grpcVMDClient) ResumeInstance(ctx context.Context, vmID, snapshotPath, memPath string, envVars map[string]string) (string, uint32, uint32, error) {
	resp, err := c.client.ResumeVM(ctx, &vmdpb.ResumeVMRequest{
		VmId:         vmID,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
		EnvVars:      envVars,
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
// instance from the snapshot files, bypassing any in-memory state. Used as
// a fallback when ResumeInstance returns NotFound (e.g. after VMD lost its
// map to a crash but the snapshot files are still on disk).
func (c *grpcVMDClient) RestoreSnapshot(ctx context.Context, vmID, snapshotPath, memPath string, envVars map[string]string) (string, uint32, uint32, error) {
	resp, err := c.client.RestoreSnapshot(ctx, &vmdpb.RestoreSnapshotRequest{
		VmId:         vmID,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
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

func (c *grpcVMDClient) ExecCommand(ctx context.Context, vmID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32) (string, string, int32, error) {
	stream, err := c.client.ExecCommand(ctx, &vmdpb.ExecCommandRequest{
		VmId:           vmID,
		Command:        command,
		Args:           args,
		Env:            env,
		WorkingDir:     workingDir,
		TimeoutSeconds: timeoutS,
	})
	if err != nil {
		return "", "", -1, fmt.Errorf("gRPC ExecCommand: %w", err)
	}

	var stdout, stderr []byte
	var exitCode int32
	for {
		resp, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", "", -1, fmt.Errorf("gRPC ExecCommand stream recv: %w", err)
		}
		stdout = append(stdout, resp.Stdout...)
		stderr = append(stderr, resp.Stderr...)
		if resp.Finished {
			exitCode = resp.ExitCode
			break
		}
	}
	return string(stdout), string(stderr), exitCode, nil
}

func (c *grpcVMDClient) ExecCommandStream(ctx context.Context, vmID, command string, args []string, env map[string]string, workingDir string, timeoutS uint32, onChunk func(stdout, stderr []byte, exitCode int32, finished bool)) error {
	stream, err := c.client.ExecCommand(ctx, &vmdpb.ExecCommandRequest{
		VmId:           vmID,
		Command:        command,
		Args:           args,
		Env:            env,
		WorkingDir:     workingDir,
		TimeoutSeconds: timeoutS,
	})
	if err != nil {
		return fmt.Errorf("gRPC ExecCommandStream: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("gRPC ExecCommandStream recv: %w", err)
		}
		onChunk(resp.Stdout, resp.Stderr, resp.ExitCode, resp.Finished)
		if resp.Finished {
			return nil
		}
	}
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
