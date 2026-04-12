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
	"google.golang.org/grpc/credentials/insecure"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	dbq "github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/hostreg"
	"github.com/superserve-ai/sandbox/internal/scheduler"
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

	// Host registry: resolves host_id → VMDClient via DB lookup + gRPC dial.
	// Falls back to the default vmdClient when the registry has no entry.
	dialVMD := func(addr string) (vmdclient.Client, error) {
		conn, err := grpc.NewClient(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
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

func (c *grpcVMDClient) CreateInstance(ctx context.Context, vmID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string, envVars map[string]string) (string, uint32, uint32, error) {
	resp, err := c.client.CreateVM(ctx, &vmdpb.CreateVMRequest{
		VmId:     vmID,
		Metadata: metadata,
		EnvVars:  envVars,
		ResourceLimits: &vmdpb.ResourceLimits{
			VcpuCount:   vcpu,
			MemoryMib:   memMiB,
			DiskSizeMib: diskMiB,
		},
	})
	if err != nil {
		return "", 0, 0, fmt.Errorf("gRPC CreateVM: %w", err)
	}
	var actualVcpu, actualMemMiB uint32
	if rl := resp.GetResourceLimits(); rl != nil {
		actualVcpu = rl.GetVcpuCount()
		actualMemMiB = rl.GetMemoryMib()
	}
	return resp.IpAddress, actualVcpu, actualMemMiB, nil
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
func (c *grpcVMDClient) RestoreSnapshot(ctx context.Context, vmID, snapshotPath, memPath string) (string, uint32, uint32, error) {
	resp, err := c.client.RestoreSnapshot(ctx, &vmdpb.RestoreSnapshotRequest{
		VmId:         vmID,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
	})
	if err != nil {
		return "", 0, 0, fmt.Errorf("gRPC RestoreSnapshot: %w", err)
	}
	// RestoreSnapshotResponse doesn't carry ResourceLimits in the proto today,
	// so we return 0,0 and let the caller keep the existing DB values.
	return resp.IpAddress, 0, 0, nil
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
