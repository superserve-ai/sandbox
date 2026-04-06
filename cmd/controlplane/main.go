// Command controlplane starts the Superserve Sandbox control plane API server.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	// Connect to PostgreSQL.
	ctx := context.Background()
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
	router := api.SetupRouter(handlers, dbPool)

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

func (c *grpcVMDClient) CreateInstance(ctx context.Context, vmID string, vcpu, memMiB, diskMiB uint32, metadata map[string]string) (string, error) {
	resp, err := c.client.CreateVM(ctx, &vmdpb.CreateVMRequest{
		VmId:     vmID,
		Metadata: metadata,
		ResourceLimits: &vmdpb.ResourceLimits{
			VcpuCount:   vcpu,
			MemoryMib:   memMiB,
			DiskSizeMib: diskMiB,
		},
	})
	if err != nil {
		return "", fmt.Errorf("gRPC CreateVM: %w", err)
	}
	return resp.IpAddress, nil
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

func (c *grpcVMDClient) ResumeInstance(ctx context.Context, vmID, snapshotPath, memPath string) (string, error) {
	resp, err := c.client.ResumeVM(ctx, &vmdpb.ResumeVMRequest{
		VmId:         vmID,
		SnapshotPath: snapshotPath,
		MemFilePath:  memPath,
	})
	if err != nil {
		return "", fmt.Errorf("gRPC ResumeVM: %w", err)
	}
	return resp.IpAddress, nil
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

func (c *grpcVMDClient) UploadFile(ctx context.Context, vmID, path string, content io.Reader) (int64, error) {
	stream, err := c.client.UploadFile(ctx)
	if err != nil {
		return 0, fmt.Errorf("gRPC UploadFile: %w", err)
	}

	buf := make([]byte, 64*1024)
	first := true
	for {
		n, readErr := content.Read(buf)
		if n > 0 || first {
			msg := &vmdpb.UploadFileRequest{Data: buf[:n]}
			if first {
				msg.VmId = vmID
				msg.Path = path
				first = false
			}
			if err := stream.Send(msg); err != nil {
				return 0, fmt.Errorf("gRPC UploadFile send: %w", err)
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return 0, fmt.Errorf("gRPC UploadFile read content: %w", readErr)
			}
			break
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return 0, fmt.Errorf("gRPC UploadFile close: %w", err)
	}
	return resp.BytesWritten, nil
}

func (c *grpcVMDClient) DownloadFile(ctx context.Context, vmID, path string) (io.ReadCloser, error) {
	streamCtx, streamCancel := context.WithCancel(ctx)

	stream, err := c.client.DownloadFile(streamCtx, &vmdpb.DownloadFileRequest{
		VmId: vmID,
		Path: path,
	})
	if err != nil {
		streamCancel()
		return nil, fmt.Errorf("gRPC DownloadFile: %w", err)
	}

	first, err := stream.Recv()
	if err != nil {
		streamCancel()
		if err == io.EOF {
			return io.NopCloser(strings.NewReader("")), nil
		}
		return nil, fmt.Errorf("gRPC DownloadFile: %w", err)
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer streamCancel()
		if len(first.Data) > 0 {
			if _, err := pw.Write(first.Data); err != nil {
				return
			}
		}
		for {
			resp, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					pw.CloseWithError(fmt.Errorf("gRPC DownloadFile recv: %w", err))
				}
				return
			}
			if len(resp.Data) > 0 {
				if _, err := pw.Write(resp.Data); err != nil {
					return
				}
			}
		}
	}()

	return pr, nil
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
