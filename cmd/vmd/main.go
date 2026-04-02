package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/vm"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// Config holds the daemon configuration sourced from environment variables.
type Config struct {
	FirecrackerBin string
	JailerBin      string
	KernelPath     string
	BaseRootfsPath string
	SnapshotDir    string
	RunDir     string
	GRPCPort       int
	HostInterface  string
}

func loadConfig() (Config, error) {
	port, err := strconv.Atoi(envOrDefault("GRPC_PORT", "50051"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid GRPC_PORT: %w", err)
	}

	cfg := Config{
		FirecrackerBin: envOrDefault("FIRECRACKER_BIN", "/usr/local/bin/firecracker"),
		JailerBin:      envOrDefault("JAILER_BIN", "/usr/bin/jailer"),
		KernelPath:     requireEnv("KERNEL_PATH"),
		BaseRootfsPath: requireEnv("BASE_ROOTFS_PATH"),
		SnapshotDir:    envOrDefault("SNAPSHOT_DIR", "/var/lib/sandbox/snapshots"),
		RunDir:     envOrDefault("RUN_DIR", "/var/lib/sandbox/rundir"),
		GRPCPort:       port,
		HostInterface:  envOrDefault("HOST_INTERFACE", "eth0"),
	}

	if cfg.KernelPath == "" {
		return Config{}, fmt.Errorf("KERNEL_PATH environment variable is required")
	}
	if cfg.BaseRootfsPath == "" {
		return Config{}, fmt.Errorf("BASE_ROOTFS_PATH environment variable is required")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string) string {
	return os.Getenv(key)
}

func main() {
	// Structured logging with zerolog — unix timestamp, caller info enabled.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "vmd").
		Logger()

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	log.Info().
		Str("firecracker_bin", cfg.FirecrackerBin).
		Str("kernel_path", cfg.KernelPath).
		Int("grpc_port", cfg.GRPCPort).
		Msg("starting VM daemon")

	// Validate required system tools are available.
	for _, tool := range []string{"ip", "unshare", "sh", "mount", "cp", "iptables"} {
		if _, err := exec.LookPath(tool); err != nil {
			log.Fatal().Str("tool", tool).Msg("required system tool not found in PATH")
		}
	}

	// Ensure required directories exist.
	for _, dir := range []string{cfg.SnapshotDir, cfg.RunDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatal().Err(err).Str("dir", dir).Msg("failed to create directory")
		}
	}

	// Initialize the network manager.
	netMgr := network.NewManager(cfg.HostInterface, log)

	// Initialize the VM manager.
	mgr, err := vm.NewManager(vm.ManagerConfig{
		FirecrackerBin: cfg.FirecrackerBin,
		JailerBin:      cfg.JailerBin,
		KernelPath:     cfg.KernelPath,
		BaseRootfsPath: cfg.BaseRootfsPath,
		SnapshotDir:    cfg.SnapshotDir,
		RunDir:     cfg.RunDir,
	}, netMgr, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize VM manager")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Boot a throwaway VM from the base image, snapshot it, and keep the
	// snapshot on disk. Every subsequent CreateVM restores from this template
	// snapshot instead of cold-booting (~90-200ms vs ~933ms).
	if err := mgr.InitDefaultTemplate(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize default template")
	}

	// Start the gRPC server.
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		log.Fatal().Err(err).Int("port", cfg.GRPCPort).Msg("failed to listen")
	}

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(64<<20), // 64 MiB
	)
	vmdpb.RegisterVMDaemonServer(grpcServer, vm.NewGRPCAdapter(mgr))

	// Serve in a goroutine so we can handle shutdown signals.
	go func() {
		log.Info().Int("port", cfg.GRPCPort).Msg("gRPC server listening")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("gRPC server failed")
		}
	}()

	// Wait for termination signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("received shutdown signal")

	// Graceful shutdown: stop accepting new RPCs, drain in-flight requests.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Msg("gRPC server stopped gracefully")
	case <-shutdownCtx.Done():
		log.Warn().Msg("graceful shutdown timed out, forcing stop")
		grpcServer.Stop()
	}

	// Cancel background tasks, cleanup all active VMs, and remove template files.
	cancel()
	mgr.ShutdownAll()
	mgr.CleanupTemplate()

	log.Info().Msg("VM daemon shutdown complete")
}
