package main

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/builder"
)

func TestDefaultWaitCoversQueueAndExecution(t *testing.T) {
	if defaultWaitDeadline <= 2*time.Minute+30*time.Minute {
		t.Fatal("seed wait must leave polling headroom beyond queue and execution deadlines")
	}
}

func TestDefaultResourcesMatchExplicitSeedInput(t *testing.T) {
	vcpu, memory, disk := resolvedResources(seedSpec{})
	explicitVCPU, explicitMemory, explicitDisk := int32(1), int32(1024), int32(4096)
	v, m, d := resolvedResources(seedSpec{Vcpu: &explicitVCPU, MemoryMib: &explicitMemory, DiskMib: &explicitDisk})
	if vcpu != v || memory != m || disk != d {
		t.Fatal("default and explicit resources differ")
	}
	raw := []byte(`{"from":"example/image:latest"}`)
	a, err := builder.InputHash(raw, vcpu, memory, disk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := builder.InputHash(raw, v, m, d)
	if err != nil || a != b {
		t.Fatalf("equivalent seed input differs: %v", err)
	}
}

func TestSeedWaitFailsCancellationFailureAndTimeout(t *testing.T) {
	for _, status := range []string{"ready", "failed", "cancelled", "pending"} {
		t.Run(status, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if status == "pending" {
				cancel()
			}
			failed := waitForBuildStatuses(ctx, []uuid.UUID{uuid.New()}, func(context.Context, uuid.UUID) (string, string, bool, error) {
				return status, "", status != "pending", nil
			})
			if (failed == 0) != (status == "ready") {
				t.Fatalf("status=%s failures=%d", status, failed)
			}
		})
	}
}
