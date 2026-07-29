package vm

import (
	"context"
	"errors"
	"testing"

	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func TestGRPCAdapterAdvertisesSavedSnapshotsCapability(t *testing.T) {
	mgr := &Manager{cfg: ManagerConfig{
		SnapshotDir:                "/var/lib/sandbox/snapshots",
		RunDir:                     "/run/sandbox",
		UffdEnabled:                true,
		ResumeUffdEnabled:          true,
		IncrementalSnapshotEnabled: true,
	}, savedSnapshotCapabilityProbe: func(context.Context) error { return nil }}
	resp, err := NewGRPCAdapter(mgr).GetCapabilities(context.Background(), &vmdpb.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	if !resp.GetSavedSnapshotsV1() {
		t.Fatal("saved_snapshots_v1 was not advertised")
	}
}

func TestGRPCAdapterDoesNotAdvertiseSavedSnapshotsWithoutRequiredHostFeatures(t *testing.T) {
	tests := []struct {
		name string
		mgr  *Manager
	}{
		{name: "nil manager"},
		{name: "unconfigured", mgr: &Manager{}},
		{name: "no incremental", mgr: &Manager{cfg: ManagerConfig{
			SnapshotDir:       "/var/lib/sandbox/snapshots",
			RunDir:            "/run/sandbox",
			UffdEnabled:       true,
			ResumeUffdEnabled: true,
		}}},
		{name: "reflink unsupported", mgr: &Manager{
			cfg: ManagerConfig{
				SnapshotDir:                "/var/lib/sandbox/snapshots",
				RunDir:                     "/run/sandbox",
				UffdEnabled:                true,
				ResumeUffdEnabled:          true,
				IncrementalSnapshotEnabled: true,
			},
			savedSnapshotCapabilityProbe: func(context.Context) error {
				return errors.New("reflink is unavailable")
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := (&GRPCAdapter{mgr: tt.mgr}).GetCapabilities(context.Background(), &vmdpb.GetCapabilitiesRequest{})
			if err != nil {
				t.Fatalf("GetCapabilities: %v", err)
			}
			if resp.GetSavedSnapshotsV1() {
				t.Fatal("saved_snapshots_v1 advertised without required host features")
			}
		})
	}
}
