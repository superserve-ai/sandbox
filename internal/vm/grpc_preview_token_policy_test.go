package vm

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func TestPreviewPortsFromProtoValidatesTokenizedSentinels(t *testing.T) {
	ports, err := previewPortsFromProto([]*vmdpb.PreviewPort{
		{Port: 3000, Access: preview.AccessPrivateTokenV1, TokenVersion: 9},
		{Port: 3001, Access: preview.AccessPrivate, TokenVersion: 12},
		{Port: 3002, Access: preview.AccessPublic, TokenVersion: -1},
		{Port: 3003, Access: preview.AccessPrivateBrowserV1, TokenVersion: 10},
	})
	if err != nil {
		t.Fatalf("previewPortsFromProto: %v", err)
	}
	if got := ports[3000]; got.Access != preview.AccessPrivateTokenV1 || got.TokenVersion != 9 {
		t.Fatalf("tokenized port = %+v, want sentinel generation 9", got)
	}
	if got := ports[3003]; got.Access != preview.AccessPrivateBrowserV1 || got.TokenVersion != 10 {
		t.Fatalf("browser-tokenized port = %+v, want browser sentinel generation 10", got)
	}
	for _, port := range []int32{3001, 3002} {
		if got := ports[port]; got.TokenVersion != 0 {
			t.Fatalf("non-token port %d retained generation: %+v", port, got)
		}
	}
}

func TestPreviewPortsFromProtoRejectsTokenizedSentinelsWithoutGeneration(t *testing.T) {
	for _, access := range []string{preview.AccessPrivateTokenV1, preview.AccessPrivateBrowserV1} {
		for _, version := range []int64{0, -1} {
			_, err := previewPortsFromProto([]*vmdpb.PreviewPort{{
				Port: 3000, Access: access, TokenVersion: version,
			}})
			if err == nil {
				t.Fatalf("access %q token version %d accepted", access, version)
			}
		}
	}
}

func TestGRPCRejectsTokenizedSentinelsWithoutPolicyRevision(t *testing.T) {
	for _, access := range []string{preview.AccessPrivateTokenV1, preview.AccessPrivateBrowserV1} {
		t.Run(access+" update", func(t *testing.T) {
			adapter := NewGRPCAdapter(&Manager{})
			_, err := adapter.UpdateSandboxPreviewPolicy(context.Background(), &vmdpb.UpdateSandboxPreviewPolicyRequest{
				VmId: "vm-token", PreviewAccess: preview.AccessPrivate,
				PreviewPorts: []*vmdpb.PreviewPort{{
					Port: 3000, Access: access, TokenVersion: 1,
				}},
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("status = %v, want InvalidArgument", status.Code(err))
			}
		})
		t.Run(access+" restore", func(t *testing.T) {
			adapter := NewGRPCAdapter(&Manager{})
			_, err := adapter.RestoreSnapshot(context.Background(), &vmdpb.RestoreSnapshotRequest{
				VmId: "vm-token", PreviewAccess: preview.AccessPrivate,
				PreviewPorts: []*vmdpb.PreviewPort{{
					Port: 3000, Access: access, TokenVersion: 1,
				}},
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("status = %v, want InvalidArgument", status.Code(err))
			}
		})
	}
}
