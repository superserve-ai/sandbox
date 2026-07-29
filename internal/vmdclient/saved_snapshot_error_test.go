package vmdclient

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSanitizeSavedSnapshotErrorRemovesPathsAndPreservesClassification(t *testing.T) {
	const hostPath = "/var/lib/superserve/private/snapshots/team/source/snapshot/mem.snap"
	original, err := status.New(codes.DataLoss, "read "+hostPath+": input/output error").WithDetails(&errdetails.ErrorInfo{
		Reason: SavedSnapshotSourceResumeFailureReason,
		Domain: "vmd.superserve.ai",
		Metadata: map[string]string{
			"artifact_path": hostPath,
		},
	})
	if err != nil {
		t.Fatalf("attach error details: %v", err)
	}

	got := SanitizeSavedSnapshotError(
		SavedSnapshotOperationCapture,
		fmt.Errorf("gRPC CreateSnapshot(saved): %w", original.Err()),
	)
	if status.Code(got) != codes.DataLoss {
		t.Fatalf("code = %s, want DataLoss (%v)", status.Code(got), got)
	}
	if !GRPCErrorHasReason(got, SavedSnapshotSourceResumeFailureReason) {
		t.Fatalf("stable reason was not preserved: %v", got)
	}
	if strings.Contains(got.Error(), hostPath) || strings.Contains(got.Error(), "artifact_path") {
		t.Fatalf("sanitized error exposed host artifact metadata: %v", got)
	}
	if !strings.Contains(got.Error(), "saved snapshot capture failed") {
		t.Fatalf("sanitized error lost operation context: %v", got)
	}
	for _, detail := range status.Convert(got).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && len(info.GetMetadata()) != 0 {
			t.Fatalf("sanitized ErrorInfo retained metadata: %+v", info.GetMetadata())
		}
	}
}

func TestSanitizeSavedSnapshotErrorMapsContextErrorsWithoutTheirText(t *testing.T) {
	got := SanitizeSavedSnapshotError(SavedSnapshotOperationDelete, fmt.Errorf("remove /private/artifact: %w", context.DeadlineExceeded))
	if status.Code(got) != codes.DeadlineExceeded {
		t.Fatalf("code = %s, want DeadlineExceeded (%v)", status.Code(got), got)
	}
	if strings.Contains(got.Error(), "/private/artifact") {
		t.Fatalf("sanitized context error exposed path: %v", got)
	}
}
