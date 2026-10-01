package api

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A daemon refusal reaches the caller in the daemon's words, without the
// client's RPC wrapping around them.
func TestVMDErrorMessageUnwrapsTheClientPrefix(t *testing.T) {
	inner := status.Error(codes.FailedPrecondition, "the sandbox is paused; take a mem+fs snapshot")
	err := fmt.Errorf("gRPC CreateSavedSnapshot: %w", inner)
	if got := vmdErrorMessage(err); got != "the sandbox is paused; take a mem+fs snapshot" {
		t.Fatalf("message = %q", got)
	}
}
