package vmdclient

import (
	"errors"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsPauseArtifactsMissing(t *testing.T) {
	marked, err := status.New(codes.FailedPrecondition, "gone").WithDetails(&errdetails.ErrorInfo{Reason: PauseArtifactsMissingReason})
	if err != nil {
		t.Fatal(err)
	}
	if !IsPauseArtifactsMissing(marked.Err()) {
		t.Fatal("a marked precondition failure must be recognized")
	}
	if IsPauseArtifactsMissing(status.Error(codes.FailedPrecondition, "other precondition")) {
		t.Fatal("an unmarked precondition failure must not be")
	}
	if IsPauseArtifactsMissing(errors.New("plain")) || IsPauseArtifactsMissing(nil) {
		t.Fatal("non-status errors must not be")
	}
}
