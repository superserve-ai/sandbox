package vmdclient

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestOnlyExplicitPreBootRefusalIsReplaceable(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.ResourceExhausted} {
		if IsAdmissionRefusal(status.Error(code, "ambiguous")) {
			t.Fatal("generic failure accepted")
		}
		if !IsAdmissionRefusal(AdmissionRefused(code, "closed")) {
			t.Fatal("explicit refusal lost")
		}
	}
	if IsAdmissionRefusal(AdmissionRefused(codes.Internal, "unexpected")) {
		t.Fatal("invalid refusal code accepted")
	}
}
