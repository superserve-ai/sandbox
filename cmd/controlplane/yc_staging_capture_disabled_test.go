//go:build !yc_staging_validation

package main

import "testing"

func TestOrdinaryBuildCannotEnableYCStagingCapture(t *testing.T) {
	t.Setenv("YC_STAGING_VALIDATION_RUN_ID", "0123456789abcdef0123456789abcdef")
	t.Setenv("YC_STAGING_VALIDATION_EMAIL", "customer@example.test")
	t.Setenv("YC_STAGING_VALIDATION_EXPIRES_AT", "2099-01-01T00:00:00Z")
	t.Setenv("K_SERVICE", "superserve-api")
	state := newYCStagingCaptureVerifier(t.Context())
	if state.Verifier != nil || !state.Requested {
		t.Fatal("ordinary build activated a synthetic verifier")
	}
}
