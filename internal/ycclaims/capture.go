package ycclaims

import (
	"context"
	"time"
)

type CaptureVerifier func(ctx context.Context, link, submittedEmail string) (Evidence, string, error)

type CaptureValidation struct {
	Requested bool
	Verifier  CaptureVerifier
	ExpiresAt time.Time
}

func ValidationRequested(lookup func(string) (string, bool)) bool {
	for _, key := range []string{"YC_STAGING_VALIDATION_RUN_ID", "YC_STAGING_VALIDATION_EMAIL", "YC_STAGING_VALIDATION_EXPIRES_AT", "YC_STAGING_VALIDATION_CLAIM_ID"} {
		if _, present := lookup(key); present {
			return true
		}
	}
	return false
}

func VerifyCapture(ctx context.Context, link, _ string) (Evidence, string, error) {
	return NewVerifier().Verify(ctx, link)
}
