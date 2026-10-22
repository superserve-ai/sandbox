//go:build !yc_staging_validation

package main

import (
	"context"
	"os"

	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

func newYCStagingCaptureVerifier(context.Context) ycclaims.CaptureValidation {
	return ycclaims.CaptureValidation{Requested: ycclaims.ValidationRequested(os.LookupEnv)}
}
