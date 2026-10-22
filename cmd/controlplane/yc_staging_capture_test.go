//go:build yc_staging_validation && !yc_verifier_fixture

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestYCStagingCaptureTarget(t *testing.T) {
	for _, tc := range []struct {
		name, run, service, project string
		projectErr                  error
		wantEnabled                 bool
		wantCalls                   int
	}{
		{"unconfigured", "", stagingCaptureService, stagingCaptureProject, nil, false, 0},
		{"invalid run", "guessable", stagingCaptureService, stagingCaptureProject, nil, false, 0},
		{"wrong service", "0123456789abcdef0123456789abcdef", "other-service", stagingCaptureProject, nil, false, 0},
		{"wrong project", "0123456789abcdef0123456789abcdef", stagingCaptureService, "other-project", nil, false, 1},
		{"unavailable", "0123456789abcdef0123456789abcdef", stagingCaptureService, "", errors.New("unavailable"), false, 1},
		{"staging", "0123456789abcdef0123456789abcdef", stagingCaptureService, stagingCaptureProject, nil, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]string{"YC_STAGING_VALIDATION_RUN_ID": tc.run, "K_SERVICE": tc.service,
				"YC_STAGING_VALIDATION_EMAIL": "customer@example.test", "YC_STAGING_VALIDATION_EXPIRES_AT": time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)}
			calls := 0
			got := configuredYCStagingCapture(t.Context(), func(k string) (string, bool) { v, ok := values[k]; return v, ok }, func(ctx context.Context) (string, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second {
					t.Fatal("unbounded startup metadata request")
				}
				return tc.project, tc.projectErr
			})
			if (got.Verifier != nil) != tc.wantEnabled || calls != tc.wantCalls || !got.Requested {
				t.Fatalf("enabled=%v requested=%v metadata calls=%d", got.Verifier != nil, got.Requested, calls)
			}
			if got.Verifier != nil {
				for range 2 {
					if _, _, err := got.Verifier(t.Context(), "https://www.ycombinator.com/verify/staging-"+tc.run, values["YC_STAGING_VALIDATION_EMAIL"]); err != nil {
						t.Fatal(err)
					}
				}
				if calls != 1 {
					t.Fatal("request repeated cloud identity lookup")
				}
			}
		})
	}
}
