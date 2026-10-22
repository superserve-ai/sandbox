//go:build yc_staging_validation && !yc_verifier_fixture

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

const stagingCaptureProject = "rayai-dev"
const stagingCaptureService = "superserve-api"

func newYCStagingCaptureVerifier(ctx context.Context) ycclaims.CaptureValidation {
	return configuredYCStagingCapture(ctx, os.LookupEnv, stagingMetadataProject)
}

func configuredYCStagingCapture(ctx context.Context, lookup func(string) (string, bool), project func(context.Context) (string, error)) ycclaims.CaptureValidation {
	state := ycclaims.CaptureValidation{Requested: ycclaims.ValidationRequested(lookup)}
	if !state.Requested {
		return state
	}
	env := func(k string) string { v, _ := lookup(k); return v }
	run := env("YC_STAGING_VALIDATION_RUN_ID")
	verifier, err := ycclaims.NewStagingCaptureVerifier(run, env("YC_STAGING_VALIDATION_EMAIL"), env("YC_STAGING_VALIDATION_EXPIRES_AT"))
	if err != nil || env("K_SERVICE") != stagingCaptureService {
		log.Warn().Msg("staging capture fixture disabled: invalid binding or service")
		return state
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	actual, err := project(ctx)
	if err != nil || actual != stagingCaptureProject {
		log.Warn().Msg("staging capture fixture disabled: project identity unavailable or mismatched")
		return state
	}
	log.Info().Msg("staging capture fixture enabled for one expiring binding")
	state.Verifier = verifier
	state.ExpiresAt, _ = time.Parse(time.RFC3339, env("YC_STAGING_VALIDATION_EXPIRES_AT"))
	return state
}

func stagingMetadataProject(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/computeMetadata/v1/project/project-id", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 2 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("metadata unavailable")
	}
	defer resp.Body.Close()
	value, err := io.ReadAll(io.LimitReader(resp.Body, 257))
	if err != nil || len(value) > 256 || resp.StatusCode != http.StatusOK || resp.Header.Get("Metadata-Flavor") != "Google" {
		return "", errors.New("invalid metadata response")
	}
	return strings.TrimSpace(string(value)), nil
}
