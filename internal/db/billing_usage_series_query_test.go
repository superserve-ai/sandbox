package db

import (
	"strings"
	"testing"
)

func TestGetTeamBillingUsageSeriesPreservesFractionalArtifactSeconds(t *testing.T) {
	// Artifact usage can straddle multiple requested buckets.  Rounding inside
	// each bucket would discard every bucket's remainder and make the series
	// disagree with the aggregate usage query, which rounds only once.
	marker := "COALESCE(SUM(artifact_mib*EXTRACT(EPOCH FROM (upper(r)-lower(r)))),0)::numeric AS mib_seconds"
	if !strings.Contains(getTeamBillingUsageSeries, marker) {
		t.Fatalf("usage-series query must preserve fractional artifact MiB-seconds before bucketing")
	}
	if strings.Contains(getTeamBillingUsageSeries, "FLOOR(COALESCE(SUM(artifact_mib*EXTRACT(EPOCH FROM (upper(r)-lower(r))))") {
		t.Fatalf("usage-series query must not floor artifact usage independently per bucket")
	}
}
