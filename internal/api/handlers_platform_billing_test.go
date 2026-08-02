package api

import (
	"strings"
	"testing"
)

func TestParsePlatformBillingParams(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		got, err := parsePlatformBillingParams(pageCtx(t, ""))
		if err != nil {
			t.Fatalf("parse defaults: %v", err)
		}
		if got.Limit != platformBillingDefaultLimit || got.Offset != 0 {
			t.Fatalf("pagination = %d/%d, want %d/0", got.Limit, got.Offset, platformBillingDefaultLimit)
		}
		if got.SortBy != "team_name" || got.SortDir != "desc" {
			t.Fatalf("sort = %s/%s, want team_name/desc", got.SortBy, got.SortDir)
		}
	})

	t.Run("all inputs", func(t *testing.T) {
		got, err := parsePlatformBillingParams(pageCtx(t, "limit=25&offset=50&sort=current_charges_usd&order=asc&search=50%25_acme"))
		if err != nil {
			t.Fatalf("parse inputs: %v", err)
		}
		if got.Limit != 25 || got.Offset != 50 {
			t.Fatalf("pagination = %d/%d, want 25/50", got.Limit, got.Offset)
		}
		if got.SortBy != "current_charges_usd" || got.SortDir != "asc" {
			t.Fatalf("sort = %s/%s", got.SortBy, got.SortDir)
		}
		if got.Search != `50\%\_acme` {
			t.Fatalf("search = %q, want escaped literal", got.Search)
		}
	})

	t.Run("search too long", func(t *testing.T) {
		if _, err := parsePlatformBillingParams(pageCtx(t, "search="+strings.Repeat("a", 201))); err == nil {
			t.Fatal("expected long search to be rejected")
		}
	})

	t.Run("search counts characters not bytes", func(t *testing.T) {
		search := strings.Repeat("搜索", 100)
		got, err := parsePlatformBillingParams(pageCtx(t, "search="+search))
		if err != nil {
			t.Fatalf("parse multibyte search: %v", err)
		}
		if want := searchTerm(search); want == nil || got.Search != *want {
			t.Fatalf("search = %q, want escaped literal", got.Search)
		}
	})
}

func TestPlatformBillingQuerySelection(t *testing.T) {
	if got := platformBillingQueryForSort("team_name"); got != platformBillingMetadataQuery {
		t.Fatal("team_name sort should use the metadata-paging query")
	}
	if got := platformBillingQueryForSort("created_at"); got != platformBillingMetadataQuery {
		t.Fatal("created_at sort should use the metadata-paging query")
	}
	if got := platformBillingQueryForSort("current_charges_usd"); got != platformBillingChargesQuery {
		t.Fatal("billing-derived sort should use the full billing query")
	}
}

func TestPlatformBillingRequiredRateCountIgnoresFutureRates(t *testing.T) {
	if !strings.Contains(platformBillingChargesQuery, "resource IN ('vcpu', 'memory_gib', 'storage_gib')") {
		t.Fatal("required-rate count should only include the three billing resources")
	}
}

func TestPlatformBillingReconstructsCurrentPeriodCreditsFromLedger(t *testing.T) {
	if !strings.Contains(platformBillingChargesQuery, "team_credit_ledger") {
		t.Fatal("billing query should read the current-period credit ledger")
	}
	if !strings.Contains(platformBillingChargesQuery, "available_credits") {
		t.Fatal("billing query should reconstruct an available-credits balance")
	}
}

func TestPlatformBillingStableSortingTreatsErrorsAsSecondaryKey(t *testing.T) {
	if !strings.Contains(platformBillingChargesQuery, "CASE WHEN error_code IS NOT NULL THEN 1 ELSE 0 END ASC") {
		t.Fatal("billing sort should keep error rows behind successful rows")
	}
	if !strings.Contains(platformBillingChargesQuery, "lower(team_name) ASC") {
		t.Fatal("billing sort should use team name as a stable secondary key")
	}
}
