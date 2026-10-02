package api

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestBillingUsageSeriesTimezoneValidation(t *testing.T) {
	for _, raw := range []string{"", "   ", "Not/AZone", "Local", " Local "} {
		req := httptest.NewRequest("GET", "/billing/usage-series?timezone="+url.QueryEscape(raw), nil)
		if _, err := billingUsageSeriesTimezone(req.URL.Query().Get("timezone")); err == nil {
			t.Errorf("request timezone %q should be rejected", raw)
		}
	}
	req := httptest.NewRequest("GET", "/billing/usage-series?timezone=+America%2FChicago+", nil)
	if loc, err := billingUsageSeriesTimezone(req.URL.Query().Get("timezone")); err != nil || loc == nil {
		t.Fatalf("valid timezone rejected: %v", err)
	}
}
