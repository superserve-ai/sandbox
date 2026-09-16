//go:build integration

package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Integration-only entry points let the database harness exercise private workers.
func ProcessTrialCreditWarningForTest(h *Handlers, ctx context.Context, teamID uuid.UUID) {
	h.processTrialCreditWarning(ctx, teamID)
}

func RefreshActiveTrialEligibilityForTest(h *Handlers, ctx context.Context) {
	h.refreshActiveTrialEligibility(ctx)
}

func NewTrialCreditWarningSenderForTest(q *db.Queries, endpoint string, client *http.Client) *ResendTrialCreditWarningSender {
	s := NewResendTrialCreditWarningSender("test-key", "team@example.com", q)
	s.endpoint, s.client = endpoint, client
	return s
}
