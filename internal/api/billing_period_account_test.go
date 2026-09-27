package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestListBillingPeriodsReusesLoadedAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	teamID := uuid.New()
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	customer, subscription, status, invoice := "cus_example", "sub_example", "active", "paid"
	accountReads := 0
	periodRow := func(dest ...any) error {
		*dest[0].(*uuid.UUID) = teamID
		*dest[1].(*time.Time) = start
		*dest[2].(*time.Time) = end
		*dest[3].(*string) = "open"
		return nil
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return &mockRow{scanFn: func(dest ...any) error {
				switch {
				case strings.Contains(sql, "-- name: IsFeatureEnabledForTeam"):
					*dest[0].(*bool) = true
				case strings.Contains(sql, "-- name: GetTeamBillingAccount :one"):
					accountReads++
					if accountReads > 1 {
						return errors.New("second account read unavailable")
					}
					*dest[0].(*uuid.UUID) = teamID
					*dest[1].(**string) = &customer
					*dest[2].(**string) = &subscription
					*dest[3].(**string) = &status
					*dest[4].(**string) = &invoice
					*dest[6].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: start, Valid: true}
					*dest[7].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: end, Valid: true}
					*dest[8].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: start, Valid: true}
					*dest[9].(*bool) = true
				case strings.Contains(sql, "-- name: UpsertTeamBillingPeriod"):
					return periodRow(dest...)
				default:
					t.Fatalf("unexpected row query: %s", sql)
				}
				return nil
			}}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "-- name: ListTeamBillingPeriods") {
				t.Fatalf("unexpected rows query: %s", sql)
			}
			return &scanRows{rows: []func(...any) error{periodRow}}, nil
		},
	}
	h := &Handlers{DB: db.New(mock), Now: func() time.Time { return start.Add(time.Hour) }}
	router := gin.New()
	router.GET("/teams/:team_id/billing/periods", func(c *gin.Context) {
		c.Set("team_id", teamID.String())
		h.ListTeamBillingPeriods(c)
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/teams/"+teamID.String()+"/billing/periods", nil))
	if w.Code != http.StatusOK || accountReads != 1 {
		t.Fatalf("status=%d account reads=%d body=%s", w.Code, accountReads, w.Body.String())
	}
	var response struct {
		Periods []billingPeriodResponse `json:"periods"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Periods) != 1 {
		t.Fatalf("decode periods: %v, body=%s", err, w.Body.String())
	}
	period := response.Periods[0]
	if derefString(period.StripeCustomerID) != customer || derefString(period.StripeSubscription) != subscription ||
		derefString(period.SubscriptionStatus) != status || derefString(period.InvoiceStatus) != invoice ||
		period.CommercialBillingAnchor == nil || !period.CommercialBillingAnchor.Equal(start) ||
		period.CurrentPeriodStart == nil || !period.CurrentPeriodStart.Equal(start) ||
		period.CurrentPeriodEnd == nil || !period.CurrentPeriodEnd.Equal(end) ||
		period.CancelAtPeriodEnd == nil || !*period.CancelAtPeriodEnd {
		t.Fatalf("lost billing account metadata: %+v", period)
	}
}
