package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestPromotionProducerCredentialsAreScoped(t *testing.T) {
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "capture-example-token")
	t.Setenv("PROMOTION_ACCOUNT_TOKEN", "account-example-token")
	r := gin.New()
	capture := r.Group("/capture", PromotionProducerAuth("PROMOTION_CAPTURE_TOKEN"))
	capture.POST("/check", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	account := r.Group("/account", PromotionProducerAuth("PROMOTION_ACCOUNT_TOKEN"))
	account.POST("/check", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, tc := range []struct {
		path, token string
		status      int
	}{
		{"/capture/check", "capture-example-token", http.StatusNoContent},
		{"/capture/check", "account-example-token", http.StatusUnauthorized},
		{"/account/check", "account-example-token", http.StatusNoContent},
		{"/account/check", "capture-example-token", http.StatusUnauthorized},
		{"/account/check", "", http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader("{}"))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s with %q: got %d, want %d", tc.path, tc.token, w.Code, tc.status)
		}
	}
}

func TestPromotionAccountRequiresMatchingActor(t *testing.T) {
	accountID := uuid.New()
	otherID := uuid.New()
	for _, tc := range []struct {
		header string
		status int
	}{
		{accountID.String(), http.StatusNoContent},
		{otherID.String(), http.StatusForbidden},
		{"", http.StatusForbidden},
	} {
		r := gin.New()
		r.POST("/account", func(c *gin.Context) {
			if promotionAccountActor(c, accountID) {
				c.Status(http.StatusNoContent)
			}
		})
		req := httptest.NewRequest(http.MethodPost, "/account", nil)
		req.Header.Set("X-Actor-User-Id", tc.header)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("actor %q: got %d, want %d", tc.header, w.Code, tc.status)
		}
	}
}

func TestPromotionProducerRejectsSharedCredential(t *testing.T) {
	t.Setenv("PROMOTION_CAPTURE_TOKEN", "same-example-token")
	t.Setenv("PROMOTION_ACCOUNT_TOKEN", "same-example-token")
	r := gin.New()
	r.POST("/capture", PromotionProducerAuth("PROMOTION_CAPTURE_TOKEN"), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodPost, "/capture", nil)
	req.Header.Set("Authorization", "Bearer same-example-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestPromotionProducerRejectsMissingPeerOrInternalCredential(t *testing.T) {
	for _, tc := range []struct {
		name, captureToken, accountToken, internalToken string
	}{
		{"missing capture", "", "account-example-token", "internal-example-token"},
		{"missing peer", "capture-example-token", "", "internal-example-token"},
		{"internal token reused", "capture-example-token", "account-example-token", "capture-example-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PROMOTION_CAPTURE_TOKEN", tc.captureToken)
			t.Setenv("PROMOTION_ACCOUNT_TOKEN", tc.accountToken)
			t.Setenv("INTERNAL_API_TOKEN", tc.internalToken)
			r := gin.New()
			r.POST("/capture", PromotionProducerAuth("PROMOTION_CAPTURE_TOKEN"), func(c *gin.Context) { c.Status(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodPost, "/capture", nil)
			req.Header.Set("Authorization", "Bearer capture-example-token")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want %d", w.Code, http.StatusUnauthorized)
			}
		})
	}
}
