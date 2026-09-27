package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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
		{"capture reuses internal", "capture-example-token", "account-example-token", "capture-example-token"},
		{"account reuses internal", "capture-example-token", "account-example-token", "account-example-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PROMOTION_CAPTURE_TOKEN", tc.captureToken)
			t.Setenv("PROMOTION_ACCOUNT_TOKEN", tc.accountToken)
			t.Setenv("INTERNAL_API_TOKEN", tc.internalToken)
			for _, scope := range []struct{ path, env, token string }{
				{"/capture", "PROMOTION_CAPTURE_TOKEN", tc.captureToken},
				{"/account", "PROMOTION_ACCOUNT_TOKEN", tc.accountToken},
			} {
				r := gin.New()
				r.POST(scope.path, PromotionProducerAuth(scope.env), func(c *gin.Context) { c.Status(http.StatusNoContent) })
				req := httptest.NewRequest(http.MethodPost, scope.path, nil)
				req.Header.Set("Authorization", "Bearer "+scope.token)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("%s: got %d, want %d", scope.path, w.Code, http.StatusUnauthorized)
				}
			}
		})
	}
}
