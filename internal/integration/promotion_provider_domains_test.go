//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Use only in an isolated database or a transaction that will be rolled back.
// Map example domains onto the deployed provider branch without copying its normalization logic.
func promotionExampleProviderDomains(t *testing.T, q db.DBTX) {
	t.Helper()
	var definition string
	if err := q.QueryRow(context.Background(), `SELECT pg_get_functiondef('public.promotion_identity_key(uuid,text,boolean)'::regprocedure)`).
		Scan(&definition); err != nil {
		t.Fatal(err)
	}
	const providerDomains = "domain IN ('gmail.com', 'googlemail.com')"
	const exampleDomains = "domain IN ('mail.example.com', 'alias.example.com')"
	if strings.Count(definition, providerDomains) != 1 {
		t.Fatal("expected one canonical identity provider-domain branch")
	}
	rolloutExec(t, q, strings.Replace(definition, providerDomains, exampleDomains, 1))
}
