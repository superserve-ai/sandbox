package qm

import "testing"

// The platform's own resources are named qm-<word>-<suffix>, and a tenant's
// service account, service and bucket are all named after its slug. A slug
// whose first label is one of those words derives a colliding name, so it is
// refused before a tenant can be created with it.
func TestValidateSlugReservesPlatformNames(t *testing.T) {
	for _, slug := range []string{
		"provisioner", "provisioner-stg-usc1", "api", "api-staging",
		"redirect", "redirect-prod", "sql", "sql-admin-staging",
		"tenants", "tenants-usc1", "resend", "resend-key", "qm", "admin",
	} {
		if reason := ValidateSlug(slug); reason == "" {
			t.Errorf("ValidateSlug(%q) accepted a reserved name", slug)
		}
	}
	for _, slug := range []string{
		"pilot-team", "acme", "apiary", "sqlite-shop", "redirected-co",
	} {
		if reason := ValidateSlug(slug); reason != "" {
			t.Errorf("ValidateSlug(%q) = %q, want accepted", slug, reason)
		}
	}
}
