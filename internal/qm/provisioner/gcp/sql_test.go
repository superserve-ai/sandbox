package gcp

import (
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
)

// Database and role names are interpolated into DDL, which cannot take
// parameters — so the one thing that keeps that from being an injection
// point is this check, and the names the steps derive have to pass it.
func TestQuoteIdentifier(t *testing.T) {
	for _, slug := range []string{"pilot-team", "a-b-c", "t123", strings.Repeat("a", 40)} {
		for _, name := range []string{steps.DatabaseName(slug), steps.RoleName(slug)} {
			quoted, err := quoteIdentifier(name)
			if err != nil {
				t.Errorf("%q derived from %q was refused: %v", name, slug, err)
			}
			if quoted != `"`+name+`"` {
				t.Errorf("quoteIdentifier(%q) = %q", name, quoted)
			}
		}
	}
	for _, bad := range []string{
		"", "qm_pilot\"; DROP DATABASE postgres; --", "qm-pilot", "QM_PILOT",
		"1qm", "qm_" + strings.Repeat("a", 70), "qm_pilot team",
	} {
		if _, err := quoteIdentifier(bad); err == nil {
			t.Errorf("quoteIdentifier(%q) was accepted", bad)
		}
	}
}
