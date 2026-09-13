package qm

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/superserve-ai/sandbox/internal/qm/adminlink"
)

// Slug rules mirror the qm_tenants_slug_dns_label check constraint: an RFC
// 1123 label of 3–40 characters. Reserved names are the hostnames the
// platform itself may need under the base domain.
var (
	slugRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$`)
	reservedSlugs = map[string]bool{
		"www": true, "api": true, "admin": true, "mail": true, "qm": true,
		"app": true, "console": true, "docs": true, "status": true,
	}

	signInOptions        = map[string]bool{"magic_link": true, "slack": true}
	modelProviderOptions = map[string]bool{"anthropic": true, "openai": true, "openrouter": true}
	harnessOptions       = map[string]bool{"pi": true, "claude": true, "codex": true, "opencode": true}
)

const (
	defaultHarness   = "pi"
	maxOrgNameLen    = 100
	maxModelKeyLen   = 4096
	slugAvailableMsg = ""
)

// ValidateSlug returns "" when slug is acceptable, else a user-facing reason.
func ValidateSlug(slug string) string {
	switch {
	case len(slug) < 3 || len(slug) > 40:
		return "Slug must be 3–40 characters."
	case !slugRe.MatchString(slug):
		return "Slug may contain only lowercase letters, digits and hyphens, and must start and end with a letter or digit."
	case reservedSlugs[slug]:
		return "This slug is reserved."
	}
	return slugAvailableMsg
}

// CreateTenantRequest is the POST /v1/qm/tenants body.
type CreateTenantRequest struct {
	Slug          string `json:"slug"`
	OrgName       string `json:"orgName"`
	AdminEmail    string `json:"adminEmail"`
	SignIn        string `json:"signIn"`
	ModelProvider string `json:"modelProvider"`
	// ModelKey is handed to Secret Manager and nowhere else; it is not part
	// of any log line or stored row.
	ModelKey string `json:"modelKey"`
	Harness  string `json:"harness,omitempty"`
}

// normalize trims and lowercases what the schema expects lowercased.
func (r *CreateTenantRequest) normalize() {
	r.Slug = strings.ToLower(strings.TrimSpace(r.Slug))
	r.OrgName = strings.TrimSpace(r.OrgName)
	r.AdminEmail = strings.ToLower(strings.TrimSpace(r.AdminEmail))
	r.SignIn = strings.TrimSpace(r.SignIn)
	r.ModelProvider = strings.ToLower(strings.TrimSpace(r.ModelProvider))
	r.ModelKey = strings.TrimSpace(r.ModelKey)
	r.Harness = strings.ToLower(strings.TrimSpace(r.Harness))
	if r.Harness == "" {
		r.Harness = defaultHarness
	}
}

// validate returns field → message for every problem, empty when the
// request is acceptable. The model key is checked for shape only; whether
// the provider accepts it is the provisioner's smoke step to find out.
func (r *CreateTenantRequest) validate() map[string]string {
	fields := map[string]string{}
	if reason := ValidateSlug(r.Slug); reason != "" {
		fields["slug"] = reason
	}
	if r.OrgName == "" || utf8.RuneCountInString(r.OrgName) > maxOrgNameLen {
		fields["orgName"] = "Organization name must be 1–100 characters."
	}
	if !adminlink.ValidEmail(r.AdminEmail) {
		fields["adminEmail"] = "Enter a valid email address."
	}
	if !signInOptions[r.SignIn] {
		fields["signIn"] = "Sign-in must be magic_link or slack."
	}
	if !modelProviderOptions[r.ModelProvider] {
		fields["modelProvider"] = "Model provider must be anthropic, openai or openrouter."
	}
	switch {
	case r.ModelKey == "":
		fields["modelKey"] = "Model key is required."
	case len(r.ModelKey) > maxModelKeyLen || strings.IndexFunc(r.ModelKey, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0:
		fields["modelKey"] = "Model key must be a single token without spaces."
	}
	if !harnessOptions[r.Harness] {
		fields["harness"] = "Harness must be pi, claude, codex or opencode."
	}
	return fields
}
