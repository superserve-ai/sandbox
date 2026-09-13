package steps

import (
	"fmt"
	"strings"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// The tenant image derives most of its own configuration from PUBLIC_WEB_URL
// once AUTH_SIGNING_JWK is present — the broker's issuer, client id,
// redirect URI and the portal's matching OIDC settings all come from it — so
// what the provisioner renders is deliberately small: identity, the stores,
// the sandbox backend, and the sign-in policy.

// Sign-in is opened to the tenant's admin address and nothing else.
//
// Deriving AUTH_ALLOWED_EMAIL_DOMAIN from that address is tempting — it is
// what lets the rest of a team sign in without another deploy — but there
// is no sound way to tell a company's domain from a mailbox provider's
// from the address alone. A list of the providers to exclude is incomplete
// by construction (there is always another regional Yahoo or Outlook
// domain), and one miss opens a tenant holding the team's model key and
// sandbox credentials to anybody with an account at that provider. So the
// default fails closed, and widening it is a deliberate act by whoever
// operates the tenant rather than a guess made here.

// TenantEnv is the plain configuration of a tenant's service. Nothing
// secret-shaped belongs here: Cloud Run shows a service's environment to
// anyone who can describe it, and the provisioner logs the keys.
func TenantEnv(t *provisioner.Tenant) (map[string]string, error) {
	if t.Row.BucketName == nil {
		return nil, fmt.Errorf("the tenant has no bucket recorded")
	}
	public := t.PublicURL()
	env := map[string]string{
		"ORG_ID": t.Row.Slug,
		// The supervisor derives PORTAL_PUBLIC_URL, WEB_UI_PUBLIC_URL and
		// the whole broker/OIDC set from this one.
		"PUBLIC_WEB_URL": public,
		"PUBLIC_API_URL": public,

		"SESSION_STORE":  "postgres",
		"RUN_STORE":      "postgres",
		"SNAPSHOT_STORE": "s3",
		"TRANSFER_STORE": "s3",
		// Cloud Storage through its S3-compatible endpoint; "auto" is the
		// region name that endpoint expects.
		"S3_BUCKET":           *t.Row.BucketName,
		"S3_REGION":           "auto",
		"AWS_REGION":          "auto",
		"AWS_ENDPOINT_URL_S3": "https://storage.googleapis.com",

		"HARNESS":                 t.Row.Harness,
		"MODEL_PROVIDER":          t.Row.ModelProvider,
		"BACKGROUND_WORK_ENABLED": "true",

		"SANDBOX_BACKEND":        "superserve",
		"SUPERSERVE_BASE_URL":    t.Env.SandboxAPIURL,
		"SUPERSERVE_TEMPLATE":    t.Env.SandboxTemplate,
		"SUPERSERVE_NAME_PREFIX": sandboxNamePrefix(t.Row.Slug),

		"ADMIN_GRANTS": t.Row.AdminEmail + ":org_admin",

		// Sign-in. The broker runs inside the tenant's own container and
		// sends magic links through the platform's Resend account, so a
		// tenant that reached here can actually be signed into — the whole
		// point of the step, and the thing the reference tenant shipped
		// without.
		"AUTH_EMBEDDED":        "1",
		"AUTH_EMAIL_TRANSPORT": "resend",
		"AUTH_EMAIL_FROM":      t.Env.EmailFrom,
		"AUTH_ALLOWED_EMAILS":  t.Row.AdminEmail,
		"AUTH_BRAND_NAME":      t.Row.OrgName,
	}
	return env, nil
}

// TenantSecretEnv maps each secret-backed environment variable to the
// Secret Manager name Cloud Run mounts its latest version from.
//
// Every tenant secret here is one the secrets, database, bucket or
// sandbox_key step wrote, except RESEND_API_KEY: hosted QM has one Resend
// account and one verified sending domain, so every tenant mounts the
// platform's shared secret rather than a key of its own.
func TenantSecretEnv(t *provisioner.Tenant) (map[string]string, error) {
	if strings.TrimSpace(t.Env.ResendSecret) == "" {
		// Not a warning. A tenant with no email transport answers its
		// health check and 503s the moment anybody tries to sign in.
		return nil, fmt.Errorf("no email transport: QM_RESEND_SECRET is unset, and the tenant's sign-in would fail closed")
	}
	out := map[string]string{secretResendAPIKey: t.Env.ResendSecret}
	for _, name := range []string{
		secretDatabaseURL,
		"CORE_SIGNING_SECRET",
		"CAPABILITY_SECRET",
		"PORTAL_IDENTITY_SECRET",
		"CONNECTOR_SECRET_KEY",
		"SKILL_SIGNING_SECRET",
		secrets.PortalSessionSecret,
		"AUTH_TOKEN_SECRET",
		"AUTH_CLIENT_SECRET",
		"AUTH_SIGNING_JWK",
		secretAccessKeyID,
		secretSecretAccessKey,
		secretSandboxAPIKey,
		secrets.ModelKeyName(t.Row.ModelProvider),
	} {
		out[name] = t.SecretName(name)
	}
	return out, nil
}

// sandboxNamePrefix is the prefix the tenant's sandboxes are named with. It
// is a sandbox name component, so it keeps to lowercase alphanumerics and
// stays short.
func sandboxNamePrefix(slug string) string {
	const maxPrefix = 12
	var b strings.Builder
	b.WriteString("qm")
	for _, r := range slug {
		if b.Len() >= maxPrefix {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
