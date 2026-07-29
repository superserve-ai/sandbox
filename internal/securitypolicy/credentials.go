// Package securitypolicy owns cross-service security time bounds. Keeping
// these values outside the API package prevents background reconcilers from
// silently using a shorter revocation window than the credentials they revoke.
package securitypolicy

import "time"

// SandboxCredentialLifetime is the maximum lifetime of a sandbox secrets JWT.
// Every durable sandbox revocation must live for at least this long.
const SandboxCredentialLifetime = 90 * 24 * time.Hour
