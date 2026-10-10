package api

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/requestlog"
)

const logIdentityKey = "request_log_identity"
const logAuthorizationOutcomeKey = "request_log_authorization_outcome"

func logIdentity(c *gin.Context) requestlog.Identity {
	if caller, ok := VerifiedMachineCallerFromContext(c); ok {
		return requestlog.VerifiedCaller(caller)
	}
	i, _ := c.Get(logIdentityKey)
	identity, _ := i.(requestlog.Identity)
	return identity
}

func logAuthOutcome(c *gin.Context, outcome string) {
	c.Set(logIdentityKey, requestlog.Unresolved(outcome))
}

func logSharedAuthAttempt(c *gin.Context, configured bool) {
	outcome := "invalid"
	if !configured {
		outcome = "error"
	} else if c.GetHeader("Authorization") == "" {
		outcome = "missing"
	}
	logAuthOutcome(c, outcome)
}

func logServiceIdentity(c *gin.Context, kind string) {
	c.Set(logIdentityKey, requestlog.Identity{
		ActorType: kind, AuthOutcome: "authenticated", AttributionStatus: "unavailable",
	})
}

func logHumanIdentity(c *gin.Context, userID string) {
	i := logIdentity(c)
	if i.AuthOutcome != "authenticated" {
		return
	}
	i.DelegatedBy = i.ActorType
	i.ActorType, i.ActorID, i.UserID = "human", userID, userID
	i.AttributionStatus = "identified"
	c.Set(logIdentityKey, i)
}

// Only known identifier parameters may retain validated UUIDs. Tenant-chosen
// names can also look like UUIDs, so shape alone does not make them safe.
func requestLogPath(c *gin.Context) (string, string) {
	route := c.FullPath()
	if route == "" {
		return "__unmatched__", "__unmatched__"
	}
	parts := strings.Split(route, "/")
	for n, part := range parts {
		if strings.HasPrefix(part, ":") {
			switch part {
			case ":sandbox_id", ":template_id", ":build_id", ":snapshot_id",
				":team_id", ":user_id", ":host_id", ":assignment_id", ":period_id",
				":event_id", ":correction_id", ":restriction_id", ":identity_id":
			default:
				continue
			}
			raw := c.Param(part[1:])
			id, err := uuid.Parse(raw)
			if part == ":sandbox_id" {
				id, err = parsePublicSandboxID(raw)
			}
			if err == nil {
				parts[n] = id.String()
			}
		}
	}
	return route, strings.Join(parts, "/")
}
