package requestlog

import (
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/auth"
)

// VerifiedCaller projects an already authenticated caller into log metadata.
// It does not validate authority or recheck expiry at session completion.
func VerifiedCaller(c auth.CallerContext) Identity {
	i := Identity{AuthOutcome: "authenticated", AttributionStatus: "identified"}
	if c.TeamID == uuid.Nil {
		return Identity{ActorType: "unknown", AuthOutcome: "authenticated", AttributionStatus: "error"}
	}
	i.TeamID = c.TeamID.String()
	if c.CredentialID != uuid.Nil {
		i.CredentialID = c.CredentialID.String()
	}
	switch c.CallerKind {
	case "", "machine":
		if c.PrincipalID != uuid.Nil && c.CredentialID != uuid.Nil {
			i.ActorType, i.ActorID = "machine", c.PrincipalID.String()
		}
	case "api_key":
		if c.CredentialID != uuid.Nil {
			i.ActorType, i.ActorID = "api_key", c.CredentialID.String()
		}
	case "human":
		if c.ActorID != uuid.Nil {
			i.ActorType, i.ActorID, i.UserID = "human", c.ActorID.String(), c.ActorID.String()
		}
	}
	if i.ActorID == "" {
		i.ActorType, i.AttributionStatus = "unknown", "error"
	}
	return i
}
