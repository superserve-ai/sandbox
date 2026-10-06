package requestlog

import (
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/auth"
)

// VerifiedCaller projects an already authenticated caller into log metadata.
// It does not validate authority or recheck expiry at session completion.
func VerifiedCaller(c auth.CallerContext) Identity {
	i := Identity{AuthOutcome: "authenticated", AttributionStatus: "identified"}
	if c.TeamID == uuid.Nil || c.CredentialID == uuid.Nil {
		return Identity{ActorType: "unknown", AuthOutcome: "authenticated", AttributionStatus: "error"}
	}
	i.TeamID, i.CredentialID = c.TeamID.String(), c.CredentialID.String()
	switch c.CallerKind {
	case "", "machine":
		if c.PrincipalID == uuid.Nil {
			i.ActorType, i.AttributionStatus = "unknown", "error"
			return i
		}
		i.ActorType, i.ActorID = "machine", c.PrincipalID.String()
	case "human":
		// This capability producer currently derives ActorID from the key
		// owner. Its parent credential is proven; a human session is not.
		i.ActorType, i.ActorID = "api_key", c.CredentialID.String()
	default:
		i.ActorType, i.AttributionStatus = "unknown", "error"
	}
	return i
}
