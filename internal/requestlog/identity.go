// Package requestlog defines non-secret request attribution shared by services.
package requestlog

import "github.com/rs/zerolog"

type Identity struct {
	ActorType         string
	ActorID           string
	CredentialID      string
	UserID            string
	TeamID            string
	ResourceTeamID    string
	AuthOutcome       string
	AttributionStatus string
	DelegatedBy       string
}

func Unresolved(outcome string) Identity {
	actor, attribution := "unauthenticated", "unavailable"
	if outcome == "error" {
		actor, attribution = "unknown", "error"
	}
	return Identity{ActorType: actor, AuthOutcome: outcome, AttributionStatus: attribution}
}

func (i Identity) Log(e *zerolog.Event) *zerolog.Event {
	if i.AuthOutcome == "" {
		i = Unresolved("not_evaluated")
	}
	if i.ActorType == "" || i.AttributionStatus == "" ||
		(i.AttributionStatus == "identified" && i.ActorID == "") {
		i.ActorType, i.AttributionStatus = "unknown", "error"
	}
	e.Str("actor_type", i.ActorType).
		Str("auth_outcome", i.AuthOutcome).
		Str("attribution_status", i.AttributionStatus)
	for _, field := range []struct{ name, value string }{
		{"actor_id", i.ActorID}, {"credential_id", i.CredentialID},
		{"user_id", i.UserID}, {"team_id", i.TeamID},
		{"resource_team_id", i.ResourceTeamID}, {"delegated_by", i.DelegatedBy},
	} {
		if field.value != "" {
			e.Str(field.name, field.value)
		}
	}
	return e
}

func Method(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return method
	default:
		return "OTHER"
	}
}
