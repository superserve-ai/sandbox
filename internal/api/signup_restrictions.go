package api

import (
	"encoding/json"
	"io"
	"net/http"

	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

func (h *Handlers) EvaluateSignup(c *gin.Context) {
	// Sentry's Gin middleware buffers request bodies before handlers run.
	// Signup subjects must not be attached to an exception event.
	if hub := sentrygin.GetHubFromContext(c); hub != nil {
		hub.Scope().SetRequestBody(nil)
	}
	var input struct {
		Subjects []abuse.SignupSubject `json:"subjects"`
	}
	if c.Request.Body == nil {
		respondErrorMsg(c, "invalid_request", "invalid signup evaluation request", http.StatusBadRequest)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil || len(input.Subjects) != 1 || input.Subjects[0].Type != "fingerprint" || !abuse.ValidFingerprint(input.Subjects[0].Value) {
		respondErrorMsg(c, "invalid_request", "invalid signup evaluation request", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		respondErrorMsg(c, "invalid_request", "invalid signup evaluation request", http.StatusBadRequest)
		return
	}
	decision := h.SignupRestrictions.Evaluate(input.Subjects)
	if rec, ok := currentTelemetryRecorder().(telemetry.SignupRecorder); ok {
		rec.RecordSignupDecision(c.Request.Context(), string(decision.Mode), decision.Decision, decision.MatchedSubjectType)
	}
	c.JSON(http.StatusOK, decision)
}
