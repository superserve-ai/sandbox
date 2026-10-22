package api

import (
	"errors"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

type ycApprovalMailScope struct {
	claimID uuid.UUID
	expires time.Time
}

func (h *Handlers) ycValidationMailScope() (*ycApprovalMailScope, bool, error) {
	requested := h.YCClaimValidation.Requested || ycclaims.ValidationRequested(os.LookupEnv)
	if !requested {
		return nil, false, nil
	}
	claim, err := uuid.Parse(os.Getenv("YC_STAGING_VALIDATION_CLAIM_ID"))
	if err != nil || claim == uuid.Nil || h.YCClaimValidation.Verifier == nil || !time.Now().Before(h.YCClaimValidation.ExpiresAt) {
		return nil, true, errors.New("validation approval mail is not authorized")
	}
	return &ycApprovalMailScope{claimID: claim, expires: h.YCClaimValidation.ExpiresAt}, true, nil
}
