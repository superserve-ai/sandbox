package api

import (
	"testing"
)

func TestRenewalChoiceRuntimeDisabledAndCannotReplaceService(t *testing.T) {
	h := &Handlers{}
	if err := h.ConfigureRenewalChoices(t.Context(), RenewalChoiceConfig{}); err != nil || h.RenewalChoices != nil {
		t.Fatal("default configuration registered renewals", err)
	}
	if err := h.ConfigureRenewalChoices(t.Context(), RenewalChoiceConfig{Enabled: true}); err == nil || h.RenewalChoices != nil {
		t.Fatal("incomplete configuration registered renewals", err)
	}
	existing := &renewalChoiceService{Enabled: true}
	h.RenewalChoices = existing
	if err := h.ConfigureRenewalChoices(t.Context(), RenewalChoiceConfig{}); err == nil || h.RenewalChoices != existing {
		t.Fatal("reconfiguration replaced an existing service", err)
	}
}
