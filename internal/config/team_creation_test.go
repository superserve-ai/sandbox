package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestTeamCreationKeysFailClosed(t *testing.T) {
	key := make([]byte, ed25519.PublicKeySize)
	encoded := base64.StdEncoding.EncodeToString(key)
	keys := teamCreationKeys(`{"old":"` + encoded + `","new":"` + encoded + `"}`)
	if len(keys) != 2 {
		t.Fatalf("rotation keys: got %d", len(keys))
	}
	for _, raw := range []string{"", "not-json", `{"test":"bad"}`, `{"":"` + encoded + `"}`} {
		if teamCreationKeys(raw) != nil {
			t.Errorf("accepted invalid key configuration: %q", raw)
		}
	}
}
