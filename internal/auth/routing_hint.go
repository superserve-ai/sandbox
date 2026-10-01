package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const RoutingHintTTL = time.Hour
const RoutingHintClockSkew = time.Minute
const MaxRoutingHintBytes = 2048

// RoutingHint names a logical owner, never a network address or proxy generation.
// Authorization and local VMD ownership remain separate from this optimization.
type RoutingHint struct {
	SandboxID string `json:"s"`
	HostID    string `json:"h"`
	Audience  string `json:"a"`
	Expires   int64  `json:"e"`
	Version   int64  `json:"v"`
}

func routingMAC(seed []byte, payload string) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("superserve.routing-hint.v1\x00"))
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func SignRoutingHint(seed []byte, sandboxID, hostID, audience string, observedAt time.Time, version int64) string {
	if len(seed) < 32 || sandboxID == "" || hostID == "" || audience == "" || version <= 0 || observedAt.IsZero() || observedAt.After(time.Now().Add(RoutingHintClockSkew)) || !time.Now().Before(observedAt.Add(RoutingHintTTL)) {
		return ""
	}
	data, _ := json.Marshal(RoutingHint{sandboxID, hostID, audience, observedAt.Add(RoutingHintTTL).Unix(), version})
	payload := base64.RawURLEncoding.EncodeToString(data)
	token := "v1." + payload + "." + base64.RawURLEncoding.EncodeToString(routingMAC(seed, payload))
	if len(token) > MaxRoutingHintBytes {
		return ""
	}
	return token
}

func VerifyRoutingHint(seed []byte, token, sandboxID string, audiences []string, now time.Time) (RoutingHint, bool) {
	var hint RoutingHint
	if len(seed) < 32 || len(token) > MaxRoutingHintBytes {
		return hint, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return hint, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, routingMAC(seed, parts[1])) {
		return hint, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(data, &hint) != nil || hint.SandboxID != sandboxID || hint.HostID == "" || hint.Version <= 0 || hint.Expires <= now.Unix() || hint.Expires > now.Add(RoutingHintTTL+RoutingHintClockSkew).Unix() {
		return RoutingHint{}, false
	}
	for _, audience := range audiences {
		if hint.Audience == audience {
			return hint, true
		}
	}
	return RoutingHint{}, false
}
