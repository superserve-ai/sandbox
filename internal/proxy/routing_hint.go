package proxy

import (
	"net/http"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/auth"
)

const routingHintHeader = "X-Superserve-Routing-Hint"
const routingHintProtocol = "route."

type hostDirectory interface {
	ResolveHost(string) (SandboxRoute, bool)
}

func (h *RoutingHandler) WithRoutingHints(directory hostDirectory, revocations interface{ Allows(string, int64) bool }) *RoutingHandler {
	h.hosts = directory
	h.revocations = revocations
	return h
}

func requestRoutingHint(r *http.Request) string {
	if values := r.Header.Values(routingHintHeader); len(values) != 0 {
		if len(values) != 1 {
			return ""
		}
		return values[0]
	}
	if r.URL.Path != execConnectPath && r.URL.Path != terminalPath {
		return ""
	}
	var hint string
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			if token, ok := strings.CutPrefix(strings.TrimSpace(protocol), routingHintProtocol); ok {
				if hint != "" {
					return ""
				}
				hint = token
			}
		}
	}
	return hint
}

func (h *RoutingHandler) hintedRoute(r *http.Request, sandboxID string) (SandboxRoute, bool) {
	local, ok := h.local.(*Handler)
	if !ok || h.hosts == nil {
		return SandboxRoute{}, false
	}
	hint, ok := auth.VerifyRoutingHint(local.seedKey, requestRoutingHint(r), sandboxID, h.domains, time.Now())
	if !ok || h.revocations == nil || !h.revocations.Allows(sandboxID, hint.Version) {
		return SandboxRoute{}, false
	}
	// Even local destinations require a current directory entry: removed hosts
	// must not keep accepting old hints indefinitely.
	return h.hosts.ResolveHost(hint.HostID)
}

func scrubRoutingHint(r *http.Request) {
	r.Header.Del(routingHintHeader)
	var protocols []string
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if !strings.HasPrefix(protocol, routingHintProtocol) {
				protocols = append(protocols, protocol)
			}
		}
	}
	if len(protocols) == 0 {
		r.Header.Del("Sec-WebSocket-Protocol")
	} else {
		r.Header.Set("Sec-WebSocket-Protocol", strings.Join(protocols, ", "))
	}
}
