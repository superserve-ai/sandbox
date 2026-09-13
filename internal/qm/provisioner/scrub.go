package provisioner

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Event detail is written to Postgres and shown in the console, so anything
// secret-shaped is replaced before it leaves the runner. Two passes: keys
// that name a credential lose their value outright, and every string value
// is run through patterns for the token formats that could plausibly leak
// through an error message (provider keys, sandbox keys, connection
// strings, bearer headers, PEM blocks, long opaque blobs).

const redacted = "[redacted]"

var secretKeyRe = regexp.MustCompile(`(?i)(secret|token|password|passwd|credential|authorization|cookie|private|api[_-]?key|_key$|^key$)`)

var secretValueRes = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`ss_(?:live|test)_[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s@]+@`),
	regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*`),
	// Long opaque runs without separators: hex/base64url secrets. Hyphens
	// and slashes are excluded so resource names and references survive.
	regexp.MustCompile(`\b[A-Za-z0-9_]{40,}\b`),
}

// ScrubString redacts secret-shaped substrings.
func ScrubString(s string) string {
	for _, re := range secretValueRes {
		s = re.ReplaceAllString(s, redacted)
	}
	return s
}

// ScrubDetail redacts a detail payload recursively and returns it as JSON
// ready for qm.tenant_events.detail. Unmarshalable input becomes an
// object with a single scrubbed "value".
func ScrubDetail(detail any) json.RawMessage {
	out, err := json.Marshal(scrubValue(detail))
	if err != nil {
		out, _ = json.Marshal(map[string]string{"value": ScrubString(strings.TrimSpace(err.Error()))})
	}
	return out
}

func scrubValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return ScrubString(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if secretKeyRe.MatchString(k) {
				out[k] = redacted
				continue
			}
			out[k] = scrubValue(val)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if secretKeyRe.MatchString(k) {
				out[k] = redacted
				continue
			}
			out[k] = ScrubString(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = scrubValue(val)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = ScrubString(val)
		}
		return out
	case error:
		return ScrubString(x.Error())
	default:
		// Anything else round-trips through JSON so nested structs get the
		// same treatment as maps.
		raw, err := json.Marshal(x)
		if err != nil {
			return redacted
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return redacted
		}
		if _, isString := generic.(string); isString || generic == nil {
			return generic
		}
		switch generic.(type) {
		case map[string]any, []any:
			return scrubValue(generic)
		}
		return generic
	}
}
