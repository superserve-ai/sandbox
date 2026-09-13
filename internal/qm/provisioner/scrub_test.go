package provisioner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScrubDetailRedactsByKeyAndValue(t *testing.T) {
	in := map[string]any{
		"apiKey":        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
		"PASSWORD":      "hunter2",
		"Authorization": "Bearer abc.def.ghi",
		"nested":        map[string]any{"token": "x", "service": "qm-pilot-team"},
		"list":          []any{"ss_live_0123456789abcdef", "fine"},
		"error":         "dial postgres://qm:hunter2@db.example.com:5432/qm: Bearer eyJhbGciOiJIUzI1NiJ9 -----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
		"blob":          "ghp_" + strings.Repeat("a", 40),
		"ref":           "projects/example/secrets/qm-pilot-team-PORTAL_SESSION_SECRET/versions/latest",
		"id":            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"count":         3,
	}
	var out map[string]any
	if err := json.Unmarshal(ScrubDetail(in), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"apiKey", "PASSWORD", "Authorization"} {
		if out[k] != redacted {
			t.Errorf("%s = %v", k, out[k])
		}
	}
	nested := out["nested"].(map[string]any)
	if nested["token"] != redacted || nested["service"] != "qm-pilot-team" {
		t.Errorf("nested = %v", nested)
	}
	list := out["list"].([]any)
	if list[0] != redacted || list[1] != "fine" {
		t.Errorf("list = %v", list)
	}
	errText := out["error"].(string)
	for _, leak := range []string{"hunter2", "eyJhbGciOiJIUzI1NiJ9", "MIIE"} {
		if strings.Contains(errText, leak) {
			t.Errorf("error leaks %q: %s", leak, errText)
		}
	}
	if !strings.HasPrefix(errText, "dial [redacted]db.example.com") {
		t.Errorf("connection string host lost or credentials kept: %s", errText)
	}
	if out["blob"] != redacted {
		t.Errorf("long opaque token kept: %v", out["blob"])
	}
	if out["ref"] != in["ref"] || out["id"] != in["id"] {
		t.Errorf("resource references were redacted: ref=%v id=%v", out["ref"], out["id"])
	}
	if out["count"] != float64(3) {
		t.Errorf("count = %v", out["count"])
	}
}

func TestScrubDetailHandlesStructsAndErrors(t *testing.T) {
	type payload struct {
		Service string `json:"service"`
		Secret  string `json:"secret"`
	}
	var out map[string]any
	if err := json.Unmarshal(ScrubDetail(map[string]any{"p": payload{Service: "svc", Secret: "s3cr3t"}}), &out); err != nil {
		t.Fatal(err)
	}
	p := out["p"].(map[string]any)
	if p["service"] != "svc" || p["secret"] != redacted {
		t.Errorf("struct = %v", p)
	}
}
