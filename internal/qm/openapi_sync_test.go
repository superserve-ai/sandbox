package qm

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	yaml "go.yaml.in/yaml/v3"
)

// TestOpenAPISpecMatchesQMRoutes is the qm-api half of the spec sync check
// in internal/api: every route under /v1/qm must be documented under the
// `qm` tag, and every `qm`-tagged operation must have a route here.
func TestOpenAPISpecMatchesQMRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := SetupRouter(&Handlers{}, fakeResolver{}, zerolog.Nop())

	routeOps := map[string]bool{}
	for _, ri := range router.Routes() {
		if !strings.HasPrefix(ri.Path, "/v1/qm/") {
			continue
		}
		routeOps[ri.Method+" "+ginPathToOpenAPI(ri.Path)] = true
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	httpMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
	specOps := map[string]bool{}
	for path, item := range doc.Paths {
		for key, op := range item {
			m := strings.ToUpper(key)
			if !httpMethods[m] {
				continue
			}
			tagged := slices.Contains(opTags(op), "qm")
			underQM := strings.HasPrefix(path, "/v1/qm/")
			if tagged != underQM {
				t.Errorf("%s %s: qm operations must live under /v1/qm and carry the qm tag (tagged=%v)", m, path, tagged)
			}
			if tagged {
				specOps[m+" "+path] = true
			}
		}
	}

	for op := range routeOps {
		if !specOps[op] {
			t.Errorf("route %q is registered but missing from api/openapi.yaml — add it under the qm tag", op)
		}
	}
	for op := range specOps {
		if !routeOps[op] {
			t.Errorf("operation %q is in api/openapi.yaml but has no qm-api route", op)
		}
	}
}

func ginPathToOpenAPI(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			segs[i] = "{" + s[1:] + "}"
		}
	}
	return strings.Join(segs, "/")
}

func opTags(op any) []string {
	m, ok := op.(map[string]any)
	if !ok {
		return nil
	}
	raw, _ := m["tags"].([]any)
	tags := make([]string, 0, len(raw))
	for _, t := range raw {
		if s, ok := t.(string); ok {
			tags = append(tags, s)
		}
	}
	return tags
}
