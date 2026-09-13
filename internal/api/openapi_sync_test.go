package api

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	yaml "go.yaml.in/yaml/v3"
)

// dataPlaneSpecPaths are documented in the spec but served by boxd, not the
// control-plane router, so they have no route here.
var dataPlaneSpecPaths = map[string]bool{
	"/files":        true,
	"/exec":         true,
	"/exec/stream":  true,
	"/exec/connect": true,
}

// TestOpenAPISpecMatchesRoutes fails if a registered route is missing from
// api/openapi.yaml, or a documented operation has no route — keeping the two
// in sync. Mismatches are reported as exact "METHOD /path".
func TestOpenAPISpecMatchesRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// An empty Handlers suffices to enumerate routes; the handlers are never called.
	router := SetupRouter(ctx, &Handlers{}, nil)

	routeOps := map[string]bool{}
	for _, ri := range router.Routes() {
		// Internal infra endpoints are intentionally undocumented.
		if strings.HasPrefix(ri.Path, "/internal/") {
			continue
		}
		routeOps[ri.Method+" "+ginPathToOpenAPI(ri.Path)] = true
	}

	specOps := loadSpecOps(t)

	// Every control-plane route must be documented.
	for op := range routeOps {
		if !specOps[op] {
			t.Errorf("route %q is registered but missing from api/openapi.yaml — add it to the spec", op)
		}
	}

	// Every documented operation must have a route, except data-plane paths.
	for op := range specOps {
		path := strings.SplitN(op, " ", 2)[1]
		if dataPlaneSpecPaths[path] {
			continue
		}
		if !routeOps[op] {
			t.Errorf("operation %q is in api/openapi.yaml but has no control-plane route — remove it from the spec or implement it", op)
		}
	}
}

func TestOpenAPIPreviewTokenIsDocumentedAsARequestCredential(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	spec := string(data)
	if strings.Contains(spec, "response's `X-Superserve-Preview-Token` header") {
		t.Fatal("OpenAPI describes the preview token as a response header instead of a request credential")
	}
	for _, required := range []string{
		"a request header named `X-Superserve-Preview-Token`",
		"whose name is the response's `header` value",
	} {
		if !strings.Contains(spec, required) {
			t.Errorf("OpenAPI preview-token guidance is missing %q", required)
		}
	}
}

// qmSpecTag marks operations served by the qm-api binary (internal/qm);
// its own sync test holds them to the qm router.
const qmSpecTag = "qm"

// loadSpecOps parses api/openapi.yaml and returns the control plane's
// operations as "METHOD /path", leaving out those tagged for qm-api.
func loadSpecOps(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	// Only the HTTP-method keys are operations (skip parameters/servers/etc.).
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}

	httpMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "PATCH": true,
		"DELETE": true, "HEAD": true, "OPTIONS": true,
	}
	ops := map[string]bool{}
	for path, item := range doc.Paths {
		for key, op := range item {
			m := strings.ToUpper(key)
			if !httpMethods[m] || slices.Contains(opTags(op), qmSpecTag) {
				continue
			}
			ops[m+" "+path] = true
		}
	}
	return ops
}

// ginPathToOpenAPI rewrites gin's ":param" segments into OpenAPI's "{param}" form.
func ginPathToOpenAPI(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			segs[i] = "{" + s[1:] + "}"
		}
	}
	return strings.Join(segs, "/")
}

// opTags returns an operation's tags; path-level keys like parameters are
// not operations and yield none.
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
