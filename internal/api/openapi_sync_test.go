package api

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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

// TestOpenAPISavedSnapshotContract protects the public distinction between a
// sandbox's replaceable pause checkpoint and immutable, reusable saved
// snapshots. Route parity alone cannot catch schema regressions such as making
// inherited lifecycle fields non-nullable or dropping fork lineage.
func TestOpenAPISavedSnapshotContract(t *testing.T) {
	doc := loadSpecDocument(t)

	t.Run("routes", func(t *testing.T) {
		want := map[string]map[string]string{
			"/sandboxes/{sandbox_id}/snapshots": {"post": "createSnapshot"},
			"/snapshots":                        {"get": "listSnapshots"},
			"/snapshots/{snapshot_id}":          {"get": "getSnapshot", "delete": "deleteSnapshot"},
		}
		for path, methods := range want {
			for method, operationID := range methods {
				op := specObjectAt(t, doc, "paths", path, method)
				if got := op["operationId"]; got != operationID {
					t.Errorf("%s %s operationId = %v, want %q", strings.ToUpper(method), path, got, operationID)
				}
			}
		}
		for path := range specObjectAt(t, doc, "paths") {
			if strings.Contains(strings.ToLower(path), "cascade") {
				t.Errorf("initial snapshot canary must not publish a cascade endpoint: %s", path)
			}
		}
	})

	t.Run("fork source and response lineage", func(t *testing.T) {
		create := specObjectAt(t, doc, "components", "schemas", "CreateSandboxRequest")
		properties := specObjectAt(t, create, "properties")
		fromSnapshot := specObjectAt(t, properties, "from_snapshot")
		if got := fromSnapshot["format"]; got != "uuid" {
			t.Errorf("CreateSandboxRequest.from_snapshot format = %v, want uuid", got)
		}

		excludedTogether := stringSet(t, specObjectAt(t, create, "not")["required"], "CreateSandboxRequest.not.required")
		if !reflect.DeepEqual(excludedTogether, map[string]bool{"from_snapshot": true, "from_template": true}) {
			t.Errorf("mutually excluded source fields = %v", excludedTogether)
		}

		listItem := specObjectAt(t, doc, "components", "schemas", "SandboxListItem")
		itemProperties := specObjectAt(t, listItem, "properties")
		checkpoint := specObjectAt(t, itemProperties, "snapshot_id")
		if checkpoint["deprecated"] != true {
			t.Errorf("SandboxListItem.snapshot_id must remain deprecated; got %v", checkpoint["deprecated"])
		}
		lineage := specObjectAt(t, itemProperties, "source_snapshot_id")
		if got := lineage["format"]; got != "uuid" {
			t.Errorf("SandboxListItem.source_snapshot_id format = %v, want uuid", got)
		}

		createResponse := specObjectAt(t, doc, "paths", "/sandboxes", "post", "responses", "201", "content", "application/json", "schema")
		if got := createResponse["$ref"]; got != "#/components/schemas/SandboxResponse" {
			t.Errorf("POST /sandboxes 201 schema = %v, want SandboxResponse", got)
		}
		responseAllOf := specListAt(t, specObjectAt(t, doc, "components", "schemas", "SandboxResponse"), "allOf")
		if !listHasRef(responseAllOf, "#/components/schemas/SandboxListItem") {
			t.Error("SandboxResponse must include SandboxListItem so source_snapshot_id is returned after a fork")
		}
	})

	t.Run("nullable lifecycle inheritance", func(t *testing.T) {
		properties := specObjectAt(t, doc, "components", "schemas", "CreateSandboxRequest", "properties")
		for _, field := range []string{"timeout_seconds", "auto_delete_seconds"} {
			schema := specObjectAt(t, properties, field)
			gotTypes := stringSet(t, schema["type"], "CreateSandboxRequest."+field+".type")
			wantTypes := map[string]bool{"integer": true, "null": true}
			if !reflect.DeepEqual(gotTypes, wantTypes) {
				t.Errorf("CreateSandboxRequest.%s types = %v, want integer|null", field, gotTypes)
			}
			description, _ := schema["description"].(string)
			if !strings.Contains(description, "inherits") || !strings.Contains(description, "explicit `null` disables") {
				t.Errorf("CreateSandboxRequest.%s must document omitted=inherit and null=disable", field)
			}
		}
	})

	t.Run("replacement and private preview isolation", func(t *testing.T) {
		properties := specObjectAt(t, doc, "components", "schemas", "CreateSandboxRequest", "properties")
		for _, field := range []string{"network", "secrets"} {
			description, _ := specObjectAt(t, properties, field)["description"].(string)
			description = strings.Join(strings.Fields(description), " ")
			if !strings.Contains(description, "inherit") || !strings.Contains(description, "full replacement") || !strings.Contains(description, "JSON `null` is invalid") {
				t.Errorf("CreateSandboxRequest.%s must document omitted=inherit, object=replace, and null=invalid", field)
			}
		}
		previewDescription, _ := specObjectAt(t, properties, "preview_access")["description"].(string)
		previewDescription = strings.Join(strings.Fields(previewDescription), " ")
		for _, phrase := range []string{"zero published ports", "never inherits", "child-scoped preview token"} {
			if !strings.Contains(previewDescription, phrase) {
				t.Errorf("CreateSandboxRequest.preview_access is missing %q", phrase)
			}
		}
	})

	t.Run("saved snapshot response is complete and host opaque", func(t *testing.T) {
		snapshot := specObjectAt(t, doc, "components", "schemas", "SnapshotResponse")
		required := stringSet(t, snapshot["required"], "SnapshotResponse.required")
		for _, field := range []string{
			"id", "status", "sandbox_id", "vcpu_count", "memory_mib", "disk_mib",
			"logical_size_bytes", "exclusive_size_bytes", "child_sandbox_count",
			"child_snapshot_count", "created_at", "updated_at",
		} {
			if !required[field] {
				t.Errorf("SnapshotResponse.required is missing %q", field)
			}
		}

		properties := specObjectAt(t, snapshot, "properties")
		for _, internal := range []string{
			"host_id", "path", "mem_path", "manifest_path", "manifest_digest",
			"artifact_metadata", "secret_bindings", "failure_reason",
		} {
			if _, exposed := properties[internal]; exposed {
				t.Errorf("SnapshotResponse exposes host/internal field %q", internal)
			}
		}

		statuses := stringSet(t, specObjectAt(t, properties, "status")["enum"], "SnapshotResponse.status.enum")
		wantStatuses := map[string]bool{
			"creating": true, "ready": true, "unavailable": true, "failed": true, "deleting": true,
		}
		if !reflect.DeepEqual(statuses, wantStatuses) {
			t.Errorf("SnapshotResponse statuses = %v, want %v", statuses, wantStatuses)
		}
	})

	t.Run("delete is retryable but non cascading", func(t *testing.T) {
		pathItem := specObjectAt(t, doc, "paths", "/snapshots/{snapshot_id}")
		deleteOp := specObjectAt(t, pathItem, "delete")
		responses := specObjectAt(t, deleteOp, "responses")
		unavailable := specObjectAt(t, responses, "503")
		if got := unavailable["$ref"]; got != "#/components/responses/SnapshotHostUnavailable" {
			t.Errorf("DELETE /snapshots/{snapshot_id} 503 = %v, want SnapshotHostUnavailable", got)
		}
		conflictSchema := specObjectAt(t, responses, "409", "content", "application/json", "schema")
		if !listHasRef(specListAt(t, conflictSchema, "anyOf"), "#/components/schemas/DependencyConflictError") {
			t.Error("snapshot delete 409 must document snapshot_has_dependents details")
		}
		if operationHasParameter(pathItem, "cascade") || operationHasParameter(deleteOp, "cascade") {
			t.Error("initial snapshot delete must not accept a cascade parameter")
		}

		hostUnavailable := specObjectAt(t, doc, "components", "responses", "SnapshotHostUnavailable")
		_ = specObjectAt(t, hostUnavailable, "headers", "Retry-After")
		captureResponses := specObjectAt(t, doc, "paths", "/sandboxes/{sandbox_id}/snapshots", "post", "responses")
		if _, ok := captureResponses["410"]; !ok {
			t.Error("snapshot capture must document permanent artifact loss as 410")
		}
	})

	t.Run("snapshot-derived resume capacity is retryable", func(t *testing.T) {
		for _, path := range []string{
			"/sandboxes/{sandbox_id}/resume",
			"/sandboxes/{sandbox_id}/activate",
		} {
			unavailable := specObjectAt(t, doc, "paths", path, "post", "responses", "503")
			if got := unavailable["$ref"]; got != "#/components/responses/SandboxResumeHostUnavailable" {
				t.Errorf("POST %s 503 = %v, want SandboxResumeHostUnavailable", path, got)
			}
		}

		resumeUnavailable := specObjectAt(t, doc, "components", "responses", "SandboxResumeHostUnavailable")
		description, ok := resumeUnavailable["description"].(string)
		if !ok {
			t.Fatal("SandboxResumeHostUnavailable.description must be a string")
		}
		for _, code := range []string{"sandbox_host_unavailable", "snapshot_host_unavailable"} {
			if !strings.Contains(description, code) {
				t.Errorf("SandboxResumeHostUnavailable.description must document %q", code)
			}
		}
	})

	t.Run("snapshot authorization and terminal capture failure", func(t *testing.T) {
		for _, operation := range []struct {
			path, method string
		}{
			{path: "/snapshots", method: "get"},
			{path: "/snapshots/{snapshot_id}", method: "get"},
			{path: "/snapshots/{snapshot_id}", method: "delete"},
		} {
			responses := specObjectAt(t, doc, "paths", operation.path, operation.method, "responses")
			forbidden := specObjectAt(t, responses, "403")
			if got := forbidden["$ref"]; got != "#/components/responses/Forbidden" {
				t.Errorf("%s %s 403 = %v, want Forbidden", strings.ToUpper(operation.method), operation.path, got)
			}
		}

		capture500 := specObjectAt(t, doc, "paths", "/sandboxes/{sandbox_id}/snapshots", "post", "responses", "500")
		description, _ := capture500["description"].(string)
		if !strings.Contains(description, "snapshot_source_failed") {
			t.Error("snapshot capture 500 must document snapshot_source_failed")
		}
		errorDescription, _ := specObjectAt(t, doc, "components", "schemas", "Error")["description"].(string)
		if !strings.Contains(errorDescription, "snapshot_source_failed") {
			t.Error("Error code catalog must include snapshot_source_failed")
		}
	})
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

// loadSpecOps parses api/openapi.yaml and returns its operations as "METHOD /path".
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
		for key := range item {
			if m := strings.ToUpper(key); httpMethods[m] {
				ops[m+" "+path] = true
			}
		}
	}
	return ops
}

func loadSpecDocument(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	return doc
}

func specObjectAt(t *testing.T, root map[string]any, keys ...string) map[string]any {
	t.Helper()
	var current any = root
	path := "#"
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("%s is %T, want object while looking up %q", path, current, key)
		}
		var found bool
		current, found = object[key]
		path += "/" + key
		if !found {
			t.Fatalf("missing OpenAPI value %s", path)
		}
	}
	object, ok := current.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", path, current)
	}
	return object
}

func specListAt(t *testing.T, root map[string]any, key string) []any {
	t.Helper()
	value, ok := root[key]
	if !ok {
		t.Fatalf("missing OpenAPI list %q", key)
	}
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("OpenAPI value %q is %T, want list", key, value)
	}
	return list
}

func stringSet(t *testing.T, value any, path string) map[string]bool {
	t.Helper()
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is %T, want string list", path, value)
	}
	out := make(map[string]bool, len(list))
	for i, raw := range list {
		s, ok := raw.(string)
		if !ok {
			t.Fatalf("%s[%d] is %T, want string", path, i, raw)
		}
		out[s] = true
	}
	return out
}

func listHasRef(list []any, want string) bool {
	for _, item := range list {
		object, ok := item.(map[string]any)
		if ok && object["$ref"] == want {
			return true
		}
	}
	return false
}

func operationHasParameter(operation map[string]any, name string) bool {
	raw, ok := operation["parameters"]
	if !ok {
		return false
	}
	parameters, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, parameter := range parameters {
		object, ok := parameter.(map[string]any)
		if ok && object["name"] == name {
			return true
		}
	}
	return false
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
