package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestPreviewPublicationLegacyAllowsAnyPort(t *testing.T) {
	for _, access := range []string{"", preview.AccessLegacyPublic} {
		w := httptest.NewRecorder()
		if !enforcePreviewPublication(w, 3000, InstanceInfo{PreviewAccess: access}) {
			t.Fatalf("access %q denied a legacy port", access)
		}
	}
}

func TestPreviewPublicationStrictRequiresPublishedPort(t *testing.T) {
	info := InstanceInfo{
		PreviewAccess: preview.AccessPublic,
		PreviewPorts:  map[int]struct{}{3001: {}},
	}
	w := httptest.NewRecorder()
	if enforcePreviewPublication(w, 3000, info) {
		t.Fatal("unpublished port was allowed")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	if !enforcePreviewPublication(w, 3001, info) {
		t.Fatalf("published public port denied with status %d", w.Code)
	}
}

func TestPreviewPublicationUnknownPolicyFailsClosedEvenWhenPublished(t *testing.T) {
	w := httptest.NewRecorder()
	info := InstanceInfo{
		PreviewAccess: "future-mode",
		PreviewPorts:  map[int]struct{}{3000: {}},
	}
	if enforcePreviewPublication(w, 3000, info) {
		t.Fatal("unknown policy routed a published port")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
