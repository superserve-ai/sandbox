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
		if !enforcePreviewPublication(w, 3000, InstanceInfo{
			PreviewAccess:     access,
			PreviewPorts:      map[int]struct{}{3001: {}},
			PreviewPortAccess: map[int]string{3001: preview.AccessPrivate},
		}) {
			t.Fatalf("access %q denied a legacy port", access)
		}
	}
}

func TestPreviewPublicationLegacyHonorsExactNonPublicRecord(t *testing.T) {
	for _, mode := range []string{preview.AccessPrivate, "future-mode"} {
		w := httptest.NewRecorder()
		if enforcePreviewPublication(w, 3000, InstanceInfo{
			PreviewAccess:     preview.AccessLegacyPublic,
			PreviewPorts:      map[int]struct{}{3000: {}},
			PreviewPortAccess: map[int]string{3000: mode},
		}) {
			t.Fatalf("legacy snapshot routed exact %q port", mode)
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("mode %q status = %d, want 401", mode, w.Code)
		}
	}
}

func TestPreviewPublicationStrictRequiresPublishedPort(t *testing.T) {
	info := InstanceInfo{
		PreviewAccess:     preview.AccessPublic,
		PreviewPorts:      map[int]struct{}{3001: {}},
		PreviewPortAccess: map[int]string{3001: preview.AccessPublic},
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

func TestPreviewPublicationPerPortModes(t *testing.T) {
	info := InstanceInfo{
		// The hardened rollback fallback is private for a mixed policy, but the
		// Phase 2 proxy still honors each explicit per-port exception.
		PreviewAccess: preview.AccessPrivate,
		PreviewPorts:  map[int]struct{}{3000: {}, 3001: {}, 3002: {}, 3003: {}},
		PreviewPortAccess: map[int]string{
			3000: preview.AccessPublic,
			3001: preview.AccessPrivate,
			3002: "future-mode",
		},
	}

	w := httptest.NewRecorder()
	if !enforcePreviewPublication(w, 3000, info) {
		t.Fatalf("explicit public port denied with status %d", w.Code)
	}
	for _, port := range []int{3001, 3002, 3003} {
		w = httptest.NewRecorder()
		if enforcePreviewPublication(w, port, info) {
			t.Fatalf("port %d unexpectedly routed", port)
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("port %d status = %d, want 401", port, w.Code)
		}
	}
}

func TestPreviewPublicationUnknownPolicyFailsClosedEvenWhenPublished(t *testing.T) {
	w := httptest.NewRecorder()
	info := InstanceInfo{
		PreviewAccess:     "future-mode",
		PreviewPorts:      map[int]struct{}{3000: {}},
		PreviewPortAccess: map[int]string{3000: preview.AccessPublic},
	}
	if enforcePreviewPublication(w, 3000, info) {
		t.Fatal("unknown policy routed a published port")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
