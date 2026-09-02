package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The lifecycle routes answer the supervisor only: a request from one of the
// guest's own addresses is refused before the handler runs.
func TestLifecycleRoutesRefuseTheGuest(t *testing.T) {
	orig := localAddrs
	t.Cleanup(func() { localAddrs = orig })
	localAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("169.254.0.21"), Mask: net.CIDRMask(30, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		}, nil
	}
	called := 0
	h := hostOnly(func(http.ResponseWriter, *http.Request) { called++ })
	for _, remote := range []string{"127.0.0.1:4000", "[::1]:4000", "169.254.0.21:4000", "0.0.0.0:4000", "garbage"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/freeze", nil)
		req.RemoteAddr = remote
		h(rec, req)
		if rec.Code != http.StatusForbidden || called != 0 {
			t.Fatalf("remote %q: code=%d called=%d, want 403 and no handler", remote, rec.Code, called)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/freeze", nil)
	req.RemoteAddr = "10.12.0.1:4000"
	h(rec, req)
	if called != 1 || rec.Code != http.StatusOK {
		t.Fatalf("outside peer: called=%d code=%d, want the handler", called, rec.Code)
	}
}
