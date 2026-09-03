package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The lifecycle routes answer the supervisor only: a request from one of the
// guest's own addresses is refused before the handler runs.
func TestLifecycleRoutesRefuseTheGuest(t *testing.T) {
	reads := 0
	g := &hostGate{addrs: func() ([]net.Addr, error) {
		reads++
		if reads == 1 {
			return nil, errors.New("not yet")
		}
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("169.254.0.21"), Mask: net.CIDRMask(30, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		}, nil
	}}
	called := 0
	h := g.only(func(http.ResponseWriter, *http.Request) { called++ })

	// Until the addresses are known nothing is let through, not even an
	// outside peer.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/freeze", nil)
	req.RemoteAddr = "10.12.0.1:4000"
	h(rec, req)
	if rec.Code != http.StatusForbidden || called != 0 {
		t.Fatalf("unread addresses: code=%d called=%d, want 403 and no handler", rec.Code, called)
	}
	for _, remote := range []string{"127.0.0.1:4000", "[::1]:4000", "169.254.0.21:4000", "0.0.0.0:4000", "garbage"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/freeze", nil)
		req.RemoteAddr = remote
		h(rec, req)
		if rec.Code != http.StatusForbidden || called != 0 {
			t.Fatalf("remote %q: code=%d called=%d, want 403 and no handler", remote, rec.Code, called)
		}
	}
	rec = httptest.NewRecorder()
	req.RemoteAddr = "10.12.0.1:4000"
	h(rec, req)
	if called != 1 || rec.Code != http.StatusOK {
		t.Fatalf("outside peer: called=%d code=%d, want the handler", called, rec.Code)
	}
	// A failed read is retried; a successful one is kept for good.
	h(rec, req)
	h(rec, req)
	if reads != 2 {
		t.Fatalf("interface addresses read %d times, want 2 (one failure, one kept)", reads)
	}
}
