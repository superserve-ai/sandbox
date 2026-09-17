package main

import (
	"errors"
	"net"
	"testing"

	"github.com/rs/zerolog"
)

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func addrOf(l net.Listener) string { return l.Addr().String() }

func TestInheritedListenersMatchByPort(t *testing.T) {
	public, redirect, stray := listenLocal(t), listenLocal(t), listenLocal(t)
	inherit := func() ([]net.Listener, error) { return []net.Listener{stray, redirect, nil, public}, nil }
	gotPublic, gotRedirect := inheritedListeners(inherit, addrOf(public), addrOf(redirect), zerolog.Nop())
	if gotPublic != public || gotRedirect != redirect {
		t.Fatalf("got %v/%v, want the listeners on %s and %s", gotPublic, gotRedirect, addrOf(public), addrOf(redirect))
	}
	// The unmatched listener was closed.
	if _, err := stray.Accept(); err == nil {
		t.Fatal("stray inherited listener was left open")
	}
}

func TestInheritedListenersNoneWithoutSocketUnit(t *testing.T) {
	for _, inherit := range []func() ([]net.Listener, error){
		func() ([]net.Listener, error) { return nil, nil },
		func() ([]net.Listener, error) { return nil, errors.New("not activated") },
	} {
		public, redirect := inheritedListeners(inherit, ":5007", ":5008", zerolog.Nop())
		if public != nil || redirect != nil {
			t.Fatalf("expected nil listeners, got %v/%v", public, redirect)
		}
	}
}

func TestInheritedListenersRedirectMayBindItself(t *testing.T) {
	public := listenLocal(t)
	inherit := func() ([]net.Listener, error) { return []net.Listener{public}, nil }
	gotPublic, gotRedirect := inheritedListeners(inherit, addrOf(public), ":5008", zerolog.Nop())
	if gotPublic != public || gotRedirect != nil {
		t.Fatalf("got %v/%v, want the public listener and no redirect", gotPublic, gotRedirect)
	}
}
