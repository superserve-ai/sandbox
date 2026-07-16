package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

func TestSdbusDo_FlagOff_NotHandled(t *testing.T) {
	SetSystemdDBusEnabled(false)
	called := false
	err, handled := sdbusDo(func(*sddbus.Conn) error {
		called = true
		return nil
	})
	if handled || err != nil || called {
		t.Fatalf("flag off must not touch D-Bus: handled=%v err=%v called=%v", handled, err, called)
	}
}

func TestSdbusAnswer(t *testing.T) {
	if _, ok := sdbusAnswer(nil); !ok {
		t.Fatal("nil is an answer")
	}
	methodErr := dbus.Error{Name: "org.freedesktop.systemd1.NoSuchUnit"}
	if err, ok := sdbusAnswer(methodErr); !ok || err == nil {
		t.Fatal("a D-Bus method error is an answer and must surface")
	}
	// Transport-shaped errors must NOT count as answers — they route the
	// call to the exec fallback.
	for _, terr := range []error{
		dbus.ErrClosed,
		io.EOF, // what an in-flight call sees when the transport dies
		errors.New("read unix @->/run/systemd/private: use of closed network connection"),
	} {
		if _, ok := sdbusAnswer(terr); ok {
			t.Fatalf("%v must be transport-shaped, not an answer", terr)
		}
	}
}

func TestSdbusCondemns(t *testing.T) {
	// Caller cancellation must not condemn the shared connection.
	if sdbusCondemns(context.Canceled) || sdbusCondemns(fmt.Errorf("call: %w", context.DeadlineExceeded)) {
		t.Fatal("caller ctx expiry is the call's result, not a dead bus")
	}
	if !sdbusCondemns(io.EOF) || !sdbusCondemns(dbus.ErrClosed) {
		t.Fatal("real transport death must condemn the connection")
	}
}

func TestSdbusNotLoaded(t *testing.T) {
	if !sdbusNotLoaded(dbus.Error{Name: "org.freedesktop.systemd1.NoSuchUnit"}) {
		t.Fatal("NoSuchUnit is the definitive not-loaded answer")
	}
	if !sdbusNotLoaded(dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}) {
		t.Fatal("UnknownObject (unloaded template instance) is not-loaded")
	}
	if sdbusNotLoaded(dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"}) {
		t.Fatal("other method errors are not the not-loaded answer")
	}
	if sdbusNotLoaded(io.EOF) {
		t.Fatal("transport errors are not the not-loaded answer")
	}
}
