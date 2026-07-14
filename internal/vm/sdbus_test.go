package vm

import (
	"context"
	"errors"
	"testing"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

func TestSdbusDo_FlagOff_NotHandled(t *testing.T) {
	SetSystemdDBusEnabled(false)
	called := false
	err, handled := sdbusDo(context.Background(), func(*sddbus.Conn) error {
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
	if _, ok := sdbusAnswer(errors.New("write unix @->/run/systemd/private: broken pipe")); ok {
		t.Fatal("a transport error is not an answer (must fall back to exec)")
	}
	if sdbusClosed(methodErr) {
		t.Fatal("a method error is not a closed connection")
	}
	if !sdbusClosed(dbus.ErrClosed) {
		t.Fatal("ErrClosed must trigger the redial path")
	}
}
