package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jezek/xgb/xproto"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// testKeymap is a two-column US-like layout starting at keycode 8:
// 8 a/A, 9 u/U, 10 1/!, 11 space, 12 Return, 13 Shift_L, 14 Control_L,
// then `spares` empty keycodes.
func testKeymap(spares int) *x11Keymap {
	rows := [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}}
	var syms []xproto.Keysym
	for _, r := range rows {
		syms = append(syms, r[0], r[1])
	}
	for i := 0; i < spares; i++ {
		syms = append(syms, 0, 0)
	}
	return buildKeymap(8, 2, syms, nil)
}

const (
	kcA = xproto.Keycode(8 + iota)
	kcU
	kc1
	kcSpace
	kcReturn
	kcShift
	kcControl
	kcSpare0
	kcSpare1
)

func events(pairs ...any) []keyEvent {
	var out []keyEvent
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, keyEvent{code: pairs[i].(xproto.Keycode), press: pairs[i+1].(bool)})
	}
	return out
}

func tapEvents(code xproto.Keycode) []keyEvent { return events(code, true, code, false) }

func shiftedTap(code xproto.Keycode) []keyEvent {
	return events(kcShift, true, code, true, code, false, kcShift, false)
}

func textEvent(text string) *pb.KeyEvent {
	return &pb.KeyEvent{Input: &pb.KeyEvent_Text{Text: text}}
}

func chordEvent(key string, modifiers ...string) *pb.KeyEvent {
	return &pb.KeyEvent{Input: &pb.KeyEvent_Key{Key: key}, Modifiers: modifiers}
}

func eventsEqual(t *testing.T, got, want []keyEvent) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("events = %v\nwant     %v", got, want)
	}
}

func TestKeysymFromName(t *testing.T) {
	cases := map[string]uint32{
		"Return": 0xff0d, "return": 0xff0d, "ctrl": 0xffe3, "Control_L": 0xffe3, "super": 0xffeb,
		"a": 'a', "A": 'A', "+": '+', "é": 0xe9, "€": 0x01000000 | 0x20ac,
		"F5": 0xffc2, "F12": 0xffc9, "KP_Enter": 0xff8d, "KP_7": 0xffb7, "Page_Up": 0xff55,
		"U+00E9": 0xe9, "U20AC": 0x01000000 | 0x20ac, "0xff0d": 0xff0d, "space": ' ',
	}
	for name, want := range cases {
		got, ok := keysymFromName(name)
		if !ok || got != want {
			t.Errorf("keysymFromName(%q) = %#x, %v; want %#x", name, got, ok, want)
		}
	}
	for _, name := range []string{"XF86AudioPlay", "", "\x01", "Uzz", "0xzz"} {
		if ks, ok := keysymFromName(name); ok {
			t.Errorf("keysymFromName(%q) = %#x, want unresolved", name, ks)
		}
	}
}

func TestNormalizeKeyText(t *testing.T) {
	if got, err := normalizeKeyText("a\r\nb\rc\td\n"); err != nil || got != "a\nb\nc\td\n" {
		t.Errorf("normalize = %q, %v", got, err)
	}
	for _, bad := range []string{"a\x01b", "\x7f", "\xff\xfe", "\x85"} {
		if _, err := normalizeKeyText(bad); err == nil {
			t.Errorf("normalizeKeyText(%q) accepted", bad)
		}
	}
}

func TestPlanKey_TextUsesTheLayoutAndShift(t *testing.T) {
	km := testKeymap(2)
	segs, err := planKey(km, textEvent("aA1! \n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || len(segs[0].binds) != 0 {
		t.Fatalf("segments = %+v, want one with no binds", segs)
	}
	var want []keyEvent
	want = append(want, tapEvents(kcA)...)
	want = append(want, shiftedTap(kcA)...)
	want = append(want, tapEvents(kc1)...)
	want = append(want, shiftedTap(kc1)...)
	want = append(want, tapEvents(kcSpace)...)
	want = append(want, tapEvents(kcReturn)...)
	eventsEqual(t, segs[0].events, want)
	if len(km.bound) != 0 {
		t.Errorf("layout text bound scratch keycodes: %v", km.bound)
	}
}

func TestPlanKey_UnmappedCharactersBindScratchKeycodesOnce(t *testing.T) {
	km := testKeymap(2)
	segs, err := planKey(km, textEvent("é€é"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("segments = %d, want 1 (pool not exhausted)", len(segs))
	}
	wantBinds := []keyBind{{kcSpare0, 0xe9}, {kcSpare1, 0x01000000 | 0x20ac}}
	if fmt.Sprint(segs[0].binds) != fmt.Sprint(wantBinds) {
		t.Errorf("binds = %v, want %v", segs[0].binds, wantBinds)
	}
	var want []keyEvent
	want = append(want, tapEvents(kcSpare0)...)
	want = append(want, tapEvents(kcSpare1)...)
	want = append(want, tapEvents(kcSpare0)...)
	eventsEqual(t, segs[0].events, want)

	// The bindings persist: typing é again needs no bind at all.
	segs, err = planKey(km, textEvent("é"))
	if err != nil || len(segs) != 1 || len(segs[0].binds) != 0 {
		t.Fatalf("second plan = %+v, %v; want no binds", segs, err)
	}
	eventsEqual(t, segs[0].events, tapEvents(kcSpare0))
}

func TestPlanKey_ExhaustedPoolRebindsInANewSegment(t *testing.T) {
	km := testKeymap(1)
	segs, err := planKey(km, textEvent("éàé"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 3 {
		t.Fatalf("segments = %d, want 3: every rebind of the one spare after use starts a segment", len(segs))
	}
	for i, ks := range []uint32{0xe9, 0xe0, 0xe9} {
		if fmt.Sprint(segs[i].binds) != fmt.Sprint([]keyBind{{kcSpare0, ks}}) {
			t.Errorf("segment %d binds = %v, want %#x on the spare", i, segs[i].binds, ks)
		}
		eventsEqual(t, segs[i].events, tapEvents(kcSpare0))
	}
}

func TestPlanKey_Chords(t *testing.T) {
	km := testKeymap(1)
	cases := []struct {
		name string
		ev   *pb.KeyEvent
		want []keyEvent
	}{
		{"modifier field", chordEvent("u", "ctrl"),
			events(kcControl, true, kcU, true, kcU, false, kcControl, false)},
		{"xdotool chord syntax", chordEvent("ctrl+a"),
			events(kcControl, true, kcA, true, kcA, false, kcControl, false)},
		{"shifted key adds Shift", chordEvent("A", "ctrl"),
			events(kcControl, true, kcShift, true, kcA, true, kcA, false, kcShift, false, kcControl, false)},
		{"shift already held", chordEvent("A", "ctrl", "shift"),
			events(kcControl, true, kcShift, true, kcA, true, kcA, false, kcShift, false, kcControl, false)},
		{"literal plus", chordEvent("+"),
			tapEvents(kcSpare0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			segs, err := planKey(km, tc.ev)
			if err != nil {
				t.Fatal(err)
			}
			if len(segs) != 1 {
				t.Fatalf("segments = %d, want 1", len(segs))
			}
			eventsEqual(t, segs[0].events, tc.want)
		})
	}
}

func TestPlanKey_DeclinesBeforeTouchingTheServer(t *testing.T) {
	cases := map[string]struct {
		spares int
		ev     *pb.KeyEvent
	}{
		"unknown key name":       {1, chordEvent("XF86AudioPlay")},
		"unknown modifier":       {1, chordEvent("a", "XF86Launch1")},
		"modifier not in layout": {1, chordEvent("a", "alt")},
		"no spare keycode":       {0, textEvent("é")},
	}
	for name, tc := range cases {
		km := testKeymap(tc.spares)
		before := len(km.bound)
		_, err := planKey(km, tc.ev)
		if !errors.Is(err, errBackendKept) {
			t.Errorf("%s: err = %v, want errBackendKept", name, err)
		}
		if len(km.bound) != before {
			t.Errorf("%s: a declined plan changed the scratch state", name)
		}
	}
	if _, err := planKey(testKeymap(1), textEvent("a\x01")); err == nil || errors.Is(err, errBackendKept) {
		t.Errorf("control character: err = %v, want a validation error, not a fallback", err)
	}
}

func TestBuildKeymap_KeepsScratchBindingsAcrossReload(t *testing.T) {
	km := testKeymap(2)
	if _, err := planKey(km, textEvent("é")); err != nil {
		t.Fatal(err)
	}
	// A reload after an external MappingNotify sees our scratch keycode with
	// a keysym now; it must stay scratch, not become a layout key for é.
	syms := make([]xproto.Keysym, 0, 9*2)
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xe9, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	reloaded := buildKeymap(8, 2, syms, km.bound)
	if _, direct := reloaded.direct[0xe9]; direct {
		t.Error("scratch keycode was promoted to a layout key")
	}
	if reloaded.bound[kcSpare0] != 0xe9 || len(reloaded.spare) != 2 {
		t.Errorf("bound = %v, spare = %v; want é kept on %d and both keycodes in the pool", reloaded.bound, reloaded.spare, kcSpare0)
	}

	// A reload that no longer types é on that keycode drops the binding:
	// cleared, it is spare again; rewritten, it is a layout key.
	cleared := append(append([]xproto.Keysym{}, syms[:14]...), 0, 0, 0, 0)
	if r := buildKeymap(8, 2, cleared, km.bound); len(r.bound) != 0 || len(r.spare) != 2 {
		t.Errorf("cleared row: bound = %v, spare = %v; want no binding and two spares", r.bound, r.spare)
	}
	rewritten := append(append([]xproto.Keysym{}, syms[:14]...), 'z', 'Z', 0, 0)
	r := buildKeymap(8, 2, rewritten, km.bound)
	if len(r.bound) != 0 || r.direct['z'].code != kcSpare0 || len(r.spare) != 1 {
		t.Errorf("rewritten row: bound = %v, direct[z] = %v, spare = %v; want z on %d and one spare", r.bound, r.direct['z'], r.spare, kcSpare0)
	}
}

// A declined plan must fall back to xdotool and keep the connection: the
// fake backend has a keymap but no socket, so any emission would panic.
func TestExecKey_DeclineFallsBackWithoutDroppingTheBackend(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	withFakeBin(t, map[string]string{"xdotool": fmt.Sprintf("echo \"$@\" >> %q\nexit 0\n", logFile)})
	s := newDesktopService(&sandboxContext{})
	b := withFakeBackend(s)
	b.keys = testKeymap(1)

	ev := chordEvent("XF86AudioPlay")
	args, err := keyArgs(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.execKey(context.Background(), ev, args); err != nil {
		t.Fatalf("execKey: %v", err)
	}
	if s.x11.backend != b {
		t.Error("declined plan dropped the backend")
	}
	got, _ := os.ReadFile(logFile)
	if !strings.Contains(string(got), "key -- XF86AudioPlay") {
		t.Errorf("xdotool log = %q, want the chord delivered through xdotool", got)
	}
}
