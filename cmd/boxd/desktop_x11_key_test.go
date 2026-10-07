package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jezek/xgb/xproto"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// testKeymap is a two-column US-like layout starting at keycode 8:
// 8 a/A, 9 u/U, 10 1/!, 11 space, 12 Return, 13 Shift_L, 14 Control_L,
// 15 KP_End/KP_1, 16 Pause/Break, then `spares` usable empty keycodes
// (plus the one the keymap reserves for xdotool).
func testKeymap(spares int) *x11Keymap {
	rows := [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}}
	var syms []xproto.Keysym
	for _, r := range rows {
		syms = append(syms, r[0], r[1])
	}
	for i := 0; i < spares+1; i++ {
		syms = append(syms, 0, 0)
	}
	return buildKeymap(8, 2, syms, nil, nil)
}

func TestBuildKeymap_ReservesOneKeycodeForTheFallback(t *testing.T) {
	km := testKeymap(1)
	reserved := xproto.Keycode(int(kcSpare0) + 1)
	if len(km.spare) != 1 || km.spare[0] != kcSpare0 {
		t.Fatalf("spare = %v, want just %d with %d held back", km.spare, kcSpare0, reserved)
	}
	// Two unmapped characters do not fit in a one-keycode pool; the
	// reserved keycode is never used to make them fit.
	if _, err := planKey(km, xkbState{}, textEvent("éà")); !errors.Is(err, errBackendKept) {
		t.Fatalf("err = %v, want errBackendKept (keycode %d is reserved)", err, reserved)
	}
}

const (
	kcA = xproto.Keycode(8 + iota)
	kcU
	kc1
	kcSpace
	kcReturn
	kcShift
	kcControl
	kcKeypad1
	kcPause
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

func bindsEqual(t *testing.T, got, want []keyBind) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("binds = %v\nwant    %v", got, want)
	}
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
	segs, err := planKey(km, xkbState{}, textEvent("aA1! \n"))
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
	segs, err := planKey(km, xkbState{}, textEvent("é€é"))
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
	segs, err = planKey(km, xkbState{}, textEvent("é"))
	if err != nil || len(segs) != 1 || len(segs[0].binds) != 0 {
		t.Fatalf("second plan = %+v, %v; want no binds", segs, err)
	}
	eventsEqual(t, segs[0].events, tapEvents(kcSpare0))
}

// A keycode is never rebound within one request: when the pool runs out
// the request declines, with nothing bound.
func TestPlanKey_ExhaustedPoolDeclines(t *testing.T) {
	km := testKeymap(1)
	_, err := planKey(km, xkbState{}, textEvent("éà"))
	if !errors.Is(err, errBackendKept) {
		t.Fatalf("err = %v, want errBackendKept", err)
	}
	if len(km.bound) != 0 {
		t.Errorf("a declined plan bound %v", km.bound)
	}
	// The same characters fit across two requests: the first binds é, the
	// second evicts it for à.
	if _, err := planKey(km, xkbState{}, textEvent("é")); err != nil {
		t.Fatal(err)
	}
	segs, err := planKey(km, xkbState{}, textEvent("à"))
	if err != nil {
		t.Fatal(err)
	}
	bindsEqual(t, segs[0].binds, []keyBind{{kcSpare0, 0xe0}})
}

// A native layout key carries a legacy keysym; text written by code point
// must still find it rather than bind a scratch keycode.
func TestBuildKeymap_AliasesLegacyKeysymsByCodePoint(t *testing.T) {
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{0x7e1, 0x7c1}, {0x6c1, 0x6e1}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1]) // Greek_alpha/ALPHA, Cyrillic_a/A
	}
	km := buildKeymap(8, 2, syms, nil, nil)
	segs, err := planKey(km, xkbState{}, textEvent("αΑа"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segs[0].binds) != 0 {
		t.Errorf("binds = %v, want none: the layout has these letters", segs[0].binds)
	}
	alpha, cyrA, shift := xproto.Keycode(8), xproto.Keycode(9), xproto.Keycode(12)
	var want []keyEvent
	want = append(want, tapEvents(alpha)...)
	want = append(want, events(shift, true, alpha, true, alpha, false, shift, false)...)
	want = append(want, tapEvents(cyrA)...)
	eventsEqual(t, segs[0].events, want)
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
			segs, err := planKey(km, xkbState{}, tc.ev)
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

// Changing DISPLAY while no backend is attached must still forget the old
// server's scratch bindings.
func TestX11Holder_DisplayChangeForgetsBindingsWithoutABackend(t *testing.T) {
	s := newDesktopService(&sandboxContext{})
	b := withFakeBackend(s)
	b.keys = testKeymap(1)
	s.x11.drop(b)
	if s.x11.keys == nil {
		t.Fatal("drop did not keep the keymap")
	}
	s.x11.disabled = false
	s.x11.lastProbe = time.Now() // no dial: the cooldown returns nil
	s.x11.get(context.Background(), ":99")
	if s.x11.keys != nil {
		t.Error("bindings from the old display survived a DISPLAY change")
	}
}

// An empty row that is still a modifier (say, Lock) is not scratch.
func TestBuildKeymap_ExcludesModifierKeycodesFromThePool(t *testing.T) {
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0, 0}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	km := buildKeymap(8, 2, syms, []xproto.Keycode{kcShift, kcSpare0, 0, 0}, nil)
	if fmt.Sprint(km.spare) != fmt.Sprint([]xproto.Keycode{kcSpare1}) {
		t.Errorf("spare = %v, want only %d (%d is a modifier, %d reserved)", km.spare, kcSpare1, kcSpare0, kcSpare1+1)
	}
}

// A bound scratch keycode that another client made a modifier is given up,
// even though its symbol row is unchanged.
func TestBuildKeymap_DropsABindingThatBecameAModifier(t *testing.T) {
	km := testKeymap(2)
	if _, err := planKey(km, xkbState{}, textEvent("é")); err != nil {
		t.Fatal(err)
	}
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0xe9, 0xc9}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	r := buildKeymap(8, 2, syms, []xproto.Keycode{kcSpare0}, km)
	if len(r.bound) != 0 {
		t.Errorf("bound = %v, want the binding dropped once %d is a modifier", r.bound, kcSpare0)
	}
	for _, code := range r.spare {
		if code == kcSpare0 {
			t.Errorf("modifier keycode %d is back in the scratch pool", kcSpare0)
		}
	}
}

// Without any Shift key an uppercase letter the layout lacks cannot be
// selected (the server pairs a scratch letter as lower/upper), so decline.
func TestPlanKey_DeclinesUppercaseScratchWithoutShift(t *testing.T) {
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {0, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	km := buildKeymap(8, 2, syms, nil, nil)
	if _, err := planKey(km, xkbState{}, textEvent("é")); err != nil {
		t.Fatalf("lowercase scratch letter should still plan: %v", err)
	}
	if _, err := planKey(km, xkbState{}, textEvent("É")); !errors.Is(err, errBackendKept) {
		t.Errorf("err = %v, want errBackendKept", err)
	}
}

func TestPlanKey_DeclinesTitlecaseLetters(t *testing.T) {
	if _, err := planKey(testKeymap(2), xkbState{}, textEvent("ǅ")); !errors.Is(err, errBackendKept) {
		t.Errorf("err = %v, want errBackendKept", err)
	}
}

// A layout with only Shift_R still shifts.
func TestPlanKey_UsesShiftRWhenShiftLIsAbsent(t *testing.T) {
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftR, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	km := buildKeymap(8, 2, syms, nil, nil)
	segs, err := planKey(km, xkbState{}, textEvent("AÉ"))
	if err != nil {
		t.Fatal(err)
	}
	want := append(shiftedTap(kcA), shiftedTap(kcSpare0)...)
	eventsEqual(t, segs[0].events, want)
}

func TestPlanKey_DeclinesForKeyboardStateItCannotHonor(t *testing.T) {
	if _, err := planKey(testKeymap(1), xkbState{group: 1}, textEvent("1")); !errors.Is(err, errBackendKept) {
		t.Errorf("second group: err = %v, want errBackendKept", err)
	}
	// Shift Lock is cleared around literal text by Key, not planned around.
	segs, err := planKey(testKeymap(1), xkbState{shiftLock: true}, textEvent("1"))
	if err != nil {
		t.Fatal(err)
	}
	eventsEqual(t, segs[0].events, tapEvents(kc1))
	// A held modifier declines literal text only; a chord keeps it.
	if _, err := planKey(testKeymap(1), xkbState{held: true}, textEvent("1")); !errors.Is(err, errBackendKept) {
		t.Errorf("held modifier, text: err = %v, want errBackendKept", err)
	}
	if _, err := planKey(testKeymap(1), xkbState{held: true}, chordEvent("1")); err != nil {
		t.Errorf("held modifier, chord: %v", err)
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
		_, err := planKey(km, xkbState{}, tc.ev)
		if !errors.Is(err, errBackendKept) {
			t.Errorf("%s: err = %v, want errBackendKept", name, err)
		}
		if len(km.bound) != before {
			t.Errorf("%s: a declined plan changed the scratch state", name)
		}
	}
	if _, err := planKey(testKeymap(1), xkbState{}, textEvent("a\x01")); err == nil || errors.Is(err, errBackendKept) {
		t.Errorf("control character: err = %v, want a validation error, not a fallback", err)
	}
}

func TestBuildKeymap_KeepsScratchBindingsAcrossReload(t *testing.T) {
	km := testKeymap(2)
	if _, err := planKey(km, xkbState{}, textEvent("é")); err != nil {
		t.Fatal(err)
	}
	// A reload after an external MappingNotify sees our scratch keycode with
	// a keysym now; it must stay scratch, not become a layout key for é.
	syms := make([]xproto.Keysym, 0, 11*2)
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0xe9, 0}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	reloaded := buildKeymap(8, 2, syms, nil, km)
	if _, direct := reloaded.direct[0xe9]; direct {
		t.Error("scratch keycode was promoted to a layout key")
	}
	if reloaded.bound[kcSpare0] != 0xe9 || len(reloaded.spare) != 2 {
		t.Errorf("bound = %v, spare = %v; want é kept on %d and both keycodes in the pool", reloaded.bound, reloaded.spare, kcSpare0)
	}

	// A reload that no longer types é on that keycode drops the binding:
	// cleared, it is spare again; rewritten, it is a layout key.
	cleared := append(append([]xproto.Keysym{}, syms[:18]...), 0, 0, 0, 0, 0, 0)
	if r := buildKeymap(8, 2, cleared, nil, km); len(r.bound) != 0 || len(r.spare) != 2 {
		t.Errorf("cleared row: bound = %v, spare = %v; want no binding and two spares", r.bound, r.spare)
	}
	rewritten := append(append([]xproto.Keysym{}, syms[:18]...), 'z', 'Z', 0, 0, 0, 0)
	r := buildKeymap(8, 2, rewritten, nil, km)
	if len(r.bound) != 0 || r.direct['z'].code != kcSpare0 || len(r.spare) != 1 {
		t.Errorf("rewritten row: bound = %v, direct[z] = %v, spare = %v; want z on %d and one spare", r.bound, r.direct['z'], r.spare, kcSpare0)
	}

	// The server exports a bound cased letter as its lower/upper pair:
	// still ours. Any other symbol on the row means another client owns it.
	paired := append(append([]xproto.Keysym{}, syms[:18]...), 0xe9, 0xc9, 0, 0, 0, 0)
	if r := buildKeymap(8, 2, paired, nil, km); r.bound[kcSpare0] != 0xe9 {
		t.Errorf("paired row: bound = %v, want é kept on %d", r.bound, kcSpare0)
	}
	foreign := append(append([]xproto.Keysym{}, syms[:18]...), 0xe9, 'x', 0, 0, 0, 0)
	if r := buildKeymap(8, 2, foreign, nil, km); len(r.bound) != 0 || r.direct['x'].code != kcSpare0 {
		t.Errorf("foreign row: bound = %v, direct[x] = %v; want the binding dropped and x on %d", r.bound, r.direct['x'], kcSpare0)
	}
}

// A decline must fall back to xdotool and keep the connection: the fake
// backend has no socket, so Key declines before touching it, and any
// emission or drop would show.
func TestExecKey_DeclineFallsBackWithoutDroppingTheBackend(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "args.log")
	withFakeBin(t, map[string]string{"xdotool": fmt.Sprintf("echo \"$@\" >> %q\nexit 0\n", logFile)})
	s := newDesktopService(&sandboxContext{})
	b := withFakeBackend(s)

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

// Locks are cleared around literal text by Key, so the plan is the same
// with or without them.
func TestPlanKey_LocksDoNotChangeThePlan(t *testing.T) {
	plain, err := planKey(testKeymap(2), xkbState{}, textEvent("aA1!é€"))
	if err != nil {
		t.Fatal(err)
	}
	locked, err := planKey(testKeymap(2), xkbState{capsLock: true, shiftLock: true}, textEvent("aA1!é€"))
	if err != nil {
		t.Fatal(err)
	}
	eventsEqual(t, locked[0].events, plain[0].events)
}

// An uppercase letter the layout lacks is bound lowercase and typed with
// Shift; the lowercase form shares the keycode.
func TestPlanKey_UppercaseScratchLettersAreShifted(t *testing.T) {
	km := testKeymap(2)
	segs, err := planKey(km, xkbState{}, textEvent("Éé"))
	if err != nil {
		t.Fatal(err)
	}
	bindsEqual(t, segs[0].binds, []keyBind{{kcSpare0, 0xe9}})
	var want []keyEvent
	want = append(want, shiftedTap(kcSpare0)...)
	want = append(want, tapEvents(kcSpare0)...)
	eventsEqual(t, segs[0].events, want)

	segs, err = planKey(km, xkbState{}, chordEvent("É"))
	if err != nil {
		t.Fatal(err)
	}
	eventsEqual(t, segs[0].events, shiftedTap(kcSpare0))
}

// İ lowercases to i, which uppercases to I: no shared slot, the keysym
// itself is bound and still typed with Shift. The server reports such a
// key as [i, İ], which must still count as ours.
func TestPlanKey_UppercaseWithoutRoundTripKeepsItsKeysym(t *testing.T) {
	km := testKeymap(2)
	const dotI = 0x01000000 | 0x130
	segs, err := planKey(km, xkbState{}, textEvent("İ"))
	if err != nil {
		t.Fatal(err)
	}
	bindsEqual(t, segs[0].binds, []keyBind{{kcSpare0, dotI}})
	eventsEqual(t, segs[0].events, shiftedTap(kcSpare0))
	if !scratchRowIntact([]xproto.Keysym{'i', dotI}, dotI) {
		t.Error("the server's [i, İ] pairing was not recognized as the bound key")
	}
	if scratchRowIntact([]xproto.Keysym{'i', 'I'}, dotI) {
		t.Error("[i, I] is a different key and must not count as İ")
	}
	// Levels must be in canonical order: [é, é] has no shifted É any more.
	if scratchRowIntact([]xproto.Keysym{0xe9, 0xe9}, 0xe9) {
		t.Error("[é, é] was accepted as the bound é key")
	}
	if !scratchRowIntact([]xproto.Keysym{0xe9, 0xc9, 0xe9, 0xc9}, 0xe9) {
		t.Error("[é, É, é, É] (two groups) was rejected")
	}
}

// A keycode in the modifier map offers its modifier keysym and nothing
// else, even if its row also carries a character.
func TestBuildKeymap_ModifierKeycodesOfferOnlyModifierKeysyms(t *testing.T) {
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0xe9, 0xc9}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	km := buildKeymap(8, 2, syms, []xproto.Keycode{kcShift, kcSpare0}, nil)
	if _, ok := km.direct[keysymShiftL]; !ok {
		t.Error("Shift_L on a modifier keycode must stay usable")
	}
	for _, ks := range []uint32{0xff14, 0xff7f, 0xffe5} { // Scroll_Lock, Num_Lock, Caps_Lock
		if !modifierKeysym(ks) {
			t.Errorf("keysym %#x is a lock key and must count as a modifier", ks)
		}
	}
	if st, ok := km.direct[0xe9]; ok {
		t.Errorf("é on modifier keycode %d was offered as a layout key", st.code)
	}
}

// KP_1 shares its key with KP_End and Num Lock picks between them, so it
// must never go through that key with Shift: a scratch keycode instead.
func TestPlanKey_KeypadKeysUseScratchKeycodes(t *testing.T) {
	km := testKeymap(1)
	for _, name := range []string{"KP_1", "KP_End"} {
		segs, err := planKey(km, xkbState{}, chordEvent(name))
		if err != nil {
			t.Fatal(err)
		}
		eventsEqual(t, segs[0].events, tapEvents(kcSpare0))
	}
}

// Break is the second symbol on the Pause key but Control, not Shift,
// selects it; the layout can only be trusted for printable shifted symbols.
func TestPlanKey_NonPrintableLevelTwoUsesScratch(t *testing.T) {
	km := testKeymap(1)
	segs, err := planKey(km, xkbState{}, chordEvent("Pause"))
	if err != nil {
		t.Fatal(err)
	}
	eventsEqual(t, segs[0].events, tapEvents(kcPause))
	segs, err = planKey(km, xkbState{}, chordEvent("Break"))
	if err != nil {
		t.Fatal(err)
	}
	eventsEqual(t, segs[0].events, tapEvents(kcSpare0))
}

// Num Lock lives on Mod2 here; locked or not, it never counts as held.
func TestBuildKeymap_FindsIdleLockBitsAndStateIgnoresThem(t *testing.T) {
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0xff7f, 0}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	numLock := xproto.Keycode(8 + 9)
	mods := make([]xproto.Keycode, 8*2) // two keycodes per modifier
	mods[0], mods[2*2], mods[4*2] = kcShift, kcControl, numLock
	km := buildKeymap(8, 2, syms, mods, nil)
	if km.idleLocks != 1<<4 {
		t.Fatalf("idleLocks = %#x, want Mod2", km.idleLocks)
	}
	reply := make([]byte, 32)
	reply[8], reply[11] = 1<<4, 1<<4
	if got := xkbStateFromReply(reply, km.idleLocks); got.held {
		t.Errorf("state = %+v, want Num Lock ignored", got)
	}
	reply[8] |= xproto.ModMaskControl
	if got := xkbStateFromReply(reply, km.idleLocks); !got.held {
		t.Errorf("state = %+v, want held for Control alongside Num Lock", got)
	}
	// Num Lock depressed (not just locked) is a modifier being held.
	reply[8], reply[9], reply[11] = 1<<4, 1<<4, 0
	if got := xkbStateFromReply(reply, km.idleLocks); !got.held {
		t.Errorf("state = %+v, want held for a depressed Num Lock", got)
	}
}

// A chord already holding Shift_R gets no extra Shift_L.
func TestPlanKey_ChordHoldingShiftRNeedsNoShiftL(t *testing.T) {
	var syms []xproto.Keysym
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {keysymShiftR, 0}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	shiftR := xproto.Keycode(8 + 9)
	km := buildKeymap(8, 2, syms, nil, nil)
	segs, err := planKey(km, xkbState{}, chordEvent("A", "Shift_R"))
	if err != nil {
		t.Fatal(err)
	}
	eventsEqual(t, segs[0].events, events(shiftR, true, kcA, true, kcA, false, shiftR, false))
}

func TestXkbStateFromReply(t *testing.T) {
	reply := make([]byte, 32)
	reply[0], reply[1] = 1, 3 // reply, deviceID
	reply[8] = xproto.ModMaskLock | xproto.ModMaskShift | xproto.ModMaskControl
	reply[11] = xproto.ModMaskLock | xproto.ModMaskShift
	reply[12] = 1
	if got := xkbStateFromReply(reply, 0); got != (xkbState{group: 1, capsLock: true, shiftLock: true, held: true}) {
		t.Errorf("state = %+v, want group 1, both locks and a held Control", got)
	}
	reply[8] = xproto.ModMaskLock | xproto.ModMaskShift // only the locks are in effect
	if got := xkbStateFromReply(reply, 0); got.held {
		t.Errorf("state = %+v, want nothing held when only locks are in effect", got)
	}
	// A locked Control (sticky keys) is not something Key clears: held.
	reply[8], reply[11] = xproto.ModMaskControl, xproto.ModMaskControl
	if got := xkbStateFromReply(reply, 0); !got.held {
		t.Errorf("state = %+v, want held for a locked Control", got)
	}
	// Shift depressed (base) while also locked: still held.
	reply[8], reply[9], reply[11] = xproto.ModMaskShift, xproto.ModMaskShift, xproto.ModMaskShift
	if got := xkbStateFromReply(reply, 0); !got.held {
		t.Errorf("state = %+v, want held for a depressed Shift", got)
	}
	if got := xkbStateFromReply(reply[:8], 0); got != (xkbState{}) {
		t.Errorf("short reply = %+v, want zero state", got)
	}
}

// The keymap is rebuilt from a fresh fetch before every request, so the
// pool's order has to come from the previous map, not from map iteration.
func TestBuildKeymap_KeepsLRUOrderAcrossRebuilds(t *testing.T) {
	km := testKeymap(2)
	if _, err := planKey(km, xkbState{}, textEvent("éà")); err != nil {
		t.Fatal(err)
	}
	if _, err := planKey(km, xkbState{}, textEvent("é")); err != nil {
		t.Fatal(err)
	}
	syms := make([]xproto.Keysym, 0, 12*2)
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0xe9, 0xc9}, {0xe0, 0xc0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	for i := 0; i < 20; i++ {
		rebuilt := buildKeymap(8, 2, syms, nil, km)
		if fmt.Sprint(rebuilt.spare) != fmt.Sprint(km.spare) {
			t.Fatalf("rebuild %d reordered the pool: %v, was %v", i, rebuilt.spare, km.spare)
		}
		km = rebuilt
	}
	// à was used longest ago, so a new character evicts it, not é.
	segs, err := planKey(km, xkbState{}, textEvent("ü"))
	if err != nil {
		t.Fatal(err)
	}
	bindsEqual(t, segs[0].binds, []keyBind{{kcSpare1, 0xfc}})
}

// A replacement backend inherits the dropped one's scratch bindings, so
// the keycodes it bound are still recognized as ours and not as layout.
func TestX11Holder_ReconnectInheritsScratchBindings(t *testing.T) {
	s := newDesktopService(&sandboxContext{})
	first := withFakeBackend(s)
	first.keys = testKeymap(2)
	if _, err := planKey(first.keys, xkbState{}, textEvent("é")); err != nil {
		t.Fatal(err)
	}
	s.x11.drop(first)
	if s.x11.keys != first.keys {
		t.Fatal("dropping the backend did not keep its keymap")
	}
	// The next backend starts with that map; its first fetch keeps é's
	// keycode as scratch even though the server now reports it as [é, É].
	syms := make([]xproto.Keysym, 0, 12*2)
	for _, r := range [][2]xproto.Keysym{{'a', 'A'}, {'u', 'U'}, {'1', '!'}, {' ', 0}, {0xff0d, 0}, {keysymShiftL, 0}, {0xffe3, 0}, {0xff9c, 0xffb1}, {0xff13, 0xff6b}, {0xe9, 0xc9}, {0, 0}, {0, 0}} {
		syms = append(syms, r[0], r[1])
	}
	rebuilt := buildKeymap(8, 2, syms, nil, s.x11.keys)
	if rebuilt.bound[kcSpare0] != 0xe9 {
		t.Errorf("bound = %v, want é still owned on %d after the reconnect", rebuilt.bound, kcSpare0)
	}
	if _, direct := rebuilt.direct[0xe9]; direct {
		t.Error("the scratch keycode became a layout key after the reconnect")
	}
}
