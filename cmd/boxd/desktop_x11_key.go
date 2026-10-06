package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jezek/xgb/xproto"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// errBackendKept marks a key request the X11 path declined before sending
// anything: an unknown key name, a modifier the layout lacks, no spare
// keycode. The connection stays up and the caller may use xdotool instead.
var errBackendKept = errors.New("x11 key path declined")

const keysymShiftL = 0xffe1

// x11Keymap is the server's core keyboard mapping plus the scratch keycodes
// this backend has bound for characters the layout cannot type.
type x11Keymap struct {
	perCode int
	// direct resolves a keysym the layout types natively: column 0 plain,
	// column 1 with Shift held.
	direct map[uint32]keystroke
	// spare are keycodes with no keysyms of their own, least recently bound
	// first. A bound one stays bound until the pool wraps around, so a
	// repeated character never rebinds and applications are never asked to
	// re-read the map between a key press and its release.
	spare []xproto.Keycode
	// bound is the keysym each scratch keycode currently types.
	bound map[xproto.Keycode]uint32
}

type keystroke struct {
	code  xproto.Keycode
	shift bool
}

type keyEvent struct {
	code  xproto.Keycode
	press bool
}

type keyBind struct {
	code   xproto.Keycode
	keysym uint32
}

// keySegment is a run of strokes whose scratch bindings are all applied
// before the first press. A new segment starts only when the spare pool is
// exhausted and a keycode already typed in this request must be rebound.
type keySegment struct {
	binds  []keyBind
	events []keyEvent
}

// buildKeymap lowers a core keyboard mapping to lookup tables. Keycodes in
// bound are scratch keycodes from an earlier map; one stays bound only if
// the fetched row still types its keysym, otherwise the row decides.
func buildKeymap(min xproto.Keycode, perCode int, syms []xproto.Keysym, bound map[xproto.Keycode]uint32) *x11Keymap {
	km := &x11Keymap{perCode: perCode, direct: map[uint32]keystroke{}, bound: map[xproto.Keycode]uint32{}}
	if perCode < 1 {
		return km
	}
	for i := 0; (i+1)*perCode <= len(syms); i++ {
		code := xproto.Keycode(int(min) + i)
		row := syms[i*perCode : (i+1)*perCode]
		if ks, ours := bound[code]; ours && uint32(row[0]) == ks {
			km.bound[code] = ks
			continue
		}
		empty := true
		for _, ks := range row {
			if ks != 0 {
				empty = false
				break
			}
		}
		if empty {
			km.spare = append(km.spare, code)
			continue
		}
		if ks := uint32(row[0]); ks != 0 {
			if _, dup := km.direct[ks]; !dup {
				km.direct[ks] = keystroke{code: code}
			}
		}
		if perCode > 1 {
			if ks := uint32(row[1]); ks != 0 {
				if _, dup := km.direct[ks]; !dup {
					km.direct[ks] = keystroke{code: code, shift: true}
				}
			}
		}
	}
	// Previously bound scratch keycodes rejoin the pool as most recently used.
	for code := range km.bound {
		km.spare = append(km.spare, code)
	}
	return km
}

// keymap returns the current mapping, fetching it on first use and after a
// MappingNotify this backend did not cause. Queued events are drained first,
// since a change made between two requests is only known once its
// notification is read.
func (b *x11Backend) keymap() (*x11Keymap, error) {
	if err := b.drainEvents(); err != nil {
		return nil, err
	}
	if b.keys != nil && !b.keysDirty {
		return b.keys, nil
	}
	setup := xproto.Setup(b.conn)
	count := int(setup.MaxKeycode) - int(setup.MinKeycode) + 1
	reply, err := xproto.GetKeyboardMapping(b.conn, setup.MinKeycode, byte(count)).Reply()
	if err != nil {
		return nil, fmt.Errorf("keyboard mapping: %w", err)
	}
	var bound map[xproto.Keycode]uint32
	if b.keys != nil {
		bound = b.keys.bound
	}
	b.keys = buildKeymap(setup.MinKeycode, int(reply.KeysymsPerKeycode), reply.Keysyms, bound)
	b.keysDirty = false
	return b.keys, nil
}

// keyPlanner lowers one key request to keycodes against a copy of the
// scratch state, so a declined request leaves the keymap untouched.
type keyPlanner struct {
	km       *x11Keymap
	spare    []xproto.Keycode
	bound    map[xproto.Keycode]uint32
	used     map[xproto.Keycode]bool
	segments []keySegment
	cur      keySegment
}

func newKeyPlanner(km *x11Keymap) *keyPlanner {
	p := &keyPlanner{km: km, spare: append([]xproto.Keycode(nil), km.spare...),
		bound: make(map[xproto.Keycode]uint32, len(km.bound)), used: map[xproto.Keycode]bool{}}
	for code, ks := range km.bound {
		p.bound[code] = ks
	}
	return p
}

func (p *keyPlanner) touch(code xproto.Keycode) {
	for i, c := range p.spare {
		if c == code {
			p.spare = append(append(p.spare[:i:i], p.spare[i+1:]...), code)
			break
		}
	}
	p.used[code] = true
}

// scratch returns a keycode bound to ks, binding the least recently used
// spare when none is. Rebinding a keycode this request already typed with
// closes the segment, so the rebind is applied only after those strokes.
func (p *keyPlanner) scratch(ks uint32) (xproto.Keycode, bool) {
	for code, bks := range p.bound {
		if bks == ks {
			p.touch(code)
			return code, true
		}
	}
	if len(p.spare) == 0 {
		return 0, false
	}
	code := p.spare[0]
	if p.used[code] {
		p.segments = append(p.segments, p.cur)
		p.cur = keySegment{}
		p.used = map[xproto.Keycode]bool{}
	}
	p.bound[code] = ks
	p.touch(code)
	p.cur.binds = append(p.cur.binds, keyBind{code: code, keysym: ks})
	return code, true
}

// stroke resolves ks to a keystroke: natively when the layout has it (with
// Shift only when the layout has a Shift key), else through a scratch
// keycode.
func (p *keyPlanner) stroke(ks uint32) (keystroke, error) {
	_, hasShift := p.km.direct[keysymShiftL]
	if st, ok := p.km.direct[ks]; ok && (!st.shift || hasShift) {
		return st, nil
	}
	code, ok := p.scratch(ks)
	if !ok {
		return keystroke{}, fmt.Errorf("no spare keycode for keysym 0x%x: %w", ks, errBackendKept)
	}
	return keystroke{code: code}, nil
}

func (p *keyPlanner) emit(code xproto.Keycode, press bool) {
	p.cur.events = append(p.cur.events, keyEvent{code: code, press: press})
}

func (p *keyPlanner) tap(st keystroke) {
	if st.shift {
		p.emit(p.km.direct[keysymShiftL].code, true)
	}
	p.emit(st.code, true)
	p.emit(st.code, false)
	if st.shift {
		p.emit(p.km.direct[keysymShiftL].code, false)
	}
}

func (p *keyPlanner) text(text string) error {
	for _, r := range text {
		st, err := p.stroke(keysymFromRune(r))
		if err != nil {
			return err
		}
		p.tap(st)
	}
	return nil
}

// chord presses the modifiers, taps the key, and releases the modifiers in
// reverse. Modifiers must be keys the layout has; the final key may use a
// scratch keycode. Shift is added for a shifted keysym unless already held.
func (p *keyPlanner) chord(modifiers []string, key string) error {
	parts := strings.Split(key, "+")
	if key == "+" {
		parts = []string{"+"}
	}
	names := append(append([]string{}, modifiers...), parts[:len(parts)-1]...)
	var mods []xproto.Keycode
	for _, name := range names {
		ks, ok := keysymFromName(name)
		if !ok {
			return fmt.Errorf("unknown key name %q: %w", name, errBackendKept)
		}
		st, ok := p.km.direct[ks]
		if !ok || st.shift {
			return fmt.Errorf("modifier %q is not in the keyboard layout: %w", name, errBackendKept)
		}
		mods = append(mods, st.code)
	}
	last := parts[len(parts)-1]
	ks, ok := keysymFromName(last)
	if !ok {
		return fmt.Errorf("unknown key name %q: %w", last, errBackendKept)
	}
	st, err := p.stroke(ks)
	if err != nil {
		return err
	}
	for _, code := range mods {
		p.emit(code, true)
	}
	if shift, ok := p.km.direct[keysymShiftL]; ok && st.shift {
		for _, code := range mods {
			if code == shift.code {
				st.shift = false
			}
		}
	}
	p.tap(st)
	for i := len(mods) - 1; i >= 0; i-- {
		p.emit(mods[i], false)
	}
	return nil
}

// planKey lowers a validated KeyEvent. On success the keymap's scratch
// state is updated to what the plan will bind.
func planKey(km *x11Keymap, ev *pb.KeyEvent) ([]keySegment, error) {
	p := newKeyPlanner(km)
	var err error
	switch in := ev.GetInput().(type) {
	case *pb.KeyEvent_Key:
		err = p.chord(ev.GetModifiers(), in.Key)
	case *pb.KeyEvent_Text:
		var text string
		if text, err = normalizeKeyText(in.Text); err == nil {
			err = p.text(text)
		}
	default:
		err = errors.New("one of key or text is required")
	}
	if err != nil {
		return nil, err
	}
	km.spare, km.bound = p.spare, p.bound
	return append(p.segments, p.cur), nil
}

// Key delivers one KeyEvent through XTest: scratch bindings, a sync so the
// server (and every client's MappingNotify) is ahead of the presses, then
// the strokes and one sync per segment. A plan failure happens before any
// request is sent; after that, errors are returned without replay.
func (b *x11Backend) Key(ev *pb.KeyEvent) error {
	km, err := b.keymap()
	if err != nil {
		return err
	}
	segments, err := planKey(km, ev)
	if err != nil {
		return err
	}
	for _, seg := range segments {
		if len(seg.binds) > 0 {
			row := make([]xproto.Keysym, km.perCode)
			for _, bind := range seg.binds {
				row[0] = xproto.Keysym(bind.keysym)
				xproto.ChangeKeyboardMapping(b.conn, 1, bind.code, byte(km.perCode), row)
				b.ownRemaps++
			}
			if err := b.sync(); err != nil {
				return err
			}
		}
		for _, e := range seg.events {
			b.key(e.code, e.press)
		}
		if err := b.sync(); err != nil {
			b.releaseAll(seg.events)
			return err
		}
	}
	return nil
}

func (b *x11Backend) key(code xproto.Keycode, press bool) {
	typ := byte(xproto.KeyRelease)
	if press {
		typ = xproto.KeyPress
	}
	b.fakeInput(typ, byte(code), 0, 0)
}

// releaseAll is the best-effort cleanup after a failed segment: every key it
// pressed gets a release, in case the server applied the presses but not the
// releases before the connection broke.
func (b *x11Backend) releaseAll(events []keyEvent) {
	seen := map[xproto.Keycode]bool{}
	for i := len(events) - 1; i >= 0; i-- {
		if e := events[i]; e.press && !seen[e.code] {
			seen[e.code] = true
			b.key(e.code, false)
		}
	}
	_ = b.sync()
}
