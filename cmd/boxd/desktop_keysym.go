package main

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// keysymNames resolves the key names the X11 key path handles without the
// server: xdotool's modifier aliases and the keysymdef.h sections an agent
// is likely to send (modifiers, TTY, cursor, keypad, function keys, Latin-1
// punctuation). Anything else goes through xdotool, which has the full table.
var keysymNames = map[string]uint32{
	"ctrl": 0xffe3, "control": 0xffe3, "alt": 0xffe9, "shift": 0xffe1,
	"super": 0xffeb, "win": 0xffeb, "meta": 0xffe7, "hyper": 0xffed,

	"Shift_L": 0xffe1, "Shift_R": 0xffe2, "Control_L": 0xffe3, "Control_R": 0xffe4,
	"Caps_Lock": 0xffe5, "Shift_Lock": 0xffe6, "Meta_L": 0xffe7, "Meta_R": 0xffe8,
	"Alt_L": 0xffe9, "Alt_R": 0xffea, "Super_L": 0xffeb, "Super_R": 0xffec,
	"Hyper_L": 0xffed, "Hyper_R": 0xffee, "ISO_Level3_Shift": 0xfe03, "Mode_switch": 0xff7e,

	"BackSpace": 0xff08, "Tab": 0xff09, "Linefeed": 0xff0a, "Clear": 0xff0b, "Return": 0xff0d,
	"Pause": 0xff13, "Scroll_Lock": 0xff14, "Sys_Req": 0xff15, "Escape": 0xff1b, "Delete": 0xffff,

	"Home": 0xff50, "Left": 0xff51, "Up": 0xff52, "Right": 0xff53, "Down": 0xff54,
	"Prior": 0xff55, "Page_Up": 0xff55, "Next": 0xff56, "Page_Down": 0xff56, "End": 0xff57, "Begin": 0xff58,

	"Select": 0xff60, "Print": 0xff61, "Execute": 0xff62, "Insert": 0xff63, "Undo": 0xff65,
	"Redo": 0xff66, "Menu": 0xff67, "Find": 0xff68, "Cancel": 0xff69, "Help": 0xff6a,
	"Break": 0xff6b, "Num_Lock": 0xff7f,

	"KP_Space": 0xff80, "KP_Tab": 0xff89, "KP_Enter": 0xff8d,
	"KP_F1": 0xff91, "KP_F2": 0xff92, "KP_F3": 0xff93, "KP_F4": 0xff94,
	"KP_Home": 0xff95, "KP_Left": 0xff96, "KP_Up": 0xff97, "KP_Right": 0xff98, "KP_Down": 0xff99,
	"KP_Prior": 0xff9a, "KP_Page_Up": 0xff9a, "KP_Next": 0xff9b, "KP_Page_Down": 0xff9b,
	"KP_End": 0xff9c, "KP_Begin": 0xff9d, "KP_Insert": 0xff9e, "KP_Delete": 0xff9f, "KP_Equal": 0xffbd,
	"KP_Multiply": 0xffaa, "KP_Add": 0xffab, "KP_Separator": 0xffac, "KP_Subtract": 0xffad,
	"KP_Decimal": 0xffae, "KP_Divide": 0xffaf,

	"space": 0x20, "exclam": 0x21, "quotedbl": 0x22, "numbersign": 0x23, "dollar": 0x24,
	"percent": 0x25, "ampersand": 0x26, "apostrophe": 0x27, "quoteright": 0x27,
	"parenleft": 0x28, "parenright": 0x29, "asterisk": 0x2a, "plus": 0x2b, "comma": 0x2c,
	"minus": 0x2d, "period": 0x2e, "slash": 0x2f, "colon": 0x3a, "semicolon": 0x3b,
	"less": 0x3c, "equal": 0x3d, "greater": 0x3e, "question": 0x3f, "at": 0x40,
	"bracketleft": 0x5b, "backslash": 0x5c, "bracketright": 0x5d, "asciicircum": 0x5e,
	"underscore": 0x5f, "grave": 0x60, "quoteleft": 0x60, "braceleft": 0x7b, "bar": 0x7c,
	"braceright": 0x7d, "asciitilde": 0x7e,
}

// keysymNamesFolded is the same table keyed by lowercase name, so "return"
// and "escape" resolve as the SDKs' friendly names do.
var keysymNamesFolded = map[string]uint32{}

func init() {
	for i := 1; i <= 35; i++ {
		keysymNames["F"+strconv.Itoa(i)] = 0xffbe + uint32(i-1)
	}
	for i := 0; i <= 9; i++ {
		keysymNames["KP_"+strconv.Itoa(i)] = 0xffb0 + uint32(i)
	}
	for name, ks := range keysymNames {
		keysymNamesFolded[strings.ToLower(name)] = ks
	}
}

// keysymFromRune is the keysym that types r: Latin-1 keysyms equal the code
// point, everything else uses the Unicode keysym range. Line endings map to
// Return and tabs to Tab; other control characters have no keysym (0).
func keysymFromRune(r rune) uint32 {
	switch {
	case r == '\n':
		return 0xff0d
	case r == '\t':
		return 0xff09
	case r < 0x20 || (r >= 0x7f && r <= 0x9f):
		return 0
	case r <= 0xff:
		return uint32(r)
	default:
		return 0x01000000 | uint32(r)
	}
}

// keysymFromName resolves one key name the way xdotool's `key` does for the
// names this file knows: a keysym name, a single character, "U+00E9" or
// "U00E9", or a "0x" hex keysym.
func keysymFromName(name string) (uint32, bool) {
	if ks, ok := keysymNames[name]; ok {
		return ks, true
	}
	if utf8.RuneCountInString(name) == 1 {
		r, _ := utf8.DecodeRuneInString(name)
		if ks := keysymFromRune(r); ks != 0 {
			return ks, true
		}
		return 0, false
	}
	if hex, ok := strings.CutPrefix(name, "0x"); ok {
		ks, err := strconv.ParseUint(hex, 16, 32)
		return uint32(ks), err == nil && ks != 0
	}
	if ks, ok := keysymNamesFolded[strings.ToLower(name)]; ok {
		return ks, true
	}
	cp, ok := strings.CutPrefix(name, "U+")
	if !ok {
		cp, ok = strings.CutPrefix(name, "U")
	}
	if ok {
		if v, err := strconv.ParseUint(cp, 16, 32); err == nil && v <= unicode.MaxRune {
			if ks := keysymFromRune(rune(v)); ks != 0 {
				return ks, true
			}
		}
	}
	return 0, false
}

// normalizeKeyText maps line endings to a single Return and rejects what
// neither backend can type: invalid UTF-8 and control characters other than
// tab and newline.
func normalizeKeyText(text string) (string, error) {
	if !utf8.ValidString(text) {
		return "", errInvalidText("text is not valid UTF-8")
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	for _, r := range text {
		if keysymFromRune(r) == 0 {
			return "", errInvalidText("text contains unsupported control character " + strconv.QuoteRune(r))
		}
	}
	return text, nil
}

type errInvalidText string

func (e errInvalidText) Error() string { return string(e) }
