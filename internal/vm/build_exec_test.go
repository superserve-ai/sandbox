package vm

import "testing"

func TestShellQuote_EscapesSingleQuotes(t *testing.T) {
	cases := map[string]string{
		"plain":      "'plain'",
		"/path/to/x": "'/path/to/x'",
		"it's":       `'it'\''s'`,
		"":           "''",
	}
	for in, want := range cases {
		got := shellQuote(in)
		if got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsSafeCopyDst(t *testing.T) {
	cases := map[string]bool{
		"/app":       true,
		"/opt/foo":   true,
		"/etc/myapp": true,
		"/var/data":  true,

		// Relative paths — unsafe; resolution context is unclear and any
		// /bin-relative resolution could walk into a system dir.
		"app":   false,
		"./app": false,

		// System directories we protect from user copies during a build —
		// overwriting these corrupts the snapshot we're about to take.
		"/":     false,
		"/bin":  false,
		"/sbin": false,
		"/boot": false,
		"/proc": false,
		"/sys":  false,
		"/dev":  false,
	}
	for dst, want := range cases {
		if got := isSafeCopyDst(dst); got != want {
			t.Errorf("isSafeCopyDst(%q) = %v, want %v", dst, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("under-cap truncate: got %q", got)
	}
	if got := truncate("abcdefghij", 5); got != "abcde…" {
		t.Errorf("over-cap truncate: got %q", got)
	}
}
