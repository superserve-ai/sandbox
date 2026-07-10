package shellquote

import "testing"

func TestSingle(t *testing.T) {
	cases := []struct{ in, want string }{
		{`/run/vmd/x`, `'/run/vmd/x'`},
		{`/a b`, `'/a b'`},
		{`$FOO$(x)`, `'$FOO$(x)'`}, // expansion syntax kept literal
		{"a`b`", "'a`b`'"},         // backticks kept literal
		{`x'y`, `'x'\''y'`},        // embedded single quote escaped
	}
	for _, c := range cases {
		if got := Single(c.in); got != c.want {
			t.Errorf("Single(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
