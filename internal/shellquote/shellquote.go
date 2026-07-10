// Package shellquote renders strings as shell-safe literal words for scripts
// that run under `sh -c`.
package shellquote

import "strings"

// Single renders s as a single-quoted POSIX shell word, so the shell treats it
// literally — no $VAR, `...`, or $(...) expansion. An embedded single quote
// becomes '\”. Use for any value interpolated into a script run via sh -c.
func Single(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
