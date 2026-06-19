package api

import "testing"

// #114 (Pavitra): the list-dir path guard must reject ".." path *segments*
// without rejecting legitimate filenames that merely contain ".." as a substring
// (e.g. "hello..world"). strings.Contains(path, "..") was too aggressive.
func TestHasDotDotSegment(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/project/hello..world", false},
		{"/a/b..c/d", false},
		{"/weird..", false},
		{"/", false},
		{"/a/b/c", false},
		{"/a/../b", true},
		{"/../etc/passwd", true},
		{"/a/b/..", true},
		{"..", true},
	}
	for _, tc := range cases {
		if got := hasDotDotSegment(tc.path); got != tc.want {
			t.Errorf("hasDotDotSegment(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
