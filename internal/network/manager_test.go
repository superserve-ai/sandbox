package network

import "testing"

func TestSlotFromNamespace(t *testing.T) {
	cases := []struct {
		in        string
		wantIdx   int
		wantOK    bool
	}{
		{"ns-0", 0, true},
		{"ns-1", 1, true},
		{"ns-17", 17, true},
		{"ns-9999", 9999, true},
		{"", 0, false},
		{"ns-", 0, false},
		{"ns", 0, false},
		{"foo-1", 0, false},
		{"ns-abc", 0, false},
		{"ns-1foo", 0, false},
		{"ns-2-extra", 0, false},
		{"ns--1", 0, false},
		{"ns-0x10", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			idx, ok := slotFromNamespace(tc.in)
			if ok != tc.wantOK || idx != tc.wantIdx {
				t.Errorf("slotFromNamespace(%q) = (%d, %v), want (%d, %v)", tc.in, idx, ok, tc.wantIdx, tc.wantOK)
			}
		})
	}
}
