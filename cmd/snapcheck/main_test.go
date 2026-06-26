package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestComparePages(t *testing.T) {
	const pageSize = 8

	tests := []struct {
		name    string
		a, b    []byte
		want    []int
		wantErr string
	}{
		{
			name: "identical",
			a:    bytes.Repeat([]byte{0xAB}, pageSize*3),
			b:    bytes.Repeat([]byte{0xAB}, pageSize*3),
			want: nil,
		},
		{
			name: "one page differs",
			a:    append(bytes.Repeat([]byte{0x01}, pageSize), bytes.Repeat([]byte{0x02}, pageSize)...),
			b:    append(bytes.Repeat([]byte{0x01}, pageSize), bytes.Repeat([]byte{0x99}, pageSize)...),
			want: []int{1},
		},
		{
			name: "all empty pages match",
			a:    make([]byte, pageSize*4),
			b:    make([]byte, pageSize*4),
			want: nil,
		},
		{
			name: "short final page, equal",
			a:    bytes.Repeat([]byte{0x07}, pageSize+3),
			b:    bytes.Repeat([]byte{0x07}, pageSize+3),
			want: nil,
		},
		{
			name:    "length mismatch",
			a:       make([]byte, pageSize*2),
			b:       make([]byte, pageSize*3),
			wantErr: "differ in length",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := comparePages(bytes.NewReader(tc.a), bytes.NewReader(tc.b), pageSize)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalInts(res.diffPages, tc.want) {
				t.Fatalf("diffPages = %v, want %v", res.diffPages, tc.want)
			}
		})
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
