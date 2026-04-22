package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"empty", nil, ""},
		{"single", []string{"PATH=/a:/b"}, "/a:/b"},
		{"last wins", []string{"PATH=/a", "FOO=bar", "PATH=/b"}, "/b"},
		{"no PATH", []string{"FOO=bar"}, ""},
		{"PATH-like prefix ignored", []string{"PATHOLOGICAL=nope"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathFromEnv(tc.env); got != tc.want {
				t.Errorf("pathFromEnv(%v) = %q, want %q", tc.env, got, tc.want)
			}
		})
	}
}

func TestLookPathIn_Finds(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mytool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := lookPathIn("mytool", "/nonexistent:"+dir)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != bin {
		t.Errorf("got %q, want %q", got, bin)
	}
}

func TestLookPathIn_SkipsNonExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readme")
	if err := os.WriteFile(path, []byte("not a binary"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := lookPathIn("readme", dir); err == nil {
		t.Error("expected error for non-executable file")
	}
}

func TestLookPathIn_EmptyPath(t *testing.T) {
	if _, err := lookPathIn("sh", ""); err == nil {
		t.Error("expected error for empty PATH")
	}
}

func TestLookPathIn_NotFound(t *testing.T) {
	dir := t.TempDir()
	if _, err := lookPathIn("does-not-exist", dir); err == nil {
		t.Error("expected error for missing command")
	}
}
