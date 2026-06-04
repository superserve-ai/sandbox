package main

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyBuildError(t *testing.T) {
	tests := []struct {
		name     string
		err      string
		wantCode string
	}{
		{
			name:     "image larger than the whole disk (extraction cap)",
			err:      "build rootfs: flattened image exceeds 1073741824 bytes",
			wantCode: "image_too_large",
		},
		{
			name:     "image fits raw disk but not usable space (mkfs populate overflow)",
			err:      `make ext4: mkfs.ext4: exit status 1: mkfs.ext4: Could not allocate block in ext2 filesystem while populating file system`,
			wantCode: "image_too_large",
		},
		{
			name:     "inode exhaustion during populate",
			err:      "make ext4: mkfs.ext4: exit status 1: Could not allocate inode in ext2 filesystem while populating file system",
			wantCode: "image_too_large",
		},
		{
			name:     "an unrelated mkfs failure is NOT image_too_large",
			err:      "make ext4: mkfs.ext4: exit status 1: mke2fs: invalid blocks count - destPath",
			wantCode: "build_failed",
		},
		{
			name:     "registry pull failure still classified as pull",
			err:      "build rootfs: pull python:3.12: manifest unknown",
			wantCode: "image_pull_failed",
		},
		{
			name:     "unknown error falls back to build_failed",
			err:      "something totally unexpected happened",
			wantCode: "build_failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := classifyBuildError(errors.New(tc.err))
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if strings.TrimSpace(msg) == "" {
				t.Error("user message must not be empty")
			}
		})
	}
}
