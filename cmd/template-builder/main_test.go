package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/builder"
)

func TestBuildEventsSurviveClosedParentPipe(t *testing.T) {
	if dir := os.Getenv("BUILDER_CLOSED_PIPE_TEST_DIR"); dir != "" {
		configureBuildEventOutput()
		emitUser("system", "build started")
		var proceed [1]byte
		if _, err := io.ReadFull(os.Stdin, proceed[:]); err != nil {
			t.Fatal(err)
		}
		emitUser("system", "saving template")
		emitInternal("system", "snapshot captured")
		if !eventOutputClosed.Load() {
			t.Fatal("closed event pipe was not detected")
		}
		if err := writeBuildMeta(dir, "snapshot", "memory", "base", "delta", false, builder.BuildRootfsResult{}); err != nil {
			t.Fatal(err)
		}
		return
	}

	dir := t.TempDir()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	defer stdinWriter.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBuildEventsSurviveClosedParentPipe$")
	cmd.Env = append(os.Environ(), "BUILDER_CLOSED_PIPE_TEST_DIR="+dir)
	cmd.Stdout = writer
	cmd.Stdin = stdinReader
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		stdinReader.Close()
		t.Fatal(err)
	}
	writer.Close()
	stdinReader.Close()

	firstLine, readErr := bufio.NewReader(reader).ReadBytes('\n')
	var first buildEvent
	if readErr != nil || json.Unmarshal(firstLine, &first) != nil || first.Text != "build started" {
		reader.Close()
		stdinWriter.Close()
		_ = cmd.Wait()
		t.Fatalf("first build event = %q, read error = %v, child stderr = %s", firstLine, readErr, stderr.String())
	}
	reader.Close()
	if _, err := stdinWriter.Write([]byte{1}); err != nil {
		_ = cmd.Wait()
		t.Fatalf("release builder after closing pipe: %v; child stderr = %s", err, stderr.String())
	}
	stdinWriter.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("builder did not complete after stdout reader closed: %v; child stderr = %s", err, stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, "build.meta.json"))
	if err != nil {
		t.Fatalf("builder did not persist completion metadata: %v", err)
	}
	if !bytes.Contains(data, []byte(`"snapshot_path": "snapshot"`)) {
		t.Fatalf("unexpected completion metadata: %s", data)
	}
}

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
