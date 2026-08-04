// Package backup implements the host-side durability pipeline: enqueueing a
// pause's durable artifacts, packing their sparse extents, and (in the
// uploader) shipping them to the cell's backup bucket with create-only
// semantics.
//
// Object layout is keyed by cell-portable identifiers, never host paths, so
// a restore does not depend on which machine wrote the backup. A sandbox
// generation is content-addressed by the disk artifact's sha256: re-uploading
// a genuine retry lands on the same object names, which the bucket's
// create-only precondition turns into a no-op, while ANY changed artifact
// yields a fresh generation (see GenerationKey), never a partial overlay
// of old and new objects under one prefix.
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// GenerationKey derives a generation's content address from the full
// artifact set, base dependencies included by content digest. Keying on
// a single artifact would let the others drift: a re-pause with an
// unchanged disk but a fresh vmstate would reuse the old prefix, and an
// overlay whose base was re-pointed OR rebuilt in place with different
// bytes would dedupe onto a manifest pairing it with the wrong base
// contents (the overlay digest cannot see this: holes hash as zeros, not
// as base bytes).
//
// Size is in the key even though an honest digest already implies it:
// restore trusts the recorded size as a resource bound (truncate target,
// verification span), so a tampered manifest inflating it must fail the
// key check rather than drive an effectively unbounded zero hash.
//
// Uploads emit only this formula. Restore additionally accepts the
// legacy formula below: generations uploaded before Size joined the key
// exist in every bucket (and journal tasks carrying legacy keys survive
// vmd upgrades), and a backup tier that cannot restore its own history
// is not a backup tier. Legacy generations get their resource bounding
// from the per-entry size cap in restore validation instead.
func GenerationKey(files []TaskFile) string {
	lines := make([]string, 0, len(files))
	for _, f := range files {
		lines = append(lines, fmt.Sprintf("%s=%s=%d=%s=%s", f.Name, f.SHA256, f.Size, f.BasePath, f.BaseSHA256))
	}
	return hashKeyLines(lines)
}

// generationKeyLegacy is the pre-Size derivation (name=sha=basePath=baseSHA),
// kept ONLY so restore can verify generations uploaded under it. Nothing
// may write new generations with this key.
func generationKeyLegacy(files []TaskFile) string {
	lines := make([]string, 0, len(files))
	for _, f := range files {
		lines = append(lines, f.Name+"="+f.SHA256+"="+f.BasePath+"="+f.BaseSHA256)
	}
	return hashKeyLines(lines)
}

func hashKeyLines(lines []string) string {
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Object name templates. Generations are immutable once verified: nothing
// ever overwrites an existing object (the writer identity cannot).
const (
	sandboxPrefix  = "sandboxes"
	templatePrefix = "templates"
	// ManifestObject is the per-generation metadata object, written last:
	// its presence marks the generation complete and restorable.
	ManifestObject = "manifest.json"
)

// SandboxObject names an artifact object within a sandbox generation.
// generation is the content address (the disk artifact's sha256 hex).
func SandboxObject(sandboxID, generation, fileName string) (string, error) {
	if err := validSegment(sandboxID); err != nil {
		return "", fmt.Errorf("sandbox id: %w", err)
	}
	if err := validSegment(generation); err != nil {
		return "", fmt.Errorf("generation: %w", err)
	}
	if err := validSegment(fileName); err != nil {
		return "", fmt.Errorf("file name: %w", err)
	}
	return fmt.Sprintf("%s/%s/%s/%s", sandboxPrefix, sandboxID, generation, fileName), nil
}

// SharedBaseObject names a bucket-wide content-addressed base image
// object: bases/<sha256>.p<fingerprint>. The digest addresses the bytes
// and the fingerprint binds the extent table, so identical bases from
// any sandbox or host converge on one immutable object.
func SharedBaseObject(sha256, fingerprint string) string {
	return "bases/" + sha256 + ".p" + fingerprint
}

// TemplateObject names an artifact object within a template build
// generation. The generation segment matters even though a finished build
// is immutable: build ids are reusable (vmd defaults to build-<template>,
// and a terminal build releases the id for the next rebuild), so without
// it a rebuild would land on the previous build's prefix and create-only
// dedupe would silently keep the stale objects.
func TemplateObject(templateID, buildID, generation, fileName string) (string, error) {
	if err := validSegment(templateID); err != nil {
		return "", fmt.Errorf("template id: %w", err)
	}
	if err := validSegment(buildID); err != nil {
		return "", fmt.Errorf("build id: %w", err)
	}
	if err := validSegment(generation); err != nil {
		return "", fmt.Errorf("generation: %w", err)
	}
	if err := validSegment(fileName); err != nil {
		return "", fmt.Errorf("file name: %w", err)
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s", templatePrefix, templateID, buildID, generation, fileName), nil
}

// validSegment rejects path traversal and separator injection in object-name
// segments. Object names are built from DB identifiers and fixed file names,
// but the bucket is shared across every tenant in the cell, so segments are
// validated defensively rather than trusted.
func validSegment(s string) error {
	if s == "" {
		return fmt.Errorf("empty segment")
	}
	if strings.ContainsAny(s, "/\\") || s == "." || s == ".." {
		return fmt.Errorf("invalid segment %q", s)
	}
	return nil
}
