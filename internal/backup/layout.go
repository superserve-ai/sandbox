// Package backup implements the host-side durability pipeline: enqueueing a
// pause's durable artifacts, packing their sparse extents, and (in the
// uploader) shipping them to the cell's backup bucket with create-only
// semantics.
//
// Object layout is keyed by cell-portable identifiers, never host paths, so
// a restore does not depend on which machine wrote the backup. A sandbox
// generation is content-addressed by the disk artifact's sha256: re-uploading
// the same pause (retry, or an unchanged disk) lands on the same object
// names, which the bucket's create-only precondition turns into a no-op.
package backup

import (
	"fmt"
	"strings"
)

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

// TemplateObject names an artifact object within a template build.
func TemplateObject(templateID, buildID, fileName string) (string, error) {
	if err := validSegment(templateID); err != nil {
		return "", fmt.Errorf("template id: %w", err)
	}
	if err := validSegment(buildID); err != nil {
		return "", fmt.Errorf("build id: %w", err)
	}
	if err := validSegment(fileName); err != nil {
		return "", fmt.Errorf("file name: %w", err)
	}
	return fmt.Sprintf("%s/%s/%s/%s", templatePrefix, templateID, buildID, fileName), nil
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
