package api

import (
	"context"
	"encoding/json"

	"github.com/google/go-containerregistry/pkg/crane"

	"github.com/superserve-ai/sandbox/internal/start"
)

// imageConfig mirrors the builder.ImageDefaults JSON shape persisted in
// template.image_config (jsonb). Duplicated here (rather than importing
// internal/builder) so the API package doesn't pull the OCI/registry stack in
// just to read five fields.
type imageConfig struct {
	Entrypoint []string          `json:"entrypoint,omitempty"`
	Cmd        []string          `json:"cmd,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	User       string            `json:"user,omitempty"`
}

// resolveImageStartSpec computes the start command a sandbox should run, from a
// template's captured image config (the jsonb bytes, possibly nil/empty for
// legacy templates) plus per-request overrides. This is the bring-your-image
// glue: it turns "honor the image's ENTRYPOINT/CMD, with `command`/`env`
// overriding like `docker run`" into a concrete start.Spec that boxd supervises.
//
// A nil/empty imageConfigJSON with no command override yields a non-runnable
// Spec (Spec.IsRunnable()==false) — i.e. a base template with no auto-start,
// preserving today's behavior.
func resolveImageStartSpec(imageConfigJSON []byte, command []string, env map[string]string) (start.Spec, error) {
	var img start.Image
	if len(imageConfigJSON) > 0 {
		var cfg imageConfig
		if err := json.Unmarshal(imageConfigJSON, &cfg); err != nil {
			return start.Spec{}, err
		}
		img = start.Image{
			Entrypoint: cfg.Entrypoint,
			Cmd:        cfg.Cmd,
			Env:        cfg.Env,
			WorkingDir: cfg.WorkingDir,
			User:       cfg.User,
		}
	}
	return start.Resolve(img, start.Overrides{
		Command:    command,
		SandboxEnv: env,
	}), nil
}

// resolveImageDigest resolves an image reference to its content digest
// ("sha256:...") with a registry HEAD. Package var so tests can stub it without
// network. Mirrors how the builder resolves the digest during a real pull, so
// the value matches what FinalizeBuild persists as template.resolved_digest.
var resolveImageDigest = func(ctx context.Context, imageRef string) (string, error) {
	return crane.Digest(imageRef, crane.WithContext(ctx))
}
