package harness

import "github.com/superserve-ai/sandbox/internal/start"

// StartSpec composes the manifest's boot command into the existing start.Spec
// contract that boxd supervises in the guest, so a harness manifest can drive
// the same supervisor path as a resolved image start command. It is a
// convenience bridge — only the fields the manifest actually declares are set:
//
//   - Argv  ← StartArgv() (the split boot command).
//   - Ready ← m.Ready (the readiness probe string, passed through verbatim).
//
// Env/User/WorkingDir are left to the runtime to fill from the Actor
// environment (secrets/bindings, /state mounts), which the manifest does not
// own. Restart is left empty so start's DefaultRestartPolicy applies: a Level-1
// harness completes a turn and exits cleanly between events under the exec
// transport, and the supervisor restarts it on the next turn.
func (m *Manifest) StartSpec() start.Spec {
	return start.Spec{
		Argv:  m.StartArgv(),
		Ready: m.Ready,
	}
}
