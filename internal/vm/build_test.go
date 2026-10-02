package vm

import (
	"slices"
	"testing"

	"github.com/rs/zerolog"
)

// The builder freezes only when the host is switched to it: the flag is on
// the builder's command line for that host alone, and absent otherwise.
func TestTemplateBuildArgsCarryTheFreezeSwitch(t *testing.T) {
	for _, on := range []bool{false, true} {
		m := &Manager{log: zerolog.Nop(), netMgr: &fakeNetMgr{}, cfg: ManagerConfig{TemplateFreezeWorkload: on}}
		args := m.templateBuildArgs(BuildTemplateRequest{TemplateID: "tpl"}, "build-1", []byte("{}"), 7)
		if got := slices.Contains(args, "--freeze-workload"); got != on {
			t.Errorf("switch=%v: --freeze-workload present=%v; args=%v", on, got, args)
		}
		if !slices.Contains(args, "--template-id") || !slices.Contains(args, "7") {
			t.Errorf("args=%v; want the build's own arguments kept", args)
		}
	}
}
