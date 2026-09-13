package vm

import (
	"errors"
	"github.com/superserve-ai/sandbox/internal/admission"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkRefusalRequiresPristineFirstAttemptAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fresh    bool
		attempt  int
		leftover bool
		err      error
		proof    bool
	}{
		{"fresh", true, 1, false, network.ErrOperatorSlotLimit, true},
		{"prior life", false, 1, false, network.ErrOperatorSlotLimit, false},
		{"retry", true, 2, false, network.ErrOperatorSlotLimit, false},
		{"cleanup incomplete", true, 1, true, network.ErrOperatorSlotLimit, false},
		{"unknown", true, 1, false, errors.New("network failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager()
			m.cfg.RunDir = t.TempDir()
			m.vms = map[string]*VMInstance{"vm-a": {ID: "vm-a", Status: StatusError}}
			m.admission = admission.NewGate(false, 0)
			if tc.leftover {
				if err := os.Mkdir(filepath.Join(m.cfg.RunDir, "vm-a"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := m.networkRestoreRefusal("vm-a", tc.err, tc.fresh, tc.attempt)
			if vmdclient.IsAdmissionRefusal(err) != tc.proof {
				t.Fatal(err)
			}
			if (m.vms["vm-a"] == nil) != tc.proof {
				t.Fatal("provisional ownership cleanup violated")
			}
		})
	}
}
