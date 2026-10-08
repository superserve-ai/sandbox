package vm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
)

func TestMachineProtocolWithholdsOwnershipFromOldProxy(t *testing.T) {
	mgr := &Manager{vms: map[string]*VMInstance{
		"machine":             {ID: "machine", Status: StatusRunning, MachineOwned: true, MachineOwnerPrincipalID: "principal"},
		"malformed-machine":   {ID: "malformed-machine", Status: StatusRunning, MachineOwned: true},
		"malformed-principal": {ID: "malformed-principal", Status: StatusRunning, MachineOwnerPrincipalID: "principal"},
		"ordinary":            {ID: "ordinary", Status: StatusRunning, OwnerID: "creator"},
	}}
	server := NewLocalHTTPServer(mgr, zerolog.Nop())
	for _, id := range []string{"machine", "malformed-machine", "malformed-principal", "ordinary", "__healthcheck__"} {
		for _, revision := range []string{"", "old-revision", auth.MachineIdentityRevision} {
			request := httptest.NewRequest(http.MethodGet, "/instances/"+id, nil)
			request.Header.Set(auth.ProxyMachineIdentityHeader, revision)
			response := httptest.NewRecorder()
			server.handleInstance(response, request)
			want := http.StatusOK
			if id == "__healthcheck__" || (id != "ordinary" && revision != auth.MachineIdentityRevision) {
				want = http.StatusNotFound
			}
			if response.Code != want {
				t.Fatalf("%s revision=%q returned %d, want %d", id, revision, response.Code, want)
			}
			if response.Header().Get(auth.VMDMachineIdentityHeader) != auth.MachineIdentityRevision {
				t.Fatal("VMD omitted protocol evidence, including health 404")
			}
		}
	}
}
