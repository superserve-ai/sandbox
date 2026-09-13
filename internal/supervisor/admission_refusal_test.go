package supervisor

import (
	"context"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestBuildRequeuesOnlyDefinitiveAdmissionRefusal(t *testing.T) {
	for _, proof := range []bool{true, false} {
		mock := &pollDBTX{}
		s := &BuildSupervisor{q: db.New(mock), log: zerolog.Nop()}
		err := status.Error(codes.Unavailable, "unknown outcome")
		if proof {
			err = vmdclient.AdmissionRefused(codes.Unavailable, "draining")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s.requeueRefusedBuild(ctx, uuid.New(), err)
		if mock.fired("RequeueBuildDispatch") != proof {
			t.Fatal("unsafe requeue", proof, mock.names)
		}
	}
}
