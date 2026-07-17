package scheduler

import (
	"context"
	"errors"
	"testing"

	"github.com/superserve-ai/sandbox/internal/db"
)

type fakeHostStore struct {
	active    []db.ListActiveHostsByLoadRow
	hosts     []db.Host
	activeErr error
	hostsErr  error
}

func (f *fakeHostStore) ListActiveHostsByLoad(context.Context) ([]db.ListActiveHostsByLoadRow, error) {
	return f.active, f.activeErr
}

func (f *fakeHostStore) ListHosts(context.Context) ([]db.Host, error) {
	return f.hosts, f.hostsErr
}

func TestSelectHostLegacyFallbackRequiresEmptyHostTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		store   *fakeHostStore
		want    string
		wantErr bool
	}{
		{
			name:  "legacy database without host rows",
			store: &fakeHostStore{},
			want:  "default",
		},
		{
			name:    "provisioned but draining fleet",
			store:   &fakeHostStore{hosts: []db.Host{{ID: "default", Status: "draining"}}},
			wantErr: true,
		},
		{
			name:    "provisioned but unhealthy fleet",
			store:   &fakeHostStore{hosts: []db.Host{{ID: "default", Status: "unhealthy"}}},
			wantErr: true,
		},
		{
			name: "active host",
			store: &fakeHostStore{
				active: []db.ListActiveHostsByLoadRow{{ID: "host-a"}},
				hosts:  []db.Host{{ID: "host-a", Status: "active"}},
			},
			want: "host-a",
		},
		{
			name:    "fallback decision query fails closed",
			store:   &fakeHostStore{hostsErr: errors.New("database unavailable")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LeastLoaded{DB: tt.store, DefaultHostID: "default"}
			got, err := s.SelectHost(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SelectHost() = %q, nil; want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectHost() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("SelectHost() = %q, want %q", got, tt.want)
			}
		})
	}
}
