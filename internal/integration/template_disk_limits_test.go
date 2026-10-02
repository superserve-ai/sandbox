//go:build integration

package integration

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_CreateTemplate_DiskLimits(t *testing.T) {
	limit64 := int32(65536)
	limitAbove := int32(65537)
	cases := []struct {
		name    string
		disk    int32
		limit   *int32
		status  int
		message string
	}{
		{"minimum", 1024, nil, http.StatusAccepted, ""},
		{"below minimum", 1023, nil, http.StatusBadRequest, "disk_mib must be 1024-65536"},
		{"32 GiB", 32768, &limit64, http.StatusAccepted, ""},
		{"64 GiB", 65536, &limit64, http.StatusAccepted, ""},
		{"above ceiling", 65537, &limitAbove, http.StatusBadRequest, "disk_mib must be 1024-65536"},
		{"default quota unchanged", 8193, nil, http.StatusBadRequest, "your team's limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			teamID, apiKey := seedTeamAndKey(t)
			if _, err := testPool.Exec(t.Context(), `UPDATE team SET max_template_disk_mib = $1 WHERE id = $2`, tc.limit, teamID); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"name":"disk-limit","disk_mib":%d,"build_spec":{"from":"debian:12-slim"}}`, tc.disk)
			w := do(newRouter(t), "POST", "/templates", apiKey, body)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.message != "" && !strings.Contains(w.Body.String(), tc.message) {
				t.Fatalf("response = %s, want %q", w.Body.String(), tc.message)
			}
			if tc.status == http.StatusAccepted {
				var disk int32
				if err := testPool.QueryRow(t.Context(), `SELECT disk_mib FROM template WHERE team_id = $1 AND name = 'disk-limit'`, teamID).Scan(&disk); err != nil {
					t.Fatal(err)
				}
				if disk != tc.disk {
					t.Fatalf("persisted disk_mib = %d, want %d", disk, tc.disk)
				}
			} else {
				var count int
				if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM template WHERE team_id = $1`, teamID).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("rejected request persisted %d templates", count)
				}
			}
		})
	}
}

func TestIntegration_TemplateDiskConstraint(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	for _, disk := range []int32{1023, 1024, 32768, 65536, 65537} {
		t.Run(fmt.Sprint(disk), func(t *testing.T) {
			_, err := testQueries.CreateTemplate(t.Context(), db.CreateTemplateParams{
				TeamID:    teamID,
				Name:      fmt.Sprintf("disk-%d", disk),
				BuildSpec: []byte(`{"from":"debian:12-slim"}`),
				Vcpu:      1,
				MemoryMib: 1024,
				DiskMib:   disk,
			})
			if disk >= 1024 && disk <= 65536 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "template_disk_range" {
				t.Fatalf("expected template_disk_range check violation, got %v", err)
			}
		})
	}
}
