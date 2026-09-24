package abuse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
)

type computeConfig struct {
	Mode         ComputeMode `json:"mode"`
	TrustedTeams []uuid.UUID `json:"trusted_teams"`
	Restrictions []struct {
		SubjectType string    `json:"subject_type"`
		SubjectID   uuid.UUID `json:"subject_id"`
		Actions     []Action  `json:"actions"`
	} `json:"restrictions"`
}

// OwnerLoader returns canonical active owners among the requested user IDs,
// grouped by team. It is called only during refresh, never during evaluation.
type OwnerLoader func(context.Context, []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error)

type ConfigComputeSource struct {
	path     string
	owners   OwnerLoader
	report   func(context.Context, string)
	readFile func(string) ([]byte, error)
	current  atomic.Pointer[ComputeSnapshot]
}

func NewConfigComputeSource(path string, owners OwnerLoader, report func(context.Context, string)) *ConfigComputeSource {
	s := &ConfigComputeSource{path: path, owners: owners, report: report, readFile: os.ReadFile}
	s.current.Store(&ComputeSnapshot{mode: ModeOff})
	return s
}
func (s *ConfigComputeSource) Snapshot() *ComputeSnapshot { return s.current.Load() }

// Run refreshes until shutdown. Call Refresh before serving traffic for the
// initial load.
func (s *ConfigComputeSource) Run(ctx context.Context) {
	s.run(ctx, 5*time.Minute)
}

func (s *ConfigComputeSource) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Refresh(ctx)
		}
	}
}

// Refresh must be serialized by the caller. Read failures clear effective
// restrictions; invalid readable content leaves the published snapshot intact.
func (s *ConfigComputeSource) Refresh(ctx context.Context) {
	if s.path == "" {
		s.current.Store(&ComputeSnapshot{mode: ModeOff})
		return
	}
	data, err := s.readFile(s.path)
	if err != nil {
		s.current.Store(&ComputeSnapshot{mode: ModeOff})
		s.result(ctx, "read_error")
		return
	}
	cfg, err := parseComputeConfig(data)
	if err != nil {
		s.result(ctx, "invalid_content")
		return
	}
	snapshot := &ComputeSnapshot{mode: cfg.Mode, trusted: map[uuid.UUID]bool{}, teams: map[uuid.UUID]bool{}, users: map[uuid.UUID]bool{}}
	for _, id := range cfg.TrustedTeams {
		snapshot.trusted[id] = true
	}
	userIDsSet := map[uuid.UUID]bool{}
	for _, r := range cfg.Restrictions {
		if r.SubjectType == "user" {
			userIDsSet[r.SubjectID] = true
			continue
		}
		snapshot.teams[r.SubjectID] = true
	}
	if len(userIDsSet) > 0 && s.owners != nil {
		ownerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		userIDs := make([]uuid.UUID, 0, len(userIDsSet))
		for id := range userIDsSet {
			userIDs = append(userIDs, id)
		}
		owners, err := s.owners(ownerCtx, userIDs)
		cancel()
		if err != nil {
			s.result(ctx, "owners_error")
		} else {
			for team, ids := range owners {
				for _, id := range ids {
					if userIDsSet[id] {
						snapshot.users[team] = true
					}
				}
			}
		}
	}
	s.current.Store(snapshot)
	s.result(ctx, "success")
}
func (s *ConfigComputeSource) result(ctx context.Context, result string) {
	if s.report != nil {
		s.report(ctx, result)
	}
	if result != "success" {
		log.Error().Str("source", "config").Str("result", result).Msg("compute restriction refresh failed")
	}
}
func parseComputeConfig(data []byte) (computeConfig, error) {
	var cfg computeConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return cfg, fmt.Errorf("trailing content")
	}
	// Null is never valid config content, even where decoding treats it as
	// an omitted field or leaves an earlier duplicate field's value intact.
	dec = json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return cfg, err
		}
		if token == nil {
			return cfg, fmt.Errorf("null config value")
		}
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeOff
	}
	if cfg.Mode != ModeOff && cfg.Mode != ModeObserve && cfg.Mode != ModeEnforce {
		return cfg, fmt.Errorf("invalid mode")
	}
	for _, id := range cfg.TrustedTeams {
		if id == uuid.Nil {
			return cfg, fmt.Errorf("invalid trusted team")
		}
	}
	for _, r := range cfg.Restrictions {
		if (r.SubjectType != "team" && r.SubjectType != "user") || r.SubjectID == uuid.Nil || len(r.Actions) == 0 {
			return cfg, fmt.Errorf("invalid restriction")
		}
		for _, a := range r.Actions {
			if a != ActionCreate && a != ActionResume {
				return cfg, fmt.Errorf("invalid action")
			}
		}
	}
	return cfg, nil
}

func LoadComputeOwners(q db.DBTX) OwnerLoader {
	return func(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
		if len(userIDs) == 0 {
			return nil, nil
		}
		rows, err := q.Query(ctx, `SELECT DISTINCT ura.team_id, ura.user_id
   FROM user_role_assignments ura
   JOIN roles r ON r.id = ura.role_id AND r.scope_type = 'team'
   JOIN team_memberships tm ON tm.team_id = ura.team_id AND tm.user_id = ura.user_id AND tm.status = 'active'
   WHERE ura.scope_type = 'team' AND ura.revoked_at IS NULL AND r.name = 'team_owner'
     AND ura.user_id = ANY($1::uuid[])`, userIDs)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		owners := map[uuid.UUID][]uuid.UUID{}
		for rows.Next() {
			var team, user uuid.UUID
			if err := rows.Scan(&team, &user); err != nil {
				return nil, err
			}
			owners[team] = append(owners[team], user)
		}
		return owners, rows.Err()
	}
}
