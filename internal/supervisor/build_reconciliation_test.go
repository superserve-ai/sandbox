package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type reconciliationDB struct {
	buildID, templateID, teamID uuid.UUID
	attempts                    []db.BuildAttempt
	current                     *uuid.UUID
	now                         time.Time
	hostLost                    bool
	publication                 bool
	transitions                 []string
	recorded                    bool
	claimAvailable              bool
	claimTarget                 int
	claimCalls                  int
	submittedInput              db.SubmittedTemplateBuildInput
	templateInput               db.SubmittedTemplateBuildInput
}

func (m *reconciliationDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (m *reconciliationDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (m *reconciliationDB) QueryRow(_ context.Context, sql string, args ...interface{}) pgx.Row {
	switch {
	case strings.Contains(sql, "FROM template_build_execution e"):
		return reconciliationRow{values: []any{m.buildID, m.current, (*string)(nil), &m.now, "", len(m.attempts), m.publication, ""}}
	case strings.Contains(sql, "SELECT template_id,created_at,now()"):
		return reconciliationRow{values: []any{m.templateID, m.now.Add(-time.Minute), m.now}}
	case strings.Contains(sql, "SELECT claim_template_build"):
		m.claimCalls++
		if m.claimAvailable {
			m.current = &m.attempts[m.claimTarget].ID
			m.claimAvailable = false
			return reconciliationRow{values: []any{m.current}}
		}
		return reconciliationRow{values: []any{(*uuid.UUID)(nil)}}
	case strings.Contains(sql, "FROM template_build_input WHERE build_id"):
		input := m.submittedInput
		return reconciliationRow{values: []any{input.BuildSpec, input.Vcpu, input.MemoryMib, input.DiskMib}}
	case strings.Contains(sql, "FROM template WHERE id"):
		input := m.templateInput
		return reconciliationRow{values: []any{input.BuildSpec, input.Vcpu, input.MemoryMib, input.DiskMib}}
	case strings.Contains(sql, "FROM template_build_attempt a JOIN template_build"):
		for _, a := range m.attempts {
			if a.ID == args[0] {
				return reconciliationRow{values: []any{a.ID, a.BuildID, a.TemplateID, a.HostID, a.IncarnationID, a.VMID, a.State, a.ClaimedAt}}
			}
		}
	case strings.Contains(sql, "SELECT NOT EXISTS(SELECT 1 FROM host"):
		return reconciliationRow{values: []any{m.hostLost}}
	case strings.Contains(sql, "SELECT transition_template_attempt"):
		action := args[2].(string)
		m.transitions = append(m.transitions, action)
		if action == "retry" {
			m.current = nil
		}
		return reconciliationRow{values: []any{true}}
	case strings.Contains(sql, "SELECT record_template_publication"):
		m.recorded = true
		m.publication = true
		return reconciliationRow{values: []any{true}}
	case strings.Contains(sql, "SELECT accept_template_publication"):
		return reconciliationRow{values: []any{true}}
	case strings.Contains(sql, "SELECT template_id,team_id FROM template_build"):
		return reconciliationRow{values: []any{m.templateID, m.teamID}}
	case strings.Contains(sql, "INSERT INTO activity"):
		return reconciliationRow{err: errors.New("activity recording omitted by fake")}
	}
	return reconciliationRow{err: errors.New("unexpected query: " + sql)}
}

type reconciliationRow struct {
	values []any
	err    error
}

func (r reconciliationRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("unexpected scan shape")
	}
	for i, value := range r.values {
		switch d := dest[i].(type) {
		case *uuid.UUID:
			*d = value.(uuid.UUID)
		case **uuid.UUID:
			*d = value.(*uuid.UUID)
		case **string:
			*d = value.(*string)
		case **time.Time:
			*d = value.(*time.Time)
		case *time.Time:
			*d = value.(time.Time)
		case *string:
			*d = value.(string)
		case *int:
			*d = value.(int)
		case *bool:
			*d = value.(bool)
		case *[]byte:
			*d = value.([]byte)
		case *int32:
			*d = value.(int32)
		default:
			return errors.New("unexpected scan destination")
		}
	}
	return nil
}

type reconciliationVMD struct {
	vmdclient.Client
	dispatches        int
	polls             int
	result            vmdclient.BuildStatusResult
	dispatchedVM      string
	dispatchedAttempt string
	inputs            []vmdclient.BuildTemplateInput
}

func (v *reconciliationVMD) BuildTemplate(ctx context.Context, input vmdclient.BuildTemplateInput) (string, error) {
	v.dispatches++
	v.inputs = append(v.inputs, input)
	v.dispatchedVM = input.BuildVMID
	md, _ := metadata.FromOutgoingContext(ctx)
	v.dispatchedAttempt = strings.Join(md.Get("template-build-attempt"), "")
	return "", status.Error(codes.DeadlineExceeded, "response lost after acceptance")
}

func (v *reconciliationVMD) GetBuildStatus(ctx context.Context, vmID string) (vmdclient.BuildStatusResult, error) {
	v.polls++
	md, _ := metadata.FromOutgoingContext(ctx)
	if vmID == "" || len(md.Get("template-build-incarnation")) != 1 {
		return vmdclient.BuildStatusResult{}, errors.New("invalid status request")
	}
	return v.result, nil
}

func newReconciliationFixture() (*BuildSupervisor, *reconciliationDB, *reconciliationVMD) {
	buildID, templateID, attemptID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	m := &reconciliationDB{buildID: buildID, templateID: templateID, teamID: uuid.New(), current: &attemptID, now: now}
	m.submittedInput = db.SubmittedTemplateBuildInput{BuildSpec: []byte(`{"from":"example-base"}`), Vcpu: 1, MemoryMib: 1024, DiskMib: 2048}
	m.templateInput = m.submittedInput
	m.attempts = []db.BuildAttempt{{ID: attemptID, BuildID: buildID, TemplateID: templateID, HostID: "host-a", IncarnationID: uuid.New(), VMID: "build-" + uuid.NewString(), ClaimedAt: now.Add(-time.Minute)}}
	v := &reconciliationVMD{result: vmdclient.BuildStatusResult{Status: "running"}}
	s := &BuildSupervisor{q: db.New(m), cfg: BuildSupervisorConfig{Cell: "example-cell", PublicationBucket: "example-bucket"}, publicationStore: reconciliationStore{}, log: zerolog.New(io.Discard), resolve: func(_ context.Context, host string) (vmdclient.Client, error) {
		if host != "host-a" {
			return nil, errors.New("unexpected host")
		}
		return v, nil
	}}
	return s, m, v
}

func TestReconcileExecutionKeepsAcceptedDispatchOnOriginalOwner(t *testing.T) {
	s, m, v := newReconciliationFixture()
	m.current = nil
	m.claimAvailable = true
	for i := 0; i < 3; i++ {
		if err := s.reconcileExecution(context.Background(), m.buildID); err != nil {
			t.Fatal(err)
		}
	}
	if v.polls != 2 || v.dispatches != 1 || v.dispatchedVM != m.attempts[0].VMID || v.dispatchedAttempt != m.attempts[0].ID.String() || len(m.transitions) != 0 || *m.current != m.attempts[0].ID {
		t.Fatalf("polls=%d dispatches=%d vm=%s attempt=%s transitions=%v current=%v", v.polls, v.dispatches, v.dispatchedVM, v.dispatchedAttempt, m.transitions, m.current)
	}
}

func TestReconcileExecutionRetryRequiresPositiveInfrastructureFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lost       bool
		result     vmdclient.BuildStatusResult
		claimedAgo time.Duration
		want       string
	}{
		{"ordinary redeploy", false, vmdclient.BuildStatusResult{Status: "running"}, time.Minute, ""},
		{"changed incarnation", true, vmdclient.BuildStatusResult{}, time.Minute, "retry"},
		{"missing within grace", false, vmdclient.BuildStatusResult{NotFound: true}, 30 * time.Second, ""},
		{"missing after grace", false, vmdclient.BuildStatusResult{NotFound: true}, time.Minute, "retry"},
		{"deterministic failure", false, vmdclient.BuildStatusResult{Status: "failed", ErrorMessage: "user step failed"}, time.Minute, "fail"},
		{"unclassified failure", false, vmdclient.BuildStatusResult{Status: "failed"}, time.Minute, "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m, v := newReconciliationFixture()
			m.hostLost, v.result = tc.lost, tc.result
			m.attempts[0].ClaimedAt = m.now.Add(-tc.claimedAgo)
			if err := s.reconcileExecution(context.Background(), m.buildID); err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(m.transitions) != 0 {
					t.Fatalf("unexpected transition %v", m.transitions)
				}
			} else if len(m.transitions) != 1 || m.transitions[0] != tc.want {
				t.Fatalf("transitions = %v, want %s", m.transitions, tc.want)
			}
			if tc.want == "retry" {
				if err := s.reconcileExecution(context.Background(), m.buildID); err != nil {
					t.Fatal(err)
				}
				if v.dispatches != 0 || m.claimCalls != 1 || len(m.attempts) != 1 {
					t.Fatal("retry dispatched without an unused eligible host")
				}
			}
		})
	}
}

func TestReconcileExecutionDispatchesReplacementOnDifferentHost(t *testing.T) {
	s, m, first := newReconciliationFixture()
	m.submittedInput = db.SubmittedTemplateBuildInput{
		BuildSpec: []byte(`{"from":"example/image:original","steps":[{"run":"echo original"}],"start_cmd":"/start-original","ready_cmd":"/ready-original"}`),
		Vcpu:      2, MemoryMib: 2048, DiskMib: 4096,
	}
	m.templateInput = m.submittedInput
	m.current = nil
	m.claimAvailable = true
	if err := s.reconcileExecution(context.Background(), m.buildID); err != nil {
		t.Fatal(err)
	}
	if len(first.inputs) != 1 {
		t.Fatalf("first dispatches = %d, want one", len(first.inputs))
	}
	m.templateInput = db.SubmittedTemplateBuildInput{
		BuildSpec: []byte(`{"from":"example/image:edited","steps":[{"run":"echo edited"}],"start_cmd":"/start-edited","ready_cmd":"/ready-edited"}`),
		Vcpu:      8, MemoryMib: 8192, DiskMib: 16384,
	}
	m.hostLost = true
	if err := s.reconcileExecution(context.Background(), m.buildID); err != nil {
		t.Fatal(err)
	}
	if len(m.transitions) != 1 || m.transitions[0] != "retry" {
		t.Fatalf("transitions = %v", m.transitions)
	}
	replacement := db.BuildAttempt{ID: uuid.New(), BuildID: m.buildID, TemplateID: m.templateID, HostID: "host-b", IncarnationID: uuid.New(), VMID: "build-" + uuid.NewString(), ClaimedAt: m.now}
	m.attempts = append(m.attempts, replacement)
	m.claimTarget = 1
	m.claimAvailable = true
	other := &reconciliationVMD{}
	s.resolve = func(_ context.Context, host string) (vmdclient.Client, error) {
		if host != "host-b" {
			return nil, errors.New("replacement resolved a used host")
		}
		return other, nil
	}
	if err := s.reconcileExecution(context.Background(), m.buildID); err != nil {
		t.Fatal(err)
	}
	if other.dispatches != 1 || other.dispatchedVM != replacement.VMID || other.dispatchedAttempt != replacement.ID.String() || replacement.VMID == m.attempts[0].VMID || *m.current != replacement.ID {
		t.Fatalf("replacement dispatch=%d vm=%s attempt=%s current=%v", other.dispatches, other.dispatchedVM, other.dispatchedAttempt, m.current)
	}
	initial, retry := first.inputs[0], other.inputs[0]
	if initial.From != "example/image:original" || initial.VCPU != 2 || initial.MemoryMiB != 2048 || initial.DiskMiB != 4096 || len(initial.Steps) != 1 || initial.Steps[0].Run == nil || *initial.Steps[0].Run != "echo original" || initial.StartCmd != "/start-original" || initial.ReadyCmd != "/ready-original" {
		t.Fatalf("first dispatch did not use submitted inputs: %+v", initial)
	}
	initial.BuildVMID, retry.BuildVMID = "", ""
	if !reflect.DeepEqual(initial, retry) {
		t.Fatalf("retry changed submitted spec or resources: first=%+v retry=%+v", initial, retry)
	}
}

type reconciliationStore struct {
	object string
	data   []byte
}

func (s reconciliationStore) List(context.Context, string) ([]backup.ObjectInfo, error) {
	if s.object == "" {
		return nil, nil
	}
	return []backup.ObjectInfo{{Name: s.object}}, nil
}
func (s reconciliationStore) NewReader(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(s.data))), nil
}

func TestReconcileExecutionRecordsDurableManifestBeforeHostRetry(t *testing.T) {
	s, m, _ := newReconciliationFixture()
	m.hostLost = true
	a := m.attempts[0]
	paths := []string{"/runtime/rootfs.ext4", "/runtime/vmstate.snap", "/runtime/mem.bin", "/runtime/build.meta.json"}
	names := []string{"rootfs.ext4", "vmstate.snap", "mem.bin", "build.meta.json"}
	var files []backup.ManifestFile
	var keyFiles []backup.TaskFile
	for i, name := range names {
		hash := strings.Repeat(string(rune('a'+i)), 64)
		files = append(files, backup.ManifestFile{Name: name, RuntimePath: paths[i], Object: name + ".pabc", SHA256: hash, Size: 10})
		keyFiles = append(keyFiles, backup.TaskFile{Name: name, SHA256: hash, Size: 10})
	}
	generation := backup.GenerationKey(keyFiles)
	manifest := backup.GenerationManifest{TemplateID: a.TemplateID.String(), BuildID: a.VMID, Generation: generation, Files: files, TemplateRuntime: &backup.TemplateRuntime{RootfsPath: paths[0], SnapshotPath: paths[1], MemPath: paths[2]}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	object, err := backup.TemplateObject(a.TemplateID.String(), a.VMID, generation, backup.ManifestObject)
	if err != nil {
		t.Fatal(err)
	}
	s.publicationStore = reconciliationStore{object: object, data: data}
	if err := s.reconcileExecution(context.Background(), m.buildID); err != nil {
		t.Fatal(err)
	}
	if !m.recorded || len(m.transitions) != 0 || m.current == nil {
		t.Fatalf("recorded=%v transitions=%v current=%v", m.recorded, m.transitions, m.current)
	}
}
