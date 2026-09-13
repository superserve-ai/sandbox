package steps

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

func TestResourceNames(t *testing.T) {
	if got := DatabaseName("pilot-team"); got != "qm_pilot_team" {
		t.Errorf("database = %s", got)
	}
	if got := BucketName("example-project", "pilot-team"); got != "example-project-qm-pilot-team" {
		t.Errorf("bucket = %s", got)
	}
	longBucket := BucketName("a-thirty-character-project-name", strings.Repeat("b", 40))
	if len(longBucket) != 63 || longBucket == BucketName("a-thirty-character-project-name", strings.Repeat("b", 39)+"c") {
		t.Errorf("long bucket name = %s (%d chars)", longBucket, len(longBucket))
	}
	if got := ServiceName("pilot-team"); got != "qm-pilot-team" {
		t.Errorf("service = %s", got)
	}
	short := ServiceAccountID("pilot-team")
	long := ServiceAccountID(strings.Repeat("a", 40))
	if short != "qm-pilot-team" || len(long) != 30 || long != ServiceAccountID(strings.Repeat("a", 40)) {
		t.Errorf("service account ids: %s %s", short, long)
	}
	if ServiceAccountID(strings.Repeat("a", 39)+"b") == long {
		t.Error("truncated ids collide")
	}
	if got := ServiceAccountEmail("example-project", "pilot-team"); got != "qm-pilot-team@example-project.iam.gserviceaccount.com" {
		t.Errorf("email = %s", got)
	}
}

func newRunner(t *testing.T, stub bool) (*provisioner.Runner, *tenantstore.Memory, *secrets.Fake, uuid.UUID, tenantstore.Tenant) {
	t.Helper()
	store := tenantstore.NewMemory()
	fake := secrets.NewFake()
	teamID := uuid.New()
	tenant, err := store.CreateTenant(context.Background(), teamID, tenantstore.CreateParams{
		Slug: "pilot-team", OrgName: "Pilot Team", AdminEmail: "admin@example.com", SignIn: "magic_link", ModelProvider: "anthropic",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The model key qm-api writes before triggering a run.
	ref, _ := fake.Put(context.Background(), "qm-pilot-team-ANTHROPIC_API_KEY", []byte("sk-ant-fixture"))
	store.SetSecretRef(context.Background(), teamID, tenant.ID, "ANTHROPIC_API_KEY", ref)
	r := &provisioner.Runner{
		Store: store,
		Env:   provisioner.Env{Project: "example-project", Region: "us-central1", BaseDomain: "qm.example.com", Image: "qm:fixture", Stub: stub},
		Steps: All(Clients{Secrets: fake}),
		Log:   zerolog.Nop(),
	}
	return r, store, fake, teamID, tenant
}

func TestStubPlanProvisionsAndDeprovisions(t *testing.T) {
	ctx := context.Background()
	r, store, fake, teamID, tenant := newRunner(t, true)

	if err := r.Run(ctx, teamID, tenant.ID, provisioner.ModeProvision); err != nil {
		t.Fatal(err)
	}
	row, _ := store.GetTenant(ctx, teamID, tenant.ID)
	if row.Status != tenantstore.StatusReady {
		t.Fatalf("status = %s", row.Status)
	}
	store.SetStatus(ctx, teamID, tenant.ID, tenantstore.StatusProvisioning)
	for name, got := range map[string]*string{
		"db_name": row.DbName, "bucket": row.BucketName, "service_account": row.ServiceAccount,
		"cloud_run_service": row.CloudRunService, "image_tag": row.ImageTag, "public_url": row.PublicUrl,
	} {
		if got == nil {
			t.Errorf("%s not recorded", name)
		}
	}
	if row.PublicUrl != nil && *row.PublicUrl != "https://pilot-team.qm.example.com" {
		t.Errorf("public url = %s", *row.PublicUrl)
	}
	refs, _ := store.ListSecretRefs(ctx, teamID, tenant.ID)
	if len(refs) != 1+len(generatedSecrets) {
		t.Errorf("secret refs = %+v", refs)
	}
	if !fake.Has("qm-pilot-team-PORTAL_SESSION_SECRET") {
		t.Error("portal session secret not generated")
	}
	if v, _ := fake.Get(ctx, "qm-pilot-team-PORTAL_SESSION_SECRET"); len(v) < 32 {
		t.Errorf("portal session secret too short for the portal: %d chars", len(v))
	}

	// A second provision run converges without re-creating anything.
	if err := r.Run(ctx, teamID, tenant.ID, provisioner.ModeProvision); err != nil {
		t.Fatal(err)
	}
	events, _ := store.ListEvents(ctx, teamID, tenant.ID)
	var second []string
	for _, e := range events {
		second = append(second, e.Step+":"+e.Status)
	}
	rerun := strings.Join(second[len(second)/2:], ",")
	for _, step := range []string{"database", "service_account", "bucket", "secrets", "cloud_run"} {
		if !strings.Contains(rerun, step+":skipped") {
			t.Errorf("re-run did not skip %s: %s", step, rerun)
		}
	}
	if strings.Contains(rerun, ":failed") {
		t.Errorf("re-run failed: %s", rerun)
	}
	if fake.Puts["qm-pilot-team-PORTAL_SESSION_SECRET"] != 1 {
		t.Errorf("portal secret rewritten on re-run: %d puts", fake.Puts["qm-pilot-team-PORTAL_SESSION_SECRET"])
	}

	store.SetStatus(ctx, teamID, tenant.ID, tenantstore.StatusDeprovisioning)
	if err := r.Run(ctx, teamID, tenant.ID, provisioner.ModeDeprovision); err != nil {
		t.Fatal(err)
	}
	row, _ = store.GetTenant(ctx, teamID, tenant.ID)
	if row.Status != tenantstore.StatusDeleted {
		t.Errorf("status after deprovision = %s", row.Status)
	}
	if fake.Has("qm-pilot-team-PORTAL_SESSION_SECRET") || fake.Has("qm-pilot-team-ANTHROPIC_API_KEY") {
		t.Error("secrets survived deprovision")
	}
	if refs, _ := store.ListSecretRefs(ctx, teamID, tenant.ID); len(refs) != 0 {
		t.Errorf("secret refs survived deprovision: %+v", refs)
	}
}

func TestRealModeStopsAtFirstUnimplementedStep(t *testing.T) {
	ctx := context.Background()
	r, store, _, teamID, tenant := newRunner(t, false)
	err := r.Run(ctx, teamID, tenant.ID, provisioner.ModeProvision)
	if !errors.Is(err, provisioner.ErrNotImplemented) {
		t.Fatalf("err = %v", err)
	}
	// The secrets step is real and runs first; the identity step is the
	// first cloud-touching one.
	var nie *provisioner.NotImplementedError
	if !errors.As(err, &nie) || nie.Step != "service_account" {
		t.Errorf("stopped at %v, want service_account", err)
	}
	if refs, _ := store.ListSecretRefs(ctx, teamID, tenant.ID); len(refs) != 1+len(generatedSecrets) {
		t.Errorf("secrets not generated before the first cloud step: %+v", refs)
	}
	row, _ := store.GetTenant(ctx, teamID, tenant.ID)
	if row.Status != tenantstore.StatusFailed {
		t.Errorf("status = %s", row.Status)
	}
}

// A model key whose reference never landed is still removed on teardown.
func TestDeprovisionDeletesUnreferencedModelKey(t *testing.T) {
	ctx := context.Background()
	r, store, fake, teamID, tenant := newRunner(t, true)
	if err := store.DeleteSecretRef(ctx, teamID, tenant.ID, "ANTHROPIC_API_KEY"); err != nil {
		t.Fatal(err)
	}
	store.SetStatus(ctx, teamID, tenant.ID, tenantstore.StatusDeprovisioning)
	if err := r.Run(ctx, teamID, tenant.ID, provisioner.ModeDeprovision); err != nil {
		t.Fatal(err)
	}
	if fake.Has("qm-pilot-team-ANTHROPIC_API_KEY") {
		t.Error("unreferenced model key survived deprovision")
	}
}

// The startup gate: outside stub mode the plan reports the steps whose
// cloud implementations have not landed, so the binary refuses to serve
// rather than accepting tenants it would abandon halfway through.
func TestPlanReadyGatesUnimplementedSteps(t *testing.T) {
	clients := Clients{Secrets: secrets.NewFake()}
	if err := provisioner.PlanReady(All(clients), provisioner.Env{Stub: true}); err != nil {
		t.Errorf("stub mode: %v", err)
	}
	err := provisioner.PlanReady(All(clients), provisioner.Env{})
	if err == nil {
		t.Fatal("real mode reported a runnable plan")
	}
	for _, want := range []string{"service_account", "database", "bucket", "cloud_run", "load_balancer", "health_check", "smoke"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from %v", want, err)
		}
	}
	// The Secret Manager-backed steps have no placeholder mode: without a
	// store they are unrunnable even under the stub.
	err = provisioner.PlanReady(All(Clients{}), provisioner.Env{Stub: true})
	if err == nil || !strings.Contains(err.Error(), "secrets") || !strings.Contains(err.Error(), "admin_link") {
		t.Errorf("no secret store: %v", err)
	}
}
