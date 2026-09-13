package steps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	if got := RoleName("pilot-team"); got != "qm_pilot_team" {
		t.Errorf("role = %s", got)
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

// tenantFixture is one tenant plus every fake the plan runs against.
type tenantFixture struct {
	runner   *provisioner.Runner
	store    *tenantstore.Memory
	secrets  *secrets.Fake
	accounts *fakeAccounts
	dbs      *fakeDatabases
	buckets  *fakeBuckets
	services *fakeServices
	lb       *fakeLoadBalancer
	tenant   *fakeTenantServer
	teamID   uuid.UUID
	row      tenantstore.Tenant
}

func (f *tenantFixture) provision(t *testing.T) error {
	t.Helper()
	return f.runner.Run(context.Background(), f.teamID, f.row.ID, provisioner.ModeProvision, 0)
}

func (f *tenantFixture) deprovision(t *testing.T) error {
	t.Helper()
	ctx := context.Background()
	if _, err := f.store.SetStatus(ctx, f.teamID, f.row.ID, tenantstore.StatusDeprovisioning); err != nil {
		t.Fatal(err)
	}
	return f.runner.Run(ctx, f.teamID, f.row.ID, provisioner.ModeDeprovision, 0)
}

func (f *tenantFixture) reprovision(t *testing.T) error {
	t.Helper()
	ctx := context.Background()
	if _, err := f.store.SetStatus(ctx, f.teamID, f.row.ID, tenantstore.StatusProvisioning); err != nil {
		t.Fatal(err)
	}
	return f.runner.Run(ctx, f.teamID, f.row.ID, provisioner.ModeProvision, 0)
}

func (f *tenantFixture) current(t *testing.T) tenantstore.Tenant {
	t.Helper()
	row, err := f.store.GetTenant(context.Background(), f.teamID, f.row.ID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func (f *tenantFixture) events(t *testing.T) []tenantstore.Event {
	t.Helper()
	events, err := f.store.ListEvents(context.Background(), f.teamID, f.row.ID)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// nothingLeaked is the assertion every teardown test ends on: no identity,
// no database, no bucket, no HMAC credential, no service, no route, and no
// secret belonging to the tenant.
func (f *tenantFixture) nothingLeaked(t *testing.T) {
	t.Helper()
	if live := f.accounts.live(); len(live) != 0 {
		t.Errorf("service accounts survived teardown: %v", live)
	}
	if !f.dbs.empty() {
		t.Error("a database or role survived teardown")
	}
	if !f.buckets.empty() {
		t.Error("a bucket or storage credential survived teardown")
	}
	if !f.services.empty() {
		t.Error("a cloud run service survived teardown")
	}
	if !f.lb.empty() {
		t.Error("a load balancer host rule survived teardown")
	}
	for _, name := range f.secrets.Names() {
		if strings.HasPrefix(name, "qm-pilot-team-") {
			t.Errorf("secret survived teardown: %s", name)
		}
	}
	refs, err := f.store.ListSecretRefs(context.Background(), f.teamID, f.row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("secret refs survived teardown: %+v", refs)
	}
}

func newFixture(t *testing.T, stub bool) *tenantFixture {
	t.Helper()
	ctx := context.Background()
	store := tenantstore.NewMemory()
	fake := secrets.NewFake()
	teamID := uuid.New()
	row, err := store.CreateTenant(ctx, teamID, tenantstore.CreateParams{
		Slug: "pilot-team", OrgName: "Pilot Team", AdminEmail: "admin@example.com",
		SignIn: "magic_link", ModelProvider: "anthropic", Harness: "pi",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The model key qm-api writes before triggering a run, and the
	// platform's shared Resend key, which Terraform owns.
	ref, err := fake.Put(ctx, "qm-pilot-team-ANTHROPIC_API_KEY", []byte("sk-ant-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSecretRef(ctx, teamID, row.ID, "ANTHROPIC_API_KEY", ref); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.Put(ctx, "qm-resend-api-key", []byte("re_fixture")); err != nil {
		t.Fatal(err)
	}

	f := &tenantFixture{
		store: store, secrets: fake, teamID: teamID, row: row,
		accounts: newFakeAccounts(), dbs: newFakeDatabases(), buckets: newFakeBuckets(),
		services: newFakeServices(), lb: newFakeLoadBalancer(), tenant: newFakeTenantServer(t),
	}
	clients := Clients{
		Secrets: fake, Accounts: f.accounts, Databases: f.dbs, Buckets: f.buckets,
		Services: f.services, LoadBalancer: f.lb, HTTP: f.tenant.client(),
		// The real budgets are minutes; a test that watches a probe fail
		// should not spend them.
		HealthTimeout: 200 * time.Millisecond,
		SmokeTimeout:  200 * time.Millisecond,
		ProbeInterval: 20 * time.Millisecond,
	}
	f.runner = &provisioner.Runner{
		Store: store,
		Env:   testEnv(stub),
		Steps: All(clients),
		Log:   zerolog.Nop(),
	}
	return f
}

func testEnv(stub bool) provisioner.Env {
	return provisioner.Env{
		Project: "example-project", Region: "us-central1", BaseDomain: "qm.example.com",
		Image: "qm:fixture", Stub: stub, ExecutesPlan: true,

		SQLInstance:       "qm-tenants",
		SQLConnectionName: "example-project:us-central1:qm-tenants",
		SQLPrivateIP:      "10.0.0.3",
		SQLAdminUser:      "qm_admin",
		SQLAdminSecret:    "qm-sql-admin",
		URLMap:            "qm-https",
		VPCNetwork:        "example-network",
		VPCSubnetwork:     "example-subnet",
		BucketLocation:    "us-central1",

		ResendSecret:     "qm-resend-api-key",
		EmailFrom:        "QM <no-reply@mail.qm.example.com>",
		SandboxAPIURL:    "https://api.example.com",
		SandboxTemplate:  "qm-agent-0.1.0",
		SandboxKeyRegion: "use",
	}
}

// fakeTenantServer stands in for the deployed tenant. Its client rewrites
// every request at the tenant's public hostname to the test server, so the
// probes exercise the URLs they will really build.
type fakeTenantServer struct {
	srv *httptest.Server

	mu sync.Mutex
	// authorizeStatus is what GET /idp/authorize answers with; 503 is the
	// failure the reference tenant shipped.
	authorizeStatus int
	healthStatus    int
	// rootStatus is what the portal answers at /.
	rootStatus int
	// modelKeyStatus answers the provider's key check. The fixture's HTTP
	// client sends every request here, the provider's included, so this is
	// what stands in for Anthropic saying yes or no.
	modelKeyStatus int
	paths          []string
}

func newFakeTenantServer(t *testing.T) *fakeTenantServer {
	t.Helper()
	f := &fakeTenantServer{
		authorizeStatus: http.StatusOK, healthStatus: http.StatusOK,
		modelKeyStatus: http.StatusOK, rootStatus: http.StatusOK,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		authorize, health, modelKey, root := f.authorizeStatus, f.healthStatus, f.modelKeyStatus, f.rootStatus
		f.mu.Unlock()
		switch {
		case r.URL.Path == "/v1/models":
			w.WriteHeader(modelKey)
		case r.URL.Path == "/healthz":
			w.WriteHeader(health)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case r.URL.Path == "/idp/authorize":
			w.WriteHeader(authorize)
			if authorize >= 500 {
				_, _ = w.Write([]byte("<html><body><h1>Email delivery isn't configured</h1></body></html>"))
			}
		default:
			w.WriteHeader(root)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTenantServer) setAuthorizeStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorizeStatus = status
}

func (f *fakeTenantServer) setRootStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rootStatus = status
}

func (f *fakeTenantServer) setModelKeyStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modelKeyStatus = status
}

func (f *fakeTenantServer) requested(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.paths {
		if p == path {
			return true
		}
	}
	return false
}

func (f *fakeTenantServer) client() *http.Client {
	target, _ := url.Parse(f.srv.URL)
	return &http.Client{
		Transport: rewriteTransport{host: target.Host},
		// Same as the real probe client: a redirect is an answer, not
		// something to follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type rewriteTransport struct{ host string }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = rt.host
	return http.DefaultTransport.RoundTrip(clone)
}

// ── The happy path ───────────────────────────────────────────────────────

func TestProvisionBuildsTheWholeStack(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	row := f.current(t)
	if row.Status != tenantstore.StatusReady {
		t.Fatalf("status = %s", row.Status)
	}
	for name, got := range map[string]*string{
		"db_name": row.DbName, "bucket": row.BucketName, "service_account": row.ServiceAccount,
		"cloud_run_service": row.CloudRunService, "image_tag": row.ImageTag, "public_url": row.PublicUrl,
	} {
		if got == nil {
			t.Fatalf("%s not recorded", name)
		}
	}
	if *row.PublicUrl != "https://pilot-team.qm.example.com" {
		t.Errorf("public url = %s", *row.PublicUrl)
	}
	if !row.SandboxApiKeyID.Valid {
		t.Error("no sandbox key issued")
	}
	// The database is owned by the tenant's own role, not by the instance
	// admin the provisioner connected as, and it is closed to every other
	// role on the shared instance.
	if owner := f.dbs.databases["qm_pilot_team"]; owner != "qm_pilot_team" {
		t.Errorf("database owner = %q", owner)
	}
	if !f.dbs.closed["qm_pilot_team"] {
		t.Error("the tenant's database is still reachable by other roles")
	}
	if _, ok := f.buckets.buckets["example-project-qm-pilot-team"]; !ok {
		t.Error("bucket not created")
	}
	if len(f.buckets.hmac) != 1 {
		t.Errorf("storage credentials = %v", f.buckets.hmac)
	}
	if f.lb.hosts["pilot-team.qm.example.com"] != "qm-pilot-team" {
		t.Errorf("host rule = %v", f.lb.hosts)
	}
	// Both probes ran against the tenant's own hostname.
	if !f.tenant.requested("/healthz") || !f.tenant.requested("/idp/authorize") {
		t.Errorf("probes did not run: %v", f.tenant.paths)
	}

	spec, ok := f.services.spec("qm-pilot-team")
	if !ok {
		t.Fatal("no service deployed")
	}
	assertTenantSpec(t, spec)

	// The identity can read every secret its service mounts — the grant and
	// the spec are rendered from one list, and this is what proves it.
	granted := map[string]bool{}
	for _, name := range f.accounts.grantedSecrets() {
		granted[name] = true
	}
	for env, secretName := range spec.SecretEnv {
		if !granted[secretName] {
			t.Errorf("%s mounts %s with no grant to the tenant", env, secretName)
		}
	}

	// Nothing secret-shaped reached the event log.
	for _, e := range f.events(t) {
		var detail map[string]any
		if len(e.Detail) > 0 {
			_ = json.Unmarshal(e.Detail, &detail)
		}
		raw := string(e.Detail) + e.Step + deref(e.Message)
		for _, needle := range []string{"sk-ant-", "ss_live_", "re_fixture", "hmac-secret"} {
			if strings.Contains(raw, needle) {
				t.Errorf("event %s/%s leaked %q: %s", e.Step, e.Status, needle, raw)
			}
		}
	}
	_ = ctx
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func assertTenantSpec(t *testing.T, spec ServiceSpec) {
	t.Helper()
	if spec.Image != "qm:fixture" || spec.ServiceAccount == "" {
		t.Errorf("spec = %+v", spec)
	}
	if spec.Network != "example-network" || spec.Subnetwork != "example-subnet" {
		t.Errorf("the service is not on the VPC: %+v", spec)
	}
	// The email transport, which is the whole reason a provisioned tenant
	// can be signed into.
	for key, want := range map[string]string{
		"AUTH_EMBEDDED":        "1",
		"AUTH_EMAIL_TRANSPORT": "resend",
		"AUTH_EMAIL_FROM":      "QM <no-reply@mail.qm.example.com>",
		"AUTH_ALLOWED_EMAILS":  "admin@example.com",
		"ADMIN_GRANTS":         "admin@example.com:org_admin",
		"PUBLIC_WEB_URL":       "https://pilot-team.qm.example.com",
		"ORG_ID":               "pilot-team",
		"S3_BUCKET":            "example-project-qm-pilot-team",
		"SANDBOX_BACKEND":      "superserve",
		"SUPERSERVE_BASE_URL":  "https://api.example.com",
		"SUPERSERVE_TEMPLATE":  "qm-agent-0.1.0",
		"HARNESS":              "pi",
		"MODEL_PROVIDER":       "anthropic",
	} {
		if spec.Env[key] != want {
			t.Errorf("env %s = %q, want %q", key, spec.Env[key], want)
		}
	}
	// The Resend key is the platform's, not a per-tenant secret.
	if spec.SecretEnv["RESEND_API_KEY"] != "qm-resend-api-key" {
		t.Errorf("RESEND_API_KEY mounts %q", spec.SecretEnv["RESEND_API_KEY"])
	}
	for _, name := range []string{
		"DATABASE_URL", "CORE_SIGNING_SECRET", "CAPABILITY_SECRET", "PORTAL_IDENTITY_SECRET",
		"CONNECTOR_SECRET_KEY", "SKILL_SIGNING_SECRET", "PORTAL_SESSION_SECRET",
		"AUTH_TOKEN_SECRET", "AUTH_CLIENT_SECRET", "AUTH_SIGNING_JWK",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "SUPERSERVE_API_KEY", "ANTHROPIC_API_KEY",
	} {
		if spec.SecretEnv[name] != "qm-pilot-team-"+name {
			t.Errorf("%s mounts %q", name, spec.SecretEnv[name])
		}
	}
	// Nothing secret-shaped is in the plain environment, which Cloud Run
	// shows to anyone who can describe the service.
	for key, value := range spec.Env {
		if strings.HasPrefix(value, "sk-") || strings.HasPrefix(value, "ss_live_") || strings.HasPrefix(value, "re_") {
			t.Errorf("plain env %s carries a credential", key)
		}
	}
}

// A tenant's runtime secrets are all distinct and long enough for QM's own
// boot check, and the signing key is a P-256 private JWK.
func TestGeneratedSecretsSatisfyTheTenantImage(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, name := range []string{
		"CORE_SIGNING_SECRET", "CAPABILITY_SECRET", "PORTAL_IDENTITY_SECRET",
		"CONNECTOR_SECRET_KEY", "SKILL_SIGNING_SECRET", "PORTAL_SESSION_SECRET",
		"AUTH_TOKEN_SECRET", "AUTH_CLIENT_SECRET",
	} {
		value, err := f.secrets.Get(ctx, "qm-pilot-team-"+name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(value) < 32 {
			t.Errorf("%s is %d characters; QM requires at least 32", name, len(value))
		}
		if prev, dup := seen[string(value)]; dup {
			t.Errorf("%s reuses %s's value", name, prev)
		}
		seen[string(value)] = name
	}
	raw, err := f.secrets.Get(ctx, "qm-pilot-team-AUTH_SIGNING_JWK")
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]string
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatalf("signing key is not JSON: %v", err)
	}
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["d"] == "" || jwk["x"] == "" || jwk["y"] == "" {
		t.Errorf("signing key is not a P-256 private JWK: %v", jwk)
	}
}

// A tenant's service account, Cloud Run service and bucket are all named
// after its slug, so a slug can be chosen to land on a name that already
// exists. Adopting one would run tenant code as whatever identity it is —
// the platform's own provisioner account is a qm-<word> name too — replace
// whatever that service was, and hand all of it to teardown to delete. So
// each step adopts only what carries this tenant's own marker.
func TestProvisionRefusesResourcesItDoesNotOwn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(*tenantFixture)
		wants string
	}{
		{
			"a service account with the name the slug derives",
			func(f *tenantFixture) {
				f.accounts.mu.Lock()
				f.accounts.accounts["qm-pilot-team@example-project.iam.gserviceaccount.com"] = "the platform's provisioner"
				f.accounts.mu.Unlock()
			},
			"does not belong to this tenant",
		},
		{
			"a bucket with the name the slug derives",
			func(f *tenantFixture) {
				f.buckets.mu.Lock()
				f.buckets.buckets["example-project-qm-pilot-team"] = map[string]string{"owner": "somebody else"}
				f.buckets.mu.Unlock()
			},
			"does not belong to this tenant",
		},
		{
			"a backend service with the name the slug derives",
			func(f *tenantFixture) {
				f.lb.mu.Lock()
				f.lb.owners["qm-pilot-team"] = "somebody else"
				f.lb.mu.Unlock()
			},
			"does not belong to this tenant",
		},
		{
			"a bucket somebody else creates in the gap after the look-up",
			func(f *tenantFixture) {
				f.buckets.failNext("buckets.Get", 1)
				f.buckets.mu.Lock()
				f.buckets.buckets["example-project-qm-pilot-team"] = map[string]string{"owner": "somebody else"}
				f.buckets.mu.Unlock()
			},
			"",
		},
		{
			"a cloud run service with the name the slug derives",
			func(f *tenantFixture) {
				f.services.mu.Lock()
				f.services.services["qm-pilot-team"] = ServiceSpec{Name: "qm-pilot-team", Labels: map[string]string{"qm-tenant-id": "somebody-else"}}
				f.services.mu.Unlock()
			},
			"does not belong to this tenant",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, false)
			tc.plant(f)
			err := f.provision(t)
			if err == nil {
				t.Fatal("the provision adopted a resource it does not own")
			}
			if tc.wants != "" && !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("err = %v", err)
			}
			if f.current(t).Status != tenantstore.StatusFailed {
				t.Errorf("status = %s", f.current(t).Status)
			}
		})
	}
}

// And teardown will not delete one either: a tenant whose slug collided must
// not take the resource it collided with down with it.
func TestTeardownRefusesResourcesItDoesNotOwn(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	// Something else takes over the names between provision and teardown.
	f.accounts.mu.Lock()
	f.accounts.accounts["qm-pilot-team@example-project.iam.gserviceaccount.com"] = "the platform's provisioner"
	f.accounts.mu.Unlock()

	if err := f.deprovision(t); err == nil {
		t.Fatal("teardown deleted a resource it does not own")
	}
	if _, ok := f.accounts.accounts["qm-pilot-team@example-project.iam.gserviceaccount.com"]; !ok {
		t.Error("the account that did not belong to this tenant was deleted")
	}
}

// The marker every step keys on is the tenant's id, not its slug: the slug
// is chosen by whoever created the tenant.
func TestTenantMarkersKeyOnTheTenantID(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	id := f.row.ID.String()
	spec, _ := f.services.spec("qm-pilot-team")
	if spec.Labels[TenantLabelKey] != id {
		t.Errorf("service labels = %v", spec.Labels)
	}
	if f.buckets.buckets["example-project-qm-pilot-team"][TenantLabelKey] != id {
		t.Errorf("bucket labels = %v", f.buckets.buckets["example-project-qm-pilot-team"])
	}
	if got := f.accounts.accounts["qm-pilot-team@example-project.iam.gserviceaccount.com"]; !strings.Contains(got, id) {
		t.Errorf("service account description = %q", got)
	}
}

// ── Idempotence ──────────────────────────────────────────────────────────

func TestProvisionIsIdempotent(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	before := f.current(t)
	sessionSecret := f.secrets.Puts["qm-pilot-team-PORTAL_SESSION_SECRET"]

	if err := f.reprovision(t); err != nil {
		t.Fatal(err)
	}
	after := f.current(t)
	if after.Status != tenantstore.StatusReady {
		t.Fatalf("status = %s", after.Status)
	}
	if f.accounts.creates != 1 {
		t.Errorf("service accounts created = %d", f.accounts.creates)
	}
	if f.dbs.created != 1 {
		t.Errorf("databases created = %d", f.dbs.created)
	}
	if f.buckets.created != 1 {
		t.Errorf("buckets created = %d", f.buckets.created)
	}
	if f.buckets.minted != 1 {
		t.Errorf("storage credentials minted = %d", f.buckets.minted)
	}
	if f.lb.adds != 1 {
		t.Errorf("host rules added = %d", f.lb.adds)
	}
	if f.secrets.Puts["qm-pilot-team-PORTAL_SESSION_SECRET"] != sessionSecret {
		t.Error("a re-run rewrote the portal session secret")
	}
	if before.SandboxApiKeyID != after.SandboxApiKeyID {
		t.Error("a re-run reissued the sandbox key")
	}
	if len(f.store.IssuedKeys) != 1 {
		t.Errorf("sandbox keys issued = %d", len(f.store.IssuedKeys))
	}
	// The service is redeployed every run, deliberately: that is how a
	// rotated secret or a new image reaches a tenant.
	if f.services.deploys != 2 {
		t.Errorf("deploys = %d", f.services.deploys)
	}
}

// A route left pointing at a stale backend is repaired by the next run
// rather than reported as already done — otherwise a half-built route
// would survive every retry while the probes after it went on failing.
func TestProvisionRepairsAStaleRoute(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	f.lb.mu.Lock()
	f.lb.hosts["pilot-team.qm.example.com"] = "qm-stale"
	f.lb.mu.Unlock()

	if err := f.reprovision(t); err != nil {
		t.Fatal(err)
	}
	if got := f.lb.hosts["pilot-team.qm.example.com"]; got != "qm-pilot-team" {
		t.Errorf("a stale route survived a re-run: %q", got)
	}
}

// The isolation of a tenant's database is two statements apart from the
// CREATE that cannot share its transaction, so a run interrupted between
// them would leave a database every other tenant could connect to. The
// step reasserts both on every run rather than only on the one that
// created it.
func TestProvisionReassertsDatabaseIsolation(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	// Stand in for a first attempt that created the database and died
	// before it could close it or set its owner.
	f.dbs.mu.Lock()
	f.dbs.closed["qm_pilot_team"] = false
	f.dbs.databases["qm_pilot_team"] = "qm_admin"
	f.dbs.mu.Unlock()

	if err := f.reprovision(t); err != nil {
		t.Fatal(err)
	}
	if !f.dbs.closed["qm_pilot_team"] {
		t.Error("a re-run left the database open to other roles")
	}
	if owner := f.dbs.databases["qm_pilot_team"]; owner != "qm_pilot_team" {
		t.Errorf("a re-run left the database owned by %q", owner)
	}
	if f.dbs.created != 1 {
		t.Errorf("databases created = %d", f.dbs.created)
	}
}

// ── Rollback ─────────────────────────────────────────────────────────────

func TestDeprovisionLeavesNothingBehind(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	keyID := uuid.UUID(f.current(t).SandboxApiKeyID.Bytes)
	if err := f.deprovision(t); err != nil {
		t.Fatal(err)
	}
	if f.current(t).Status != tenantstore.StatusDeleted {
		t.Errorf("status = %s", f.current(t).Status)
	}
	if !f.store.RevokedKeys[keyID] {
		t.Error("the tenant's sandbox key was not revoked")
	}
	f.nothingLeaked(t)

	// The platform's shared Resend secret survives, but the deleted
	// tenant's identity does not stay on its policy: IAM keeps a binding
	// naming a deleted principal, so every tenant that ever existed would
	// otherwise pile up on the one policy every future tenant needs.
	if !f.secrets.Has("qm-resend-api-key") {
		t.Error("teardown deleted the platform's shared Resend key")
	}
	if members := f.accounts.grants["qm-resend-api-key"]; len(members) != 0 {
		t.Errorf("the deleted tenant is still on the shared secret's policy: %v", members)
	}
}

// The platform's email key can be rotated to a different Secret Manager
// resource between a tenant being built and being torn down. The binding
// that exists is the one made at build time, so that is the name the
// tenant's row records and the one teardown has to revoke.
func TestDeprovisionRevokesTheSharedGrantItActuallyMade(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	account := *f.current(t).ServiceAccount
	if !slices.Contains(f.accounts.grants["qm-resend-api-key"], account) {
		t.Fatalf("the tenant was not granted the shared key: %v", f.accounts.grants)
	}

	// The platform rotates to a new resource.
	if _, err := f.secrets.Put(ctx, "qm-resend-api-key-v2", []byte("re_rotated")); err != nil {
		t.Fatal(err)
	}
	env := f.runner.Env
	env.ResendSecret = "qm-resend-api-key-v2"
	f.runner.Env = env

	// A retry after the rotation moves the grant rather than accumulating
	// one on each: only one name is ever recorded, so the old binding has
	// to be given up while it is still known.
	if err := f.reprovision(t); err != nil {
		t.Fatal(err)
	}
	if members := f.accounts.grants["qm-resend-api-key"]; len(members) != 0 {
		t.Errorf("the grant on the rotated-away key survived a retry: %v", members)
	}
	if !slices.Contains(f.accounts.grants["qm-resend-api-key-v2"], account) {
		t.Errorf("the tenant was not granted the rotated key: %v", f.accounts.grants)
	}

	if err := f.deprovision(t); err != nil {
		t.Fatal(err)
	}
	if members := f.accounts.grants["qm-resend-api-key-v2"]; len(members) != 0 {
		t.Errorf("the grant survived teardown: %v", members)
	}
	// And the platform's secrets themselves are untouched: they belong to
	// no tenant.
	if !f.secrets.Has("qm-resend-api-key") || !f.secrets.Has("qm-resend-api-key-v2") {
		t.Error("teardown deleted a platform secret")
	}
}

// A provision that fails partway leaves resources behind on purpose — the
// retry is meant to converge — but the teardown that follows must still
// clear every one of them, including the ones created by a step that never
// got to record what it made.
func TestTeardownAfterAPartialProvision(t *testing.T) {
	for _, tc := range []struct {
		name string
		call string
	}{
		{"the deploy fails", "services.Deploy"},
		{"the route fails", "lb.EnsureHostRule"},
		{"the bucket grant fails", "buckets.GrantAccess"},
		{"recording the service account fails", "accounts.Create"},
		{"the database create fails", "databases.EnsureDatabase"},
		{"minting storage credentials fails", "buckets.CreateHMACKey"},
		{"a secret grant fails", "accounts.GrantSecretAccess"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, false)
			f.failOn(tc.call)
			if err := f.provision(t); err == nil {
				t.Fatal("the provision reported success")
			}
			if f.current(t).Status != tenantstore.StatusFailed {
				t.Fatalf("status = %s", f.current(t).Status)
			}
			// The failure names the step an operator has to look at, and
			// carries the reason.
			assertFailureEvent(t, f.events(t))

			if err := f.deprovision(t); err != nil {
				t.Fatalf("teardown after a failed provision: %v", err)
			}
			f.nothingLeaked(t)
		})
	}
}

// Teardown of a tenant whose provision never ran at all: every step's
// Rollback has to be safe when its Run never was.
func TestTeardownWithoutAProvision(t *testing.T) {
	f := newFixture(t, false)
	if err := f.deprovision(t); err != nil {
		t.Fatal(err)
	}
	if f.current(t).Status != tenantstore.StatusDeleted {
		t.Errorf("status = %s", f.current(t).Status)
	}
	f.nothingLeaked(t)
	// Every step reported a terminal status rather than erroring out.
	terminal := map[string]string{}
	for _, e := range f.events(t) {
		if e.Status != tenantstore.EventStarted {
			terminal[e.Step] = e.Status
		}
	}
	for _, step := range []string{
		"secrets", "service_account", "database", "bucket", "sandbox_key",
		"cloud_run", "load_balancer", "health_check", "smoke", "admin_link",
	} {
		if terminal[step] == "" {
			t.Errorf("%s never reached a terminal status", step)
		}
		if terminal[step] == tenantstore.EventFailed {
			t.Errorf("%s failed on a tenant that was never provisioned", step)
		}
	}
}

// A teardown that fails partway is retried, and the retry has to converge
// rather than trip over what the first attempt already removed.
func TestTeardownIsRetryable(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	f.failOn("databases.DropDatabase")
	if err := f.deprovision(t); err == nil {
		t.Fatal("the teardown reported success")
	}
	if f.current(t).Status != tenantstore.StatusFailed {
		t.Fatalf("status = %s", f.current(t).Status)
	}
	if err := f.deprovision(t); err != nil {
		t.Fatalf("retried teardown: %v", err)
	}
	f.nothingLeaked(t)
}

func (f *tenantFixture) failOn(call string) {
	switch {
	case strings.HasPrefix(call, "accounts."):
		f.accounts.failNext(call, 1)
	case strings.HasPrefix(call, "databases."):
		f.dbs.failNext(call, 1)
	case strings.HasPrefix(call, "buckets."):
		f.buckets.failNext(call, 1)
	case strings.HasPrefix(call, "services."):
		f.services.failNext(call, 1)
	case strings.HasPrefix(call, "lb."):
		f.lb.failNext(call, 1)
	}
}

func assertFailureEvent(t *testing.T, events []tenantstore.Event) {
	t.Helper()
	for _, e := range events {
		if e.Status != tenantstore.EventFailed || e.Step == provisioner.RunStep {
			continue
		}
		if len(e.Detail) == 0 {
			t.Errorf("%s failed with no detail to act on", e.Step)
		}
		var detail map[string]any
		if err := json.Unmarshal(e.Detail, &detail); err != nil {
			t.Errorf("%s detail is not JSON: %v", e.Step, err)
		}
		if msg, _ := detail["error"].(string); msg == "" {
			t.Errorf("%s detail carries no error: %s", e.Step, e.Detail)
		}
		return
	}
	t.Error("no step reported a failure")
}

// QM_BASE_DOMAIN is deployment configuration and can change after a tenant
// is built. The rule on the shared URL map is still the hostname the tenant
// was routed under, so teardown has to look for that one — otherwise the
// route survives and the backend delete behind it fails on every retry.
func TestTeardownRemovesTheRouteTheTenantWasBuiltWith(t *testing.T) {
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.lb.hosts["pilot-team.qm.example.com"]; !ok {
		t.Fatalf("routes = %v", f.lb.hosts)
	}
	env := f.runner.Env
	env.BaseDomain = "qm2.example.com"
	f.runner.Env = env

	if err := f.deprovision(t); err != nil {
		t.Fatal(err)
	}
	if !f.lb.empty() {
		t.Errorf("the route the tenant was built with survived teardown: %v", f.lb.hosts)
	}
}

// ── Sign-in ──────────────────────────────────────────────────────────────

// The defect this whole step set exists to prevent: a stack whose health
// check is green and whose sign-in path fails closed. A healthy service
// that 503s on /idp/authorize must fail the provision, not pass it.
func TestSmokeFailsWhenSignInFailsClosed(t *testing.T) {
	f := newFixture(t, false)
	f.tenant.setAuthorizeStatus(http.StatusServiceUnavailable)
	err := f.provision(t)
	if err == nil {
		t.Fatal("a tenant nobody can sign in to was reported ready")
	}
	if !strings.Contains(err.Error(), "sign-in fails closed") {
		t.Errorf("err = %v", err)
	}
	if f.current(t).Status != tenantstore.StatusFailed {
		t.Errorf("status = %s", f.current(t).Status)
	}
	// The operator is told what the tenant said, not just that a probe
	// failed.
	var found bool
	for _, e := range f.events(t) {
		if e.Step == "smoke" && e.Status == tenantstore.EventFailed && strings.Contains(string(e.Detail), "Email delivery") {
			found = true
		}
	}
	if !found {
		t.Errorf("the smoke failure did not carry the tenant's own reason: %v", f.events(t))
	}
}

// A redirect is the broker's own answer to a well-formed request, so it
// passes; anything that is not the broker answering does not. A 404 is an
// image with no broker mounted and a 401 is the load balancer's request
// being turned away before it ever reaches one — both are tenants nobody
// could sign in to, and neither is a 5xx.
func TestSmokeAcceptsOnlyTheBrokersOwnAnswer(t *testing.T) {
	f := newFixture(t, false)
	f.tenant.setAuthorizeStatus(http.StatusFound)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}

	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusBadRequest} {
		other := newFixture(t, false)
		other.tenant.setAuthorizeStatus(status)
		err := other.provision(t)
		if err == nil {
			t.Errorf("a tenant whose sign-in answered %d was reported ready", status)
			continue
		}
		if !strings.Contains(err.Error(), "sign-in fails closed") {
			t.Errorf("status %d: err = %v", status, err)
		}
	}
}

// A portal that does not answer its own front door is not a usable tenant,
// even with a green health check: a 404 is a route that is not there and a
// 401 is a front door turning visitors away.
func TestSmokeFailsWhenThePortalDoesNotAnswer(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusInternalServerError} {
		f := newFixture(t, false)
		f.tenant.setRootStatus(status)
		err := f.provision(t)
		if err == nil {
			t.Errorf("a tenant whose portal answered %d was reported ready", status)
			continue
		}
		if !strings.Contains(err.Error(), "portal returned") {
			t.Errorf("status %d: err = %v", status, err)
		}
	}
	// A redirect to sign-in is the portal answering.
	f := newFixture(t, false)
	f.tenant.setRootStatus(http.StatusFound)
	if err := f.provision(t); err != nil {
		t.Fatalf("a portal that redirects to sign-in: %v", err)
	}
}

// A model key the provider rejects outright fails the provision: a tenant
// whose agent cannot call a model is not a working tenant, and finding out
// at the first message instead is far worse.
func TestSmokeFailsOnARejectedModelKey(t *testing.T) {
	f := newFixture(t, false)
	f.tenant.setModelKeyStatus(http.StatusUnauthorized)
	err := f.provision(t)
	if err == nil {
		t.Fatal("a tenant whose model key was rejected was reported ready")
	}
	if !strings.Contains(err.Error(), "rejected the tenant's model key") {
		t.Errorf("err = %v", err)
	}
	// The key itself never reaches the event log.
	for _, e := range f.events(t) {
		if strings.Contains(string(e.Detail)+deref(e.Message), "sk-ant-fixture") {
			t.Errorf("the model key leaked into %s/%s", e.Step, e.Status)
		}
	}
}

// Not being able to ask the provider is not the same as being told no: a
// rate limit, an outage or an egress policy in the way must not fail a
// provision.
func TestSmokeToleratesAnUnreachableProvider(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusNotFound} {
		f := newFixture(t, false)
		f.tenant.setModelKeyStatus(status)
		if err := f.provision(t); err != nil {
			t.Errorf("provider answered %d: %v", status, err)
		}
	}
}

// ── Sign-in policy ───────────────────────────────────────────────────────

// Sign-in opens to the admin's address and nothing else. Deriving a domain
// from that address would be convenient and is not sound: nothing in an
// address distinguishes a company's domain from a mailbox provider's, and
// one wrong guess opens the tenant — with the team's model key and sandbox
// credentials in it — to every account at that provider.
func TestTenantEnvDoesNotWidenSignInToADomain(t *testing.T) {
	for _, admin := range []string{"founder@gmail.com", "admin@pilot-team.com", "someone@yahoo.fr"} {
		f := newFixture(t, false)
		if err := f.provision(t); err != nil {
			t.Fatal(err)
		}
		row := f.current(t)
		row.AdminEmail = admin
		env, err := TenantEnv(provisioner.NewTenant(row, testEnv(false), f.store))
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := env["AUTH_ALLOWED_EMAIL_DOMAIN"]; ok {
			t.Errorf("%s widened sign-in to %q", admin, got)
		}
		if env["AUTH_ALLOWED_EMAILS"] != admin {
			t.Errorf("AUTH_ALLOWED_EMAILS = %q, want %q", env["AUTH_ALLOWED_EMAILS"], admin)
		}
	}
}

// ── Readiness ────────────────────────────────────────────────────────────

// The startup gate. It no longer reports unimplemented steps — there are
// none — but it still refuses a binary whose plan could not run: a missing
// client, or a shared-infrastructure value the deploy never set.
func TestPlanReadyRefusesAnIncompleteConfiguration(t *testing.T) {
	full := Clients{
		Secrets: secrets.NewFake(), Accounts: newFakeAccounts(), Databases: newFakeDatabases(),
		Buckets: newFakeBuckets(), Services: newFakeServices(), LoadBalancer: newFakeLoadBalancer(),
	}
	if err := provisioner.PlanReady(All(full), testEnv(false)); err != nil {
		t.Errorf("a fully configured plan was refused: %v", err)
	}
	// Stub mode needs no cloud clients and no shared infrastructure.
	if err := provisioner.PlanReady(All(Clients{Secrets: secrets.NewFake()}), provisioner.Env{Stub: true}); err != nil {
		t.Errorf("stub mode: %v", err)
	}
	// The Secret Manager-backed steps have no placeholder mode.
	err := provisioner.PlanReady(All(Clients{}), provisioner.Env{Stub: true})
	if err == nil {
		t.Fatal("a plan with no secret store was accepted")
	}
	for _, want := range []string{"secrets", "sandbox_key", "admin_link"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from %v", want, err)
		}
	}
	// No clients at all, in a process that runs plans: every cloud step
	// says so.
	err = provisioner.PlanReady(All(Clients{Secrets: secrets.NewFake()}), testEnv(false))
	if err == nil {
		t.Fatal("a plan with no cloud clients was accepted")
	}
	for _, want := range []string{"service_account", "database", "bucket", "cloud_run", "load_balancer"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from %v", want, err)
		}
	}

	// The qm-api service in its default mode only queues the job that runs
	// the plan, so it holds no cloud clients and must not refuse to start
	// for the want of them — while still checking the configuration it
	// hands that job.
	queues := testEnv(false)
	queues.ExecutesPlan = false
	if err := provisioner.PlanReady(All(Clients{Secrets: secrets.NewFake()}), queues); err != nil {
		t.Errorf("a process that only queues runs was refused: %v", err)
	}
	queues.ResendSecret = ""
	if err := provisioner.PlanReady(All(Clients{Secrets: secrets.NewFake()}), queues); err == nil || !strings.Contains(err.Error(), "QM_RESEND_SECRET") {
		t.Errorf("a process that only queues runs skipped the configuration check: %v", err)
	}

	// A tenant with no email transport can never be signed into, so the
	// plan refuses to start rather than building one.
	noEmail := testEnv(false)
	noEmail.ResendSecret = ""
	err = provisioner.PlanReady(All(full), noEmail)
	if err == nil || !strings.Contains(err.Error(), "QM_RESEND_SECRET") {
		t.Errorf("a plan with no email transport: %v", err)
	}
	noSender := testEnv(false)
	noSender.EmailFrom = ""
	if err := provisioner.PlanReady(All(full), noSender); err == nil || !strings.Contains(err.Error(), "QM_EMAIL_FROM") {
		t.Errorf("a plan with no sender address: %v", err)
	}

	for _, tc := range []struct {
		name  string
		mut   func(*provisioner.Env)
		wants string
	}{
		{"no sql host", func(e *provisioner.Env) { e.SQLPrivateIP = "" }, "QM_SQL_PRIVATE_IP"},
		{"no url map", func(e *provisioner.Env) { e.URLMap = "" }, "QM_LB_URL_MAP"},
		{"no vpc", func(e *provisioner.Env) { e.VPCSubnetwork = "" }, "QM_VPC_SUBNETWORK"},
		{"no tenant image", func(e *provisioner.Env) { e.Image = "" }, "QM_TENANT_IMAGE"},
		{"no bucket location", func(e *provisioner.Env) { e.BucketLocation = "" }, "QM_TENANT_BUCKET_LOCATION"},
		{"no sandbox template", func(e *provisioner.Env) { e.SandboxTemplate = "" }, "QM_SANDBOX_TEMPLATE"},
		{"no sql admin secret", func(e *provisioner.Env) { e.SQLAdminSecret = "" }, "QM_SQL_ADMIN_SECRET"},
		{"a mangled bucket lifecycle policy", func(e *provisioner.Env) { e.BucketLifecycleJSON = "{not json" }, "QM_TENANT_BUCKET_LIFECYCLE_JSON"},
		{"a lifecycle policy that is only whitespace", func(e *provisioner.Env) { e.BucketLifecycleJSON = "  \n " }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testEnv(false)
			tc.mut(&env)
			err := provisioner.PlanReady(All(full), env)
			if tc.wants == "" {
				// Nothing but whitespace is no policy, and the bucket
				// client has to read it the same way — a plan that starts
				// here and then fails to parse it stops every tenant after
				// its secrets, identity and database already exist.
				if err != nil {
					t.Errorf("err = %v, want the plan accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("err = %v, want %s named", err, tc.wants)
			}
		})
	}
}

// ── Stub mode ────────────────────────────────────────────────────────────

func TestStubPlanProvisionsAndDeprovisions(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, true)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	row := f.current(t)
	if row.Status != tenantstore.StatusReady {
		t.Fatalf("status = %s", row.Status)
	}
	for name, got := range map[string]*string{
		"db_name": row.DbName, "bucket": row.BucketName, "service_account": row.ServiceAccount,
		"cloud_run_service": row.CloudRunService, "image_tag": row.ImageTag, "public_url": row.PublicUrl,
	} {
		if got == nil {
			t.Errorf("%s not recorded", name)
		}
	}
	// Nothing was asked of the cloud.
	if f.accounts.creates != 0 || f.dbs.created != 0 || f.buckets.created != 0 || f.services.deploys != 0 || f.lb.adds != 0 {
		t.Error("stub mode called a cloud client")
	}
	if v, _ := f.secrets.Get(ctx, "qm-pilot-team-PORTAL_SESSION_SECRET"); len(v) < 32 {
		t.Errorf("portal session secret too short for the portal: %d chars", len(v))
	}

	if err := f.reprovision(t); err != nil {
		t.Fatal(err)
	}
	events := f.events(t)
	var statuses []string
	for _, e := range events {
		statuses = append(statuses, e.Step+":"+e.Status)
	}
	rerun := strings.Join(statuses[len(statuses)/2:], ",")
	for _, step := range []string{"database", "service_account", "bucket", "secrets", "cloud_run", "sandbox_key"} {
		if !strings.Contains(rerun, step+":skipped") {
			t.Errorf("re-run did not skip %s: %s", step, rerun)
		}
	}
	if strings.Contains(rerun, ":failed") {
		t.Errorf("re-run failed: %s", rerun)
	}

	if err := f.deprovision(t); err != nil {
		t.Fatal(err)
	}
	if f.current(t).Status != tenantstore.StatusDeleted {
		t.Errorf("status after deprovision = %s", f.current(t).Status)
	}
	if f.secrets.Has("qm-pilot-team-PORTAL_SESSION_SECRET") || f.secrets.Has("qm-pilot-team-ANTHROPIC_API_KEY") {
		t.Error("secrets survived deprovision")
	}
	// The platform's shared Resend key belongs to no tenant and must
	// survive every teardown.
	if !f.secrets.Has("qm-resend-api-key") {
		t.Error("teardown deleted the platform's shared Resend key")
	}
	if refs, _ := f.store.ListSecretRefs(ctx, f.teamID, f.row.ID); len(refs) != 0 {
		t.Errorf("secret refs survived deprovision: %+v", refs)
	}
}

// A model key whose reference never landed is still removed on teardown.
func TestDeprovisionDeletesUnreferencedModelKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, true)
	if err := f.store.DeleteSecretRef(ctx, f.teamID, f.row.ID, "ANTHROPIC_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := f.deprovision(t); err != nil {
		t.Fatal(err)
	}
	if f.secrets.Has("qm-pilot-team-ANTHROPIC_API_KEY") {
		t.Error("unreferenced model key survived deprovision")
	}
}

// Teardown revokes the tenant's sandbox API key rather than merely
// forgetting the reference: the key is bound to this cell, and team
// migration refuses a region cutover while a tenant still points at a live
// one.
func TestDeprovisionRevokesTheSandboxKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, false)
	if err := f.provision(t); err != nil {
		t.Fatal(err)
	}
	keyID := uuid.UUID(f.current(t).SandboxApiKeyID.Bytes)
	if f.store.RevokedKeys[keyID] {
		t.Error("provisioning revoked the tenant's sandbox key")
	}
	// The key the tenant's service mounts is the one that was issued.
	raw, err := f.secrets.Get(ctx, "qm-pilot-team-SUPERSERVE_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "ss_live_use_") {
		t.Errorf("the issued key is not tagged with the cell's region: %d characters", len(raw))
	}

	if err := f.deprovision(t); err != nil {
		t.Fatal(err)
	}
	if !f.store.RevokedKeys[keyID] {
		t.Error("deprovisioning left the tenant's sandbox key live")
	}

	// A tenant that never got a key tears down without one.
	other := newFixture(t, false)
	if err := other.deprovision(t); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range other.events(t) {
		if e.Step == "sandbox_key" && e.Status == tenantstore.EventSkipped {
			found = true
		}
	}
	if !found {
		t.Error("teardown without a key did not skip sandbox_key")
	}
}

func TestNewSandboxKeyShape(t *testing.T) {
	tagged, err := NewSandboxKey("use")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tagged, "ss_live_use_") {
		t.Errorf("key = %q", tagged)
	}
	untagged, err := NewSandboxKey("")
	if err != nil {
		t.Fatal(err)
	}
	// The random half is base64url, so it may contain underscores of its
	// own; what matters is that no region token was inserted.
	if !strings.HasPrefix(untagged, "ss_live_") || strings.HasPrefix(untagged, "ss_live_use_") {
		t.Errorf("untagged key = %q", untagged)
	}
	if tagged == untagged {
		t.Error("two keys came out the same")
	}
}

func TestDatabaseURL(t *testing.T) {
	env := testEnv(false)
	got := DatabaseURL(env, "qm_pilot_team", "p@ss word/1", "qm_pilot_team")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("%q: %v", got, err)
	}
	if u.Host != "10.0.0.3:5432" || u.Path != "/qm_pilot_team" {
		t.Errorf("url = %s", got)
	}
	// The shared instance refuses unencrypted connections, so a DSN that
	// disabled TLS would fail to connect at all.
	if u.Query().Get("sslmode") != "require" {
		t.Errorf("sslmode = %q", u.Query().Get("sslmode"))
	}
	// The password is escaped rather than breaking the URL apart.
	pw, _ := u.User.Password()
	if pw != "p@ss word/1" {
		t.Errorf("password = %q", pw)
	}
	env.SQLPrivateIP = "10.0.0.3:6432"
	if u, _ := url.Parse(DatabaseURL(env, "r", "p", "d")); u.Host != "10.0.0.3:6432" {
		t.Errorf("an explicit port was overridden: %s", u.Host)
	}
}
