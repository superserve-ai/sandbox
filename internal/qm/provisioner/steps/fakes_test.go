package steps

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// The fakes stand in for the GCP clients. Each records what it was asked to
// do and can be told to fail one call, which is how the tests get a plan to
// stop partway and then check that rolling back leaves nothing behind.

// fakeFailures makes one named call fail, optionally only the first n times.
type fakeFailures struct {
	mu   sync.Mutex
	errs map[string]int
}

func (f *fakeFailures) failNext(call string, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errs == nil {
		f.errs = map[string]int{}
	}
	f.errs[call] = times
}

func (f *fakeFailures) check(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errs[call] == 0 {
		return nil
	}
	f.errs[call]--
	return fmt.Errorf("fake %s failed", call)
}

type fakeAccounts struct {
	fakeFailures
	mu       sync.Mutex
	accounts map[string]bool
	grants   map[string][]string // secret name -> accounts
	creates  int
	deletes  int
}

func newFakeAccounts() *fakeAccounts {
	return &fakeAccounts{accounts: map[string]bool{}, grants: map[string][]string{}}
}

func (f *fakeAccounts) Exists(_ context.Context, email string) (bool, error) {
	if err := f.check("accounts.Exists"); err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accounts[email], nil
}

func (f *fakeAccounts) Create(_ context.Context, accountID, _ string) (string, error) {
	if err := f.check("accounts.Create"); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	email := accountID + "@example-project.iam.gserviceaccount.com"
	f.accounts[email] = true
	f.creates++
	return email, nil
}

func (f *fakeAccounts) Delete(_ context.Context, email string) error {
	if err := f.check("accounts.Delete"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.accounts, email)
	f.deletes++
	return nil
}

func (f *fakeAccounts) GrantSecretAccess(_ context.Context, secretName, email string) error {
	if err := f.check("accounts.GrantSecretAccess"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, have := range f.grants[secretName] {
		if have == email {
			return nil
		}
	}
	f.grants[secretName] = append(f.grants[secretName], email)
	return nil
}

func (f *fakeAccounts) RevokeSecretAccess(_ context.Context, secretName, email string) error {
	if err := f.check("accounts.RevokeSecretAccess"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	members := f.grants[secretName][:0]
	for _, have := range f.grants[secretName] {
		if have != email {
			members = append(members, have)
		}
	}
	if len(members) == 0 {
		delete(f.grants, secretName)
		return nil
	}
	f.grants[secretName] = members
	return nil
}

func (f *fakeAccounts) live() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.accounts))
	for email := range f.accounts {
		out = append(out, email)
	}
	sort.Strings(out)
	return out
}

func (f *fakeAccounts) grantedSecrets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.grants))
	for name := range f.grants {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type fakeDatabases struct {
	fakeFailures
	mu        sync.Mutex
	databases map[string]string // name -> owner
	closed    map[string]bool   // name -> CONNECT taken from PUBLIC
	users     map[string]string // name -> password
	created   int
}

func newFakeDatabases() *fakeDatabases {
	return &fakeDatabases{databases: map[string]string{}, closed: map[string]bool{}, users: map[string]string{}}
}

func (f *fakeDatabases) EnsureDatabase(_ context.Context, name, owner string) error {
	if err := f.check("databases.EnsureDatabase"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[owner]; !ok {
		return fmt.Errorf("fake: database %s owned by a role that does not exist", name)
	}
	if _, ok := f.databases[name]; !ok {
		f.created++
	}
	// The real client reasserts the owner and the revoke on every call;
	// recording the owner each time is the fake's equivalent.
	f.databases[name] = owner
	f.closed[name] = true
	return nil
}

func (f *fakeDatabases) DropDatabase(_ context.Context, name string) error {
	if err := f.check("databases.DropDatabase"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.databases, name)
	delete(f.closed, name)
	return nil
}

func (f *fakeDatabases) EnsureUser(_ context.Context, name, password string) error {
	if err := f.check("databases.EnsureUser"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[name] = password
	return nil
}

func (f *fakeDatabases) DropUser(_ context.Context, name string) error {
	if err := f.check("databases.DropUser"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Postgres refuses to drop a role that still owns a database, and the
	// step's ordering is what keeps that from happening.
	for db, owner := range f.databases {
		if owner == name {
			return fmt.Errorf("fake: role %s still owns database %s", name, db)
		}
	}
	delete(f.users, name)
	return nil
}

func (f *fakeDatabases) empty() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.databases) == 0 && len(f.users) == 0
}

type fakeBuckets struct {
	fakeFailures
	mu      sync.Mutex
	buckets map[string]string // name -> location
	access  map[string][]string
	hmac    map[string]string // accessID -> account
	created int
	minted  int
}

func newFakeBuckets() *fakeBuckets {
	return &fakeBuckets{buckets: map[string]string{}, access: map[string][]string{}, hmac: map[string]string{}}
}

func (f *fakeBuckets) Exists(_ context.Context, name string) (bool, error) {
	if err := f.check("buckets.Exists"); err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.buckets[name]
	return ok, nil
}

func (f *fakeBuckets) Create(_ context.Context, name, location, _ string) error {
	if err := f.check("buckets.Create"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buckets[name] = location
	f.created++
	return nil
}

func (f *fakeBuckets) Delete(_ context.Context, name string) error {
	if err := f.check("buckets.Delete"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.buckets, name)
	delete(f.access, name)
	return nil
}

func (f *fakeBuckets) GrantAccess(_ context.Context, name, email string) error {
	if err := f.check("buckets.GrantAccess"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.access[name] = append(f.access[name], email)
	return nil
}

func (f *fakeBuckets) CreateHMACKey(_ context.Context, email string) (HMACKey, error) {
	if err := f.check("buckets.CreateHMACKey"); err != nil {
		return HMACKey{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.minted++
	id := fmt.Sprintf("GOOG%08d", f.minted)
	f.hmac[id] = email
	return HMACKey{AccessID: id, Secret: "hmac-secret-" + id}, nil
}

func (f *fakeBuckets) ListHMACKeys(_ context.Context, email string) ([]string, error) {
	if err := f.check("buckets.ListHMACKeys"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id, owner := range f.hmac {
		if owner == email {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeBuckets) DeleteHMACKey(_ context.Context, accessID string) error {
	if err := f.check("buckets.DeleteHMACKey"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hmac, accessID)
	return nil
}

func (f *fakeBuckets) empty() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.buckets) == 0 && len(f.hmac) == 0
}

type fakeServices struct {
	fakeFailures
	mu       sync.Mutex
	services map[string]ServiceSpec
	deploys  int
}

func newFakeServices() *fakeServices {
	return &fakeServices{services: map[string]ServiceSpec{}}
}

func (f *fakeServices) Get(_ context.Context, name string) (ServiceStatus, bool, error) {
	if err := f.check("services.Get"); err != nil {
		return ServiceStatus{}, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	spec, ok := f.services[name]
	if !ok {
		return ServiceStatus{}, false, nil
	}
	return ServiceStatus{URI: "https://" + name + ".run.app", Revision: name + "-0001", ImageTag: spec.Image}, true, nil
}

func (f *fakeServices) Deploy(_ context.Context, spec ServiceSpec) (ServiceStatus, error) {
	if err := f.check("services.Deploy"); err != nil {
		return ServiceStatus{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.services[spec.Name] = spec
	f.deploys++
	return ServiceStatus{URI: "https://" + spec.Name + ".run.app", Revision: spec.Name + "-0001", ImageTag: spec.Image}, nil
}

func (f *fakeServices) Delete(_ context.Context, name string) error {
	if err := f.check("services.Delete"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.services, name)
	return nil
}

func (f *fakeServices) spec(name string) (ServiceSpec, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	spec, ok := f.services[name]
	return spec, ok
}

func (f *fakeServices) empty() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.services) == 0
}

type fakeLoadBalancer struct {
	fakeFailures
	mu    sync.Mutex
	hosts map[string]string
	adds  int
}

func newFakeLoadBalancer() *fakeLoadBalancer {
	return &fakeLoadBalancer{hosts: map[string]string{}}
}

func (f *fakeLoadBalancer) HostRuleExists(_ context.Context, host string) (bool, error) {
	if err := f.check("lb.HostRuleExists"); err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.hosts[host]
	return ok, nil
}

func (f *fakeLoadBalancer) AddHostRule(_ context.Context, host, service string) error {
	if err := f.check("lb.AddHostRule"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[host] = service
	f.adds++
	return nil
}

func (f *fakeLoadBalancer) RemoveHostRule(_ context.Context, host string) error {
	if err := f.check("lb.RemoveHostRule"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hosts, host)
	return nil
}

func (f *fakeLoadBalancer) empty() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.hosts) == 0
}
