package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// HMACKey is an interoperability credential for one service account: the
// tenant's QM talks to Cloud Storage through an S3 client, which
// authenticates with an access key rather than with the Google credentials
// Cloud Run injects.
type HMACKey struct {
	AccessID string
	Secret   string
}

// BucketAdmin manages the tenant's object storage (Cloud Storage JSON API).
//
// Every method must be idempotent. Create on a bucket that exists is a
// no-op, Delete on one that does not is a no-op, and Delete empties the
// bucket first — Cloud Storage refuses to delete a bucket with objects in
// it, so a teardown that did not would fail forever on any tenant that had
// used its storage.
type BucketAdmin interface {
	// Get returns the bucket's labels, or exists=false when there is none.
	// The labels are what tell a bucket this tenant owns from one that
	// merely has the name its slug derives.
	Get(ctx context.Context, name string) (labels map[string]string, exists bool, err error)
	// Create makes the bucket in location with uniform bucket-level access,
	// the given labels, and — when lifecycleJSON is non-empty — that
	// lifecycle policy.
	Create(ctx context.Context, name, location, lifecycleJSON string, labels map[string]string) error
	Delete(ctx context.Context, name string) error
	// GrantAccess binds roles/storage.objectAdmin on the bucket to the
	// tenant's service account.
	GrantAccess(ctx context.Context, name, serviceAccountEmail string) error
	// CreateHMACKey mints an interoperability key for the service account.
	CreateHMACKey(ctx context.Context, serviceAccountEmail string) (HMACKey, error)
	// ListHMACKeys returns the access IDs of every key, active or not, that
	// belongs to the service account.
	ListHMACKeys(ctx context.Context, serviceAccountEmail string) ([]string, error)
	// DeleteHMACKey deactivates and deletes one key. Idempotent.
	DeleteHMACKey(ctx context.Context, accessID string) error
}

var errNoBucketAdmin = errors.New("no bucket client configured")

// bucket creates the tenant's bucket, grants its identity access, and mints
// the HMAC credentials the tenant's S3 client uses. Output: Row.BucketName.
type bucket struct {
	c Clients
}

func (bucket) Name() string { return "bucket" }

func (s bucket) Ready(env provisioner.Env) error {
	if env.Stub {
		return nil
	}
	if env.ExecutesPlan && s.c.Buckets == nil {
		return errNoBucketAdmin
	}
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	if err := env.Require("QM_TENANT_BUCKET_LOCATION", env.BucketLocation); err != nil {
		return err
	}
	// Parsed here rather than at the bucket call: a malformed policy would
	// otherwise be discovered after the tenant's secrets, sandbox key,
	// identity and database already exist, on every tenant, forever.
	_, err := ParseLifecyclePolicy(env.BucketLifecycleJSON)
	return err
}

// ParseLifecyclePolicy checks the shape of QM_TENANT_BUCKET_LIFECYCLE_JSON
// and reports whether there is a policy to apply. Only the outline is
// checked — the rules themselves are Cloud Storage's to accept — but the
// outline is what a deploy can mangle.
//
// Strict about the outline on purpose. A permissive parse turns `{}`,
// `null` or a misspelled `{"rules": ...}` into "no rules", which is not an
// error anywhere: the plan starts, every bucket is created, and the policy
// nobody notices is missing is the one that reaps abandoned uploads.
func ParseLifecyclePolicy(policy string) (string, error) {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return "", nil
	}
	var parsed struct {
		Rule *[]json.RawMessage `json:"rule"`
	}
	decoder := json.NewDecoder(strings.NewReader(policy))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return "", fmt.Errorf("QM_TENANT_BUCKET_LIFECYCLE_JSON is not a lifecycle policy: %w", err)
	}
	// A decoder stops at the end of the first value, so anything after it
	// would pass here and be rejected later by the bucket client's whole-
	// input unmarshal — after the tenant's secrets, identity and database
	// already exist.
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return "", errors.New("QM_TENANT_BUCKET_LIFECYCLE_JSON is not a lifecycle policy: trailing data after the object")
	}
	if parsed.Rule == nil {
		return "", errors.New(`QM_TENANT_BUCKET_LIFECYCLE_JSON is not a lifecycle policy: no "rule" list`)
	}
	return policy, nil
}

func (s bucket) Run(ctx context.Context, t *provisioner.Tenant) error {
	name := BucketName(t.Env.Project, t.Row.Slug)
	if t.Env.Stub {
		if t.Row.BucketName != nil {
			return provisioner.Skip("bucket " + *t.Row.BucketName + " already recorded")
		}
		return t.Record(ctx, tenantstore.Resources{BucketName: &name})
	}
	if s.c.Buckets == nil {
		return errNoBucketAdmin
	}
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	if t.Row.ServiceAccount == nil {
		return fmt.Errorf("bucket: the tenant has no service account recorded")
	}
	account := *t.Row.ServiceAccount

	labels := TenantLabels(t.Row.ID.String(), t.Row.Slug)
	existing, exists, err := s.c.Buckets.Get(ctx, name)
	switch {
	case err != nil:
		return fmt.Errorf("look up the tenant's bucket: %w", err)
	case !exists:
		if err := s.c.Buckets.Create(ctx, name, t.Env.BucketLocation, t.Env.BucketLifecycleJSON, labels); err != nil {
			return fmt.Errorf("create the tenant's bucket: %w", err)
		}
		// Read back rather than trusting the create: it tolerates an
		// already-exists, which is how a bucket somebody else made in the
		// gap between the look-up above and here would otherwise be
		// adopted — and granted to this tenant on the next line.
		if existing, exists, err = s.c.Buckets.Get(ctx, name); err != nil {
			return fmt.Errorf("look up the tenant's bucket: %w", err)
		} else if !exists {
			return fmt.Errorf("bucket %s was created but cannot be read", name)
		}
		fallthrough
	default:
		if existing[TenantLabelKey] != t.Row.ID.String() {
			return fmt.Errorf("%w: bucket %s", ErrNotOwned, name)
		}
	}
	if err := s.c.Buckets.GrantAccess(ctx, name, account); err != nil {
		return fmt.Errorf("grant the tenant access to its bucket: %w", err)
	}
	if err := s.ensureHMACKey(ctx, t, account); err != nil {
		return err
	}
	if t.Row.BucketName != nil && *t.Row.BucketName == name {
		return provisioner.Skip("bucket " + name + " already recorded")
	}
	return t.Record(ctx, tenantstore.Resources{BucketName: &name})
}

// ensureHMACKey mints the interoperability credential once and leaves it
// alone afterwards. The check is on the secrets, not on the account's key
// list: a key whose secret was never stored is unusable (Cloud Storage
// returns the secret exactly once, at creation), so it is deleted and
// replaced rather than adopted.
func (s bucket) ensureHMACKey(ctx context.Context, t *provisioner.Tenant, account string) error {
	stored, err := s.hmacStored(ctx, t)
	if err != nil {
		return err
	}
	if stored {
		return nil
	}
	// Clear whatever half an earlier attempt left behind before minting a
	// replacement. Without this, a run that failed having written only the
	// access ID and a second that fails having written only the secret
	// leave two halves of different keys in place — which hmacStored reads
	// as a usable credential, and the tenant becomes ready with object
	// storage it cannot reach.
	if err := s.forgetHMACSecrets(ctx, t); err != nil {
		return err
	}
	// Nothing usable is recorded, so any key the account already has came
	// from an attempt that died before it could store one. Clear them out
	// rather than accumulating orphans across retries: an account is capped
	// at five keys, which a retry loop would otherwise exhaust.
	if err := s.deleteHMACKeys(ctx, account); err != nil {
		return err
	}
	key, err := s.c.Buckets.CreateHMACKey(ctx, account)
	if err != nil {
		return fmt.Errorf("create the tenant's storage credentials: %w", err)
	}
	// The secret first, then the access ID, and a slice rather than a map
	// because the order is the point: hmacStored treats "both halves
	// present" as a usable credential, so the half it keys on has to be the
	// one written last. An interrupted run then leaves at worst an orphan
	// secret with no access ID beside it, which the next attempt replaces.
	for _, half := range []struct{ name, value string }{
		{secretSecretAccessKey, key.Secret},
		{secretAccessKeyID, key.AccessID},
	} {
		if err := putTenantSecret(ctx, s.c, t, half.name, half.value); err != nil {
			return err
		}
	}
	return nil
}

// hmacStored reports whether both halves of a usable credential are in
// Secret Manager. The access ID is checked first because it is the half
// ensureHMACKey writes last: if it is there, the secret beside it belongs
// to the same key.
func (s bucket) hmacStored(ctx context.Context, t *provisioner.Tenant) (bool, error) {
	for _, name := range []string{secretAccessKeyID, secretSecretAccessKey} {
		if _, err := readTenantSecret(ctx, s.c, t, name); err != nil {
			if errors.Is(err, secrets.ErrNotFound) {
				return false, nil
			}
			return false, fmt.Errorf("read %s: %w", name, err)
		}
	}
	return true, nil
}

// forgetHMACSecrets removes both halves of whatever credential is stored,
// so what is written next is a matched pair or nothing.
func (s bucket) forgetHMACSecrets(ctx context.Context, t *provisioner.Tenant) error {
	for _, name := range []string{secretAccessKeyID, secretSecretAccessKey} {
		if err := deleteTenantSecret(ctx, s.c, t, name); err != nil {
			return err
		}
		if err := t.DeleteSecretRef(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (s bucket) deleteHMACKeys(ctx context.Context, account string) error {
	ids, err := s.c.Buckets.ListHMACKeys(ctx, account)
	if err != nil {
		return fmt.Errorf("list the tenant's storage credentials: %w", err)
	}
	for _, id := range ids {
		if err := s.c.Buckets.DeleteHMACKey(ctx, id); err != nil {
			return fmt.Errorf("delete the tenant's storage credentials: %w", err)
		}
	}
	return nil
}

// Rollback deletes the HMAC credentials, their secrets and the bucket. The
// credentials go first and unconditionally: they outlive the bucket (they
// authenticate as the service account, not as the bucket) and are the half
// that is still a live credential if the delete stops partway.
func (s bucket) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		if t.Row.BucketName == nil {
			return provisioner.Skip("no bucket recorded")
		}
		return nil
	}
	if s.c.Buckets == nil {
		return errNoBucketAdmin
	}
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	// Credentials minted by a run that died before Record are still swept —
	// an HMAC key authenticates as the service account, so one left behind
	// is a live credential — but only from an account this tenant owns.
	// Sweeping an account that merely shares the derived name would delete
	// somebody else's storage credentials.
	account, ok, err := tenantAccount(ctx, s.c, t)
	if err != nil {
		return err
	}
	if ok {
		if err := s.deleteHMACKeys(ctx, account); err != nil {
			return err
		}
	}
	if err := s.forgetHMACSecrets(ctx, t); err != nil {
		return err
	}
	name := BucketName(t.Env.Project, t.Row.Slug)
	if t.Row.BucketName != nil {
		name = *t.Row.BucketName
	}
	// As on the way up: emptying and deleting a bucket that is not this
	// tenant's would destroy whatever is in it. Left alone rather than
	// reported as an error, so the rest of the teardown still runs. That
	// includes a name claimed by another project entirely — the bucket
	// namespace is global, so Get reports that collision as ErrNotOwned
	// too, and treating it as anything else would strand this tenant's
	// database, service account and secrets behind an error no retry
	// clears.
	existing, exists, err := s.c.Buckets.Get(ctx, name)
	if err != nil && !errors.Is(err, ErrNotOwned) {
		return fmt.Errorf("look up the tenant's bucket: %w", err)
	}
	if errors.Is(err, ErrNotOwned) || (exists && existing[TenantLabelKey] != t.Row.ID.String()) {
		return provisioner.Skip("the bucket named for this tenant belongs to something else; left alone")
	}
	if err := s.c.Buckets.Delete(ctx, name); err != nil {
		return fmt.Errorf("delete the tenant's bucket: %w", err)
	}
	if t.Row.BucketName == nil {
		return provisioner.Skip("no bucket recorded")
	}
	return nil
}
