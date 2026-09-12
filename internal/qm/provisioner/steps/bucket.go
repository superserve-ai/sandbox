package steps

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// BucketAdmin manages the tenant's object storage (Cloud Storage JSON API
// or cloud.google.com/go/storage). Delete must empty the bucket first.
type BucketAdmin interface {
	Exists(ctx context.Context, name string) (bool, error)
	Create(ctx context.Context, name, location string) error
	Delete(ctx context.Context, name string) error
	// GrantAccess binds roles/storage.objectAdmin on the bucket to the
	// tenant's service account.
	GrantAccess(ctx context.Context, name, serviceAccountEmail string) error
}

// bucket creates the tenant's bucket. Output: Row.BucketName.
type bucket struct {
	c Clients
}

func (bucket) Name() string { return "bucket" }

func (s bucket) Run(ctx context.Context, t *provisioner.Tenant) error {
	name := BucketName(t.Env.Project, t.Row.Slug)
	if t.Env.Stub {
		if t.Row.BucketName != nil {
			return provisioner.Skip("bucket " + *t.Row.BucketName + " already recorded")
		}
		return t.Record(ctx, tenantstore.Resources{BucketName: &name})
	}
	return provisioner.NotImplemented(s.Name())
}

func (s bucket) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Row.BucketName == nil {
		return provisioner.Skip("no bucket recorded")
	}
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}
