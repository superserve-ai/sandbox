package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"golang.org/x/sync/errgroup"
	"google.golang.org/api/option"
	storage "google.golang.org/api/storage/v1"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
)

// objectAdminRole lets the tenant read, write and delete objects in its own
// bucket, and nothing at the bucket level.
const objectAdminRole = "roles/storage.objectAdmin"

// hmacInactive is the state a key must be in before it can be deleted.
const hmacInactive = "INACTIVE"

// Emptying a tenant's bucket on teardown. The page size bounds one listing
// pass, the worker count bounds the deletes in flight, and the object
// budget bounds the whole call: a bucket too large to clear inside one job
// stops with an error rather than running the job out of time somewhere
// less obvious, and the teardown — which is idempotent and retried —
// carries on from what is left.
const (
	emptyBucketPage       = 1000
	emptyBucketWorkers    = 16
	emptyBucketMaxObjects = 200_000
)

// Buckets is the Cloud Storage-backed steps.BucketAdmin.
type Buckets struct {
	svc     *storage.Service
	project string
}

var _ steps.BucketAdmin = (*Buckets)(nil)

func NewBuckets(ctx context.Context, project string, opts ...option.ClientOption) (*Buckets, error) {
	if project == "" {
		return nil, errors.New("storage: project is required")
	}
	svc, err := storage.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	return &Buckets{svc: svc, project: project}, nil
}

func (b *Buckets) Exists(ctx context.Context, name string) (bool, error) {
	_, err := b.svc.Buckets.Get(name).Context(ctx).Do()
	switch {
	case err == nil:
		return true, nil
	case notFound(err):
		return false, nil
	case isStatus(err, http.StatusForbidden):
		// A name taken by another project: the bucket namespace is global,
		// so this is a naming collision, not a permissions bug, and it is
		// not something a retry will resolve.
		return false, fmt.Errorf("bucket %s exists in another project", name)
	default:
		return false, fmt.Errorf("get bucket %s: %w", name, err)
	}
}

// Create makes the bucket with uniform bucket-level access — the only way
// the IAM binding GrantAccess adds is authoritative, since object ACLs
// would otherwise be a second, invisible grant path.
func (b *Buckets) Create(ctx context.Context, name, location, lifecycleJSON string) error {
	spec := &storage.Bucket{
		Name:     name,
		Location: location,
		IamConfiguration: &storage.BucketIamConfiguration{
			UniformBucketLevelAccess: &storage.BucketIamConfigurationUniformBucketLevelAccess{Enabled: true},
		},
		Labels: map[string]string{"managed-by": "qm-api"},
	}
	if lifecycleJSON != "" {
		var lifecycle storage.BucketLifecycle
		if err := json.Unmarshal([]byte(lifecycleJSON), &lifecycle); err != nil {
			return fmt.Errorf("parse the tenant bucket lifecycle policy: %w", err)
		}
		spec.Lifecycle = &lifecycle
	}
	_, err := b.svc.Buckets.Insert(b.project, spec).Context(ctx).Do()
	if err != nil && !alreadyExists(err) {
		return fmt.Errorf("create bucket %s: %w", name, err)
	}
	return nil
}

// Delete empties the bucket first: Cloud Storage refuses to delete a bucket
// that still holds objects, and a teardown that did not would fail forever
// on any tenant that had used its storage.
func (b *Buckets) Delete(ctx context.Context, name string) error {
	if err := b.empty(ctx, name); err != nil {
		return err
	}
	err := b.svc.Buckets.Delete(name).Context(ctx).Do()
	if err != nil && !notFound(err) {
		return fmt.Errorf("delete bucket %s: %w", name, err)
	}
	return nil
}

// empty deletes every object and every noncurrent version. Versions matter:
// a bucket with versioning on still counts soft-deleted objects against the
// delete.
func (b *Buckets) empty(ctx context.Context, name string) error {
	// Re-listing from the start each pass rather than paging: every object
	// seen is deleted before the next list, so the next page is whatever is
	// left. A delete that cannot proceed returns an error and ends the
	// loop, so this cannot spin.
	deleted := 0
	for deleted < emptyBucketMaxObjects {
		resp, err := b.svc.Objects.List(name).Versions(true).MaxResults(emptyBucketPage).Context(ctx).Do()
		if err != nil {
			if notFound(err) {
				return nil
			}
			return fmt.Errorf("list the objects in bucket %s: %w", name, err)
		}
		if len(resp.Items) == 0 {
			return nil
		}
		if err := b.deleteObjects(ctx, name, resp.Items); err != nil {
			return err
		}
		deleted += len(resp.Items)
	}
	return fmt.Errorf("bucket %s still holds objects after deleting %d: retry the teardown to continue", name, deleted)
}

// deleteObjects removes one listing page with a bounded number of requests
// in flight, and returns the first failure.
func (b *Buckets) deleteObjects(ctx context.Context, bucket string, objects []*storage.Object) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var group errgroup.Group
	group.SetLimit(emptyBucketWorkers)
	for _, obj := range objects {
		group.Go(func() error {
			del := b.svc.Objects.Delete(bucket, obj.Name).Context(ctx)
			if obj.Generation != 0 {
				del = del.Generation(obj.Generation)
			}
			if err := del.Do(); err != nil && !notFound(err) {
				return fmt.Errorf("delete %s from bucket %s: %w", obj.Name, bucket, err)
			}
			return nil
		})
	}
	return group.Wait()
}

// GrantAccess adds the tenant's identity to the bucket's object-admin
// binding, leaving anything else on the policy alone.
func (b *Buckets) GrantAccess(ctx context.Context, name, email string) error {
	member := "serviceAccount:" + email
	var lastErr error
	for attempt := 0; attempt < setIAMPolicyAttempts; attempt++ {
		policy, err := b.svc.Buckets.GetIamPolicy(name).
			OptionsRequestedPolicyVersion(iamPolicyVersion).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("read the iam policy of bucket %s: %w", name, err)
		}
		for _, binding := range policy.Bindings {
			if binding.Role == objectAdminRole && binding.Condition == nil && slices.Contains(binding.Members, member) {
				return nil
			}
		}
		policy.Bindings = append(policy.Bindings, &storage.PolicyBindings{Role: objectAdminRole, Members: []string{member}})
		policy.Version = iamPolicyVersion
		_, err = b.svc.Buckets.SetIamPolicy(name, policy).Context(ctx).Do()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isStatus(err, http.StatusConflict) && !isStatus(err, http.StatusPreconditionFailed) {
			break
		}
	}
	return fmt.Errorf("grant %s access to bucket %s: %w", email, name, lastErr)
}

// CreateHMACKey mints the interoperability credential the tenant's S3
// client authenticates with. The secret comes back exactly once, here.
func (b *Buckets) CreateHMACKey(ctx context.Context, email string) (steps.HMACKey, error) {
	key, err := b.svc.Projects.HmacKeys.Create(b.project, email).Context(ctx).Do()
	if err != nil {
		return steps.HMACKey{}, fmt.Errorf("create an hmac key for %s: %w", email, err)
	}
	if key.Metadata == nil || key.Metadata.AccessId == "" || key.Secret == "" {
		return steps.HMACKey{}, fmt.Errorf("create an hmac key for %s: the response carried no credential", email)
	}
	return steps.HMACKey{AccessID: key.Metadata.AccessId, Secret: key.Secret}, nil
}

func (b *Buckets) ListHMACKeys(ctx context.Context, email string) ([]string, error) {
	var out []string
	call := b.svc.Projects.HmacKeys.List(b.project).ServiceAccountEmail(email).ShowDeletedKeys(false)
	err := call.Pages(ctx, func(page *storage.HmacKeysMetadata) error {
		for _, key := range page.Items {
			if key.AccessId != "" {
				out = append(out, key.AccessId)
			}
		}
		return nil
	})
	if err != nil {
		if notFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list the hmac keys of %s: %w", email, err)
	}
	return out, nil
}

// DeleteHMACKey deactivates the key and then deletes it: Cloud Storage
// refuses to delete an active one.
func (b *Buckets) DeleteHMACKey(ctx context.Context, accessID string) error {
	_, err := b.svc.Projects.HmacKeys.Update(b.project, accessID, &storage.HmacKeyMetadata{State: hmacInactive}).Context(ctx).Do()
	if err != nil && !notFound(err) && !isStatus(err, http.StatusBadRequest) {
		// A key that is already inactive answers 400; anything else is a
		// real failure, and leaving a live credential behind is not an
		// option.
		return fmt.Errorf("deactivate hmac key %s: %w", accessID, err)
	}
	if err := b.svc.Projects.HmacKeys.Delete(b.project, accessID).Context(ctx).Do(); err != nil && !notFound(err) {
		return fmt.Errorf("delete hmac key %s: %w", accessID, err)
	}
	return nil
}
