package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	secretmanager "google.golang.org/api/secretmanager/v1"
)

// GCP is the Secret Manager-backed Store. Secrets are created with
// automatic replication; access is granted per tenant service account by
// the provisioner, not here.
type GCP struct {
	svc     *secretmanager.Service
	project string
}

func NewGCP(ctx context.Context, project string, opts ...option.ClientOption) (*GCP, error) {
	if project == "" {
		return nil, errors.New("secret manager: project is required")
	}
	svc, err := secretmanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("secret manager client: %w", err)
	}
	return &GCP{svc: svc, project: project}, nil
}

func (g *GCP) secretPath(name string) string {
	return "projects/" + g.project + "/secrets/" + name
}

func (g *GCP) Put(ctx context.Context, name string, value []byte, owner string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	_, err := g.svc.Projects.Secrets.Create("projects/"+g.project, &secretmanager.Secret{
		Replication: &secretmanager.Replication{Automatic: &secretmanager.Automatic{}},
		Labels:      map[string]string{"managed-by": "qm-api", OwnerLabel: owner},
	}).SecretId(name).Context(ctx).Do()
	if err != nil {
		if !isStatus(err, http.StatusConflict) {
			return "", fmt.Errorf("create secret %s: %w", name, err)
		}
		// It was already there. Whose it is decides whether a version may
		// be added to it — the name alone is derived from a chosen slug.
		if err := g.checkOwner(ctx, name, owner); err != nil {
			return "", err
		}
	}
	_, err = g.svc.Projects.Secrets.AddVersion(g.secretPath(name), &secretmanager.AddSecretVersionRequest{
		Payload: &secretmanager.SecretPayload{Data: base64.StdEncoding.EncodeToString(value)},
	}).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("add secret version %s: %w", name, err)
	}
	return g.secretPath(name) + "/versions/latest", nil
}

func (g *GCP) Get(ctx context.Context, name string) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	resp, err := g.svc.Projects.Secrets.Versions.Access(g.secretPath(name) + "/versions/latest").Context(ctx).Do()
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("access secret %s: %w", name, err)
	}
	if resp.Payload == nil {
		return nil, ErrNotFound
	}
	data, err := base64.StdEncoding.DecodeString(resp.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("decode secret %s: %w", name, err)
	}
	return data, nil
}

func (g *GCP) Delete(ctx context.Context, name, owner string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := g.checkOwner(ctx, name, owner); err != nil {
		return err
	}
	_, err := g.svc.Projects.Secrets.Delete(g.secretPath(name)).Context(ctx).Do()
	if err != nil && !isStatus(err, http.StatusNotFound) {
		return fmt.Errorf("delete secret %s: %w", name, err)
	}
	return nil
}

func (g *GCP) Owner(ctx context.Context, name string) (string, bool, error) {
	if err := ValidName(name); err != nil {
		return "", false, err
	}
	secret, err := g.svc.Projects.Secrets.Get(g.secretPath(name)).Context(ctx).Do()
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get secret %s: %w", name, err)
	}
	return secret.Labels[OwnerLabel], true, nil
}

// checkOwner refuses a secret that exists and carries another tenant's
// owner. One that does not exist passes — the caller is about to create it,
// or is deleting something already gone.
//
// A secret with no owner label is adopted and stamped rather than refused.
// That is narrower than it looks and it is deliberate: qm-api and the
// provisioner job deploy separately (job first), so a tenant created by the
// previous API revision during that window has an unlabelled model key, and
// refusing it would consume the slug and then fail the run partway through.
// A tenant secret's name is qm-<slug>-<NAME> with NAME an upper-case
// env-var, which is a shape nothing else in the project writes — unlike the
// database and role names, where an unmarked object really could be
// somebody else's and is refused.
//
// A secret this store writes is claimed on the way through, so the
// tolerance stops applying to it. One the provisioner only ever reads —
// the model key, written by qm-api — keeps no label until qm-api next
// writes it, and stays adoptable meanwhile.
func (g *GCP) checkOwner(ctx context.Context, name, owner string) error {
	secret, err := g.svc.Projects.Secrets.Get(g.secretPath(name)).Context(ctx).Do()
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("get secret %s: %w", name, err)
	}
	have := secret.Labels[OwnerLabel]
	if have == "" {
		// Written before this label existed. Claim it, so the next caller
		// sees a labelled secret and the tolerance above stops mattering.
		return g.adopt(ctx, name, secret, owner)
	}
	if have == owner && owner != "" {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrNotOwned, name)
}

// Claim stamps owner on a secret that exists with no owner label. The
// caller is expected to have checked Owner first and only reach here on the
// unlabelled case, but this Get is its own read, not a reuse of that
// caller's — another claim can have landed in between, so a label found
// here is checked against owner rather than treated as this call's own
// doing just because it is not empty.
func (g *GCP) Claim(ctx context.Context, name, owner string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	secret, err := g.svc.Projects.Secrets.Get(g.secretPath(name)).Context(ctx).Do()
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("get secret %s: %w", name, err)
	}
	if have := secret.Labels[OwnerLabel]; have != "" {
		if have != owner {
			return fmt.Errorf("%w: %s", ErrNotOwned, name)
		}
		return nil
	}
	return g.adopt(ctx, name, secret, owner)
}

// adopt stamps the owner label on a secret that predates it. The patch
// carries the etag this call's own Get just read as a precondition, so it
// is not the only writer that could land between that Get and the Patch
// here: another caller claiming the same unlabelled secret for a different
// owner moves the etag first, and this one is refused rather than
// overwriting it. Without that precondition, a read-back after a blind
// patch cannot close the race either — two concurrent claimants can each
// read back their own write before the other's lands, and both would
// report success though only one ends up the label actually stored.
func (g *GCP) adopt(ctx context.Context, name string, secret *secretmanager.Secret, owner string) error {
	labels := map[string]string{}
	for k, v := range secret.Labels {
		labels[k] = v
	}
	labels[OwnerLabel] = owner
	_, err := g.svc.Projects.Secrets.Patch(g.secretPath(name), &secretmanager.Secret{
		Labels: labels,
		Etag:   secret.Etag,
	}).UpdateMask("labels").Context(ctx).Do()
	if err != nil && !isStatus(err, http.StatusConflict) && !isStatus(err, http.StatusPreconditionFailed) {
		return fmt.Errorf("claim secret %s: %w", name, err)
	}
	// A conflict on the etag proves only that something changed the secret
	// between our Get and this Patch — not that whatever changed it was a
	// different owner: a concurrent claim for this same owner, or some
	// other metadata write entirely, moves the etag too. Reading back and
	// judging the label actually stored is what decides foreign or not,
	// for a clean patch as much as a conflicted one — this API surface may
	// not enforce the etag as a precondition here at all, in which case an
	// apparently clean patch could just as easily have overwritten a
	// concurrent claim.
	claimed, exists, err := g.Owner(ctx, name)
	if err != nil {
		return fmt.Errorf("confirm the claim on secret %s: %w", name, err)
	}
	if exists && claimed != owner {
		return fmt.Errorf("%w: %s", ErrNotOwned, name)
	}
	return nil
}

func isStatus(err error, code int) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == code
}
