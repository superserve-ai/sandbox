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

// adopt stamps the owner label on a secret that predates it.
func (g *GCP) adopt(ctx context.Context, name string, secret *secretmanager.Secret, owner string) error {
	labels := map[string]string{}
	for k, v := range secret.Labels {
		labels[k] = v
	}
	labels[OwnerLabel] = owner
	_, err := g.svc.Projects.Secrets.Patch(g.secretPath(name), &secretmanager.Secret{Labels: labels}).
		UpdateMask("labels").Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("claim secret %s: %w", name, err)
	}
	return nil
}

func isStatus(err error, code int) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == code
}
