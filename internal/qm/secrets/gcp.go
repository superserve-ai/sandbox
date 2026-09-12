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

func (g *GCP) Put(ctx context.Context, name string, value []byte) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	_, err := g.svc.Projects.Secrets.Create("projects/"+g.project, &secretmanager.Secret{
		Replication: &secretmanager.Replication{Automatic: &secretmanager.Automatic{}},
		Labels:      map[string]string{"managed-by": "qm-api"},
	}).SecretId(name).Context(ctx).Do()
	if err != nil && !isStatus(err, http.StatusConflict) {
		return "", fmt.Errorf("create secret %s: %w", name, err)
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

func (g *GCP) Delete(ctx context.Context, name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	_, err := g.svc.Projects.Secrets.Delete(g.secretPath(name)).Context(ctx).Do()
	if err != nil && !isStatus(err, http.StatusNotFound) {
		return fmt.Errorf("delete secret %s: %w", name, err)
	}
	return nil
}

func isStatus(err error, code int) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == code
}
