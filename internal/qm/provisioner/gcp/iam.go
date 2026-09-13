package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	secretmanager "google.golang.org/api/secretmanager/v1"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
)

// secretAccessorRole is the only role a tenant's identity is ever granted on
// a secret: read the current value, nothing else.
const secretAccessorRole = "roles/secretmanager.secretAccessor"

// setIAMPolicyAttempts bounds the read-modify-write retry on a secret's IAM
// policy. Two tenants provisioning at once never touch the same secret, but
// a retried run and a concurrent platform change can, and the etag check is
// what turns that into a conflict rather than a lost binding.
const setIAMPolicyAttempts = 3

// Accounts is the IAM-backed steps.ServiceAccountAdmin.
type Accounts struct {
	iam     *iam.Service
	secrets *secretmanager.Service
	project string
}

var _ steps.ServiceAccountAdmin = (*Accounts)(nil)

func NewAccounts(ctx context.Context, project string, opts ...option.ClientOption) (*Accounts, error) {
	if project == "" {
		return nil, errors.New("iam: project is required")
	}
	svc, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("iam client: %w", err)
	}
	sm, err := secretmanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("secret manager client: %w", err)
	}
	return &Accounts{iam: svc, secrets: sm, project: project}, nil
}

func (a *Accounts) accountPath(email string) string {
	return "projects/" + a.project + "/serviceAccounts/" + email
}

func (a *Accounts) Exists(ctx context.Context, email string) (bool, error) {
	_, err := a.iam.Projects.ServiceAccounts.Get(a.accountPath(email)).Context(ctx).Do()
	switch {
	case err == nil:
		return true, nil
	case notFound(err):
		return false, nil
	default:
		return false, fmt.Errorf("get service account %s: %w", email, err)
	}
}

func (a *Accounts) Create(ctx context.Context, accountID, displayName string) (string, error) {
	account, err := a.iam.Projects.ServiceAccounts.Create("projects/"+a.project, &iam.CreateServiceAccountRequest{
		AccountId:      accountID,
		ServiceAccount: &iam.ServiceAccount{DisplayName: displayName},
	}).Context(ctx).Do()
	if err == nil {
		return account.Email, nil
	}
	if !alreadyExists(err) {
		return "", fmt.Errorf("create service account %s: %w", accountID, err)
	}
	// Raced with another attempt, or adopting one a previous run left
	// behind. Either way the account the caller asked for now exists, and
	// its email is derived from the id it was created with.
	email := accountID + "@" + a.project + ".iam.gserviceaccount.com"
	existing, err := a.iam.Projects.ServiceAccounts.Get(a.accountPath(email)).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("get the existing service account %s: %w", accountID, err)
	}
	return existing.Email, nil
}

func (a *Accounts) Delete(ctx context.Context, email string) error {
	_, err := a.iam.Projects.ServiceAccounts.Delete(a.accountPath(email)).Context(ctx).Do()
	if err != nil && !notFound(err) {
		return fmt.Errorf("delete service account %s: %w", email, err)
	}
	return nil
}

// GrantSecretAccess adds the accessor binding for the account to one
// secret's policy, and does nothing when it is already there. The
// read-modify-write carries the etag, so a concurrent change to the same
// policy is retried rather than silently overwritten.
func (a *Accounts) GrantSecretAccess(ctx context.Context, secretName, email string) error {
	resource := "projects/" + a.project + "/secrets/" + secretName
	member := "serviceAccount:" + email
	var lastErr error
	for attempt := 0; attempt < setIAMPolicyAttempts; attempt++ {
		policy, err := a.secrets.Projects.Secrets.GetIamPolicy(resource).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("read the iam policy of %s: %w", secretName, err)
		}
		for _, binding := range policy.Bindings {
			// Only unconditional bindings count: a conditional one might
			// not apply at the moment the tenant reads the secret.
			if binding.Role == secretAccessorRole && binding.Condition == nil && slices.Contains(binding.Members, member) {
				return nil
			}
		}
		policy.Bindings = append(policy.Bindings, &secretmanager.Binding{
			Role:    secretAccessorRole,
			Members: []string{member},
		})
		_, err = a.secrets.Projects.Secrets.SetIamPolicy(resource, &secretmanager.SetIamPolicyRequest{Policy: policy}).Context(ctx).Do()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isStatus(err, http.StatusConflict) && !isStatus(err, http.StatusPreconditionFailed) {
			break
		}
	}
	return fmt.Errorf("grant %s access to %s: %w", email, secretName, lastErr)
}
