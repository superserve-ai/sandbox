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

func (a *Accounts) Get(ctx context.Context, email string) (steps.ServiceAccount, bool, error) {
	account, err := a.iam.Projects.ServiceAccounts.Get(a.accountPath(email)).Context(ctx).Do()
	switch {
	case err == nil:
		return steps.ServiceAccount{Email: account.Email, Description: account.Description}, true, nil
	case notFound(err):
		return steps.ServiceAccount{}, false, nil
	default:
		return steps.ServiceAccount{}, false, fmt.Errorf("get service account %s: %w", email, err)
	}
}

// Create makes the account carrying description, which is the marker the
// caller checks before it will adopt an account that already exists.
func (a *Accounts) Create(ctx context.Context, accountID, displayName, description string) (string, error) {
	account, err := a.iam.Projects.ServiceAccounts.Create("projects/"+a.project, &iam.CreateServiceAccountRequest{
		AccountId:      accountID,
		ServiceAccount: &iam.ServiceAccount{DisplayName: displayName, Description: description},
	}).Context(ctx).Do()
	if err == nil {
		return account.Email, nil
	}
	if !alreadyExists(err) {
		return "", fmt.Errorf("create service account %s: %w", accountID, err)
	}
	// Raced with another attempt, or the caller's Get was stale. The
	// account now exists, so it goes through the same ownership check
	// rather than being adopted on the strength of its name.
	email := accountID + "@" + a.project + ".iam.gserviceaccount.com"
	existing, exists, err := a.Get(ctx, email)
	if err != nil {
		return "", fmt.Errorf("get the existing service account %s: %w", accountID, err)
	}
	if !exists {
		return "", fmt.Errorf("service account %s reported as existing but cannot be read", accountID)
	}
	if existing.Description != description {
		return "", fmt.Errorf("service account %s already exists and does not belong to this tenant", email)
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
	return a.editSecretPolicy(ctx, secretName, email, addMember, false)
}

// RevokeSecretAccess removes the binding again, and does nothing when it is
// not there.
func (a *Accounts) RevokeSecretAccess(ctx context.Context, secretName, email string) error {
	// A secret that is gone grants nobody anything, which is the outcome a
	// revoke was after. A grant cannot say the same: it would report
	// success having bound nothing, and the run would go on to deploy a
	// service mounting a secret that does not exist.
	return a.editSecretPolicy(ctx, secretName, email, removeMember, true)
}

// editSecretPolicy applies edit to the secret's policy under its etag. edit
// reports whether it changed anything; when it does not, nothing is sent.
func (a *Accounts) editSecretPolicy(ctx context.Context, secretName, email string, edit func(*secretmanager.Policy, string) bool, missingIsFine bool) error {
	resource := "projects/" + a.project + "/secrets/" + secretName
	member := "serviceAccount:" + email
	var lastErr error
	for attempt := 0; attempt < setIAMPolicyAttempts; attempt++ {
		policy, err := a.secrets.Projects.Secrets.GetIamPolicy(resource).
			OptionsRequestedPolicyVersion(iamPolicyVersion).Context(ctx).Do()
		if err != nil {
			if notFound(err) && missingIsFine {
				return nil
			}
			return fmt.Errorf("read the iam policy of %s: %w", secretName, err)
		}
		if !edit(policy, member) {
			return nil
		}
		// A policy read at version 3 has to be written back at version 3,
		// or IAM treats the conditional bindings it carries as unknown.
		policy.Version = iamPolicyVersion
		_, err = a.secrets.Projects.Secrets.SetIamPolicy(resource, &secretmanager.SetIamPolicyRequest{Policy: policy}).Context(ctx).Do()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isStatus(err, http.StatusConflict) && !isStatus(err, http.StatusPreconditionFailed) {
			break
		}
	}
	return fmt.Errorf("update the iam policy of %s for %s: %w", secretName, email, lastErr)
}

// addMember puts member in the unconditional accessor binding. Only
// unconditional bindings count: a conditional one might not apply at the
// moment the tenant reads the secret.
func addMember(policy *secretmanager.Policy, member string) bool {
	for _, binding := range policy.Bindings {
		if !isAccessorBinding(binding) {
			continue
		}
		if slices.Contains(binding.Members, member) {
			return false
		}
		binding.Members = append(binding.Members, member)
		return true
	}
	policy.Bindings = append(policy.Bindings, &secretmanager.Binding{
		Role:    secretAccessorRole,
		Members: []string{member},
	})
	return true
}

// removeMember takes member out of every accessor binding, and drops a
// binding left with no principals — IAM rejects one.
func removeMember(policy *secretmanager.Policy, member string) bool {
	changed := false
	kept := make([]*secretmanager.Binding, 0, len(policy.Bindings))
	for _, binding := range policy.Bindings {
		if !isAccessorBinding(binding) || !slices.Contains(binding.Members, member) {
			kept = append(kept, binding)
			continue
		}
		changed = true
		members := make([]string, 0, len(binding.Members))
		for _, have := range binding.Members {
			if have != member {
				members = append(members, have)
			}
		}
		if len(members) == 0 {
			continue
		}
		binding.Members = members
		kept = append(kept, binding)
	}
	if changed {
		policy.Bindings = kept
	}
	return changed
}

func isAccessorBinding(b *secretmanager.Binding) bool {
	return b.Role == secretAccessorRole && b.Condition == nil
}
