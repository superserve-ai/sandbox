package authz

import (
	"context"
	"testing"
)

func TestRequirePlatformAdminGoogleSession(t *testing.T) {
	ctx := context.Background()
	verified := true

	tests := []struct {
		name    string
		session SessionClaims
		wantErr bool
	}{
		{
			name: "google superserve verified",
			session: SessionClaims{
				Provider:      "google",
				Email:         "admin@superserve.ai",
				EmailVerified: &verified,
			},
		},
		{
			name: "provider trimmed and case-insensitive",
			session: SessionClaims{
				Provider:      "  Google ",
				Email:         " admin@superserve.ai ",
				EmailVerified: &verified,
			},
		},
		{
			name: "wrong provider",
			session: SessionClaims{
				Provider:      "email",
				Email:         "admin@superserve.ai",
				EmailVerified: &verified,
			},
			wantErr: true,
		},
		{
			name: "wrong domain",
			session: SessionClaims{
				Provider:      "google",
				Email:         "admin@superserve.ai.evil.com",
				EmailVerified: &verified,
			},
			wantErr: true,
		},
		{
			name: "unverified denied",
			session: SessionClaims{
				Provider:      "google",
				Email:         "admin@superserve.ai",
				EmailVerified: boolPtr(false),
			},
			wantErr: true,
		},
		{
			name: "missing email denied",
			session: SessionClaims{
				Provider:      "google",
				EmailVerified: &verified,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RequirePlatformAdminGoogleSession(ctx, tc.session)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }
