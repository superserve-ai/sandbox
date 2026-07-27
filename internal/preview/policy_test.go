package preview

import "testing"

func TestValidatePublishedPort(t *testing.T) {
	for _, port := range []int32{MinPublishedPort, 3000, MaxPublishedPort} {
		if err := ValidatePublishedPort(port); err != nil {
			t.Errorf("ValidatePublishedPort(%d): %v", port, err)
		}
	}
	for _, port := range []int32{MinPublishedPort - 1, ReservedBoxdPort, MaxPublishedPort + 1} {
		if err := ValidatePublishedPort(port); err == nil {
			t.Errorf("ValidatePublishedPort(%d) succeeded, want rejection", port)
		}
	}
}

func TestRestrictiveFallback(t *testing.T) {
	tests := []struct {
		name    string
		sandbox string
		ports   []string
		want    string
	}{
		{name: "strict all public", sandbox: AccessPublic, ports: []string{AccessPublic, AccessPublic}, want: AccessPublic},
		{name: "phase one empty mode inherits public", sandbox: AccessPublic, ports: []string{""}, want: AccessPublic},
		{name: "private default", sandbox: AccessPrivate, ports: []string{AccessPublic}, want: AccessPrivate},
		{name: "mixed private", sandbox: AccessPublic, ports: []string{AccessPublic, AccessPrivate}, want: AccessPrivate},
		{name: "unknown port", sandbox: AccessPublic, ports: []string{"future"}, want: AccessPrivate},
		{name: "legacy compatible public row", sandbox: AccessLegacyPublic, ports: []string{AccessPublic}, want: AccessLegacyPublic},
		{name: "legacy inconsistent private row", sandbox: AccessLegacyPublic, ports: []string{AccessPrivate}, want: AccessPrivate},
		{name: "empty legacy inconsistent unknown row", sandbox: "", ports: []string{"future"}, want: AccessPrivate},
		{name: "unknown sandbox stays unknown", sandbox: "future-sandbox", ports: []string{AccessPrivate}, want: "future-sandbox"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RestrictiveFallback(tt.sandbox, tt.ports...); got != tt.want {
				t.Fatalf("RestrictiveFallback(%q, %q) = %q, want %q", tt.sandbox, tt.ports, got, tt.want)
			}
		})
	}
}
