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
