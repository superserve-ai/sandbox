package api

import (
	"encoding/json"
	"testing"
)

// The PATCH contract hangs on the absent/null/value tri-state: absent leaves
// the setting untouched, null clears it, a number sets it. A plain pointer
// can't represent all three, so verify the wrapper does.
func TestOptionalInt32TriState(t *testing.T) {
	var req patchSandboxRequest
	if err := json.Unmarshal([]byte(`{"metadata":{}}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.AutoDeleteSeconds.Set {
		t.Error("absent field must not be Set")
	}

	req = patchSandboxRequest{}
	if err := json.Unmarshal([]byte(`{"auto_delete_seconds":null}`), &req); err != nil {
		t.Fatal(err)
	}
	if !req.AutoDeleteSeconds.Set || req.AutoDeleteSeconds.Value != nil {
		t.Errorf("null must be Set with nil Value, got %+v", req.AutoDeleteSeconds)
	}

	req = patchSandboxRequest{}
	if err := json.Unmarshal([]byte(`{"auto_delete_seconds":3600}`), &req); err != nil {
		t.Fatal(err)
	}
	if !req.AutoDeleteSeconds.Set || req.AutoDeleteSeconds.Value == nil || *req.AutoDeleteSeconds.Value != 3600 {
		t.Errorf("3600 must be Set with Value=3600, got %+v", req.AutoDeleteSeconds)
	}

	if err := json.Unmarshal([]byte(`{"auto_delete_seconds":"soon"}`), &req); err == nil {
		t.Error("non-numeric value must fail to bind")
	}
}

func TestValidateAutoDeleteSeconds(t *testing.T) {
	for _, v := range []int32{0, 1, 3600, maxAutoDeleteSeconds} {
		if err := validateAutoDeleteSeconds(&v); err != nil {
			t.Errorf("%d should be valid: %v", v, err)
		}
	}
	if err := validateAutoDeleteSeconds(nil); err != nil {
		t.Errorf("nil (disabled) should be valid: %v", err)
	}
	for _, v := range []int32{-1, maxAutoDeleteSeconds + 1} {
		if err := validateAutoDeleteSeconds(&v); err == nil {
			t.Errorf("%d should be rejected", v)
		}
	}
}

func TestValidateTimeoutSeconds(t *testing.T) {
	for _, v := range []int32{1, 3600, maxTimeoutSeconds} {
		if err := validateTimeoutSeconds(&v); err != nil {
			t.Errorf("%d should be valid: %v", v, err)
		}
	}
	if err := validateTimeoutSeconds(nil); err != nil {
		t.Errorf("nil (disabled) should be valid: %v", err)
	}
	for _, v := range []int32{0, -1, maxTimeoutSeconds + 1} {
		if err := validateTimeoutSeconds(&v); err == nil {
			t.Errorf("%d should be rejected", v)
		}
	}
}
