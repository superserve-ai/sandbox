package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// InputHash identifies both the guest specification and its resource shape.
// Resource shape is part of a Firecracker snapshot's identity.
func InputHash(raw []byte, vcpu, memoryMiB, diskMiB int32) (string, error) {
	var spec BuildSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return "", err
	}
	input := struct {
		Spec      BuildSpec `json:"spec"`
		VCPU      int32     `json:"vcpu"`
		MemoryMiB int32     `json:"memory_mib"`
		DiskMiB   int32     `json:"disk_mib"`
	}{spec, vcpu, memoryMiB, diskMiB}
	canonical, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
