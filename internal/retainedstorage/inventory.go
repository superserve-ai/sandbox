// Package retainedstorage defines the versioned physical allocation inventory
// shared by the host sampler and the durable storage report receiver.
package retainedstorage

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/google/uuid"
)

const (
	Version         = 1
	MaxOwners       = 4096
	MaxExtents      = 32768
	MaxPayloadBytes = 8 << 20
	// Manifest metadata is input to the bounded inventory scan.  Keep its
	// cumulative budget below the report payload budget so a fleet-sized set of
	// individually valid manifests cannot force gigabytes of reads.
	MaxManifestBytes = 8 << 20
)

// Extent identifies physical bytes within one host filesystem. Metadata that
// cannot be shared uses a filesystem/inode-specific device namespace.
type Extent struct {
	Device string `json:"device"`
	Start  int64  `json:"start"`
	Length int64  `json:"length"`
}

type Owner struct {
	Kind       string   `json:"kind"`
	ID         string   `json:"id"`
	Generation string   `json:"generation"`
	Extents    []Extent `json:"extents"`
}

// Inventory is a complete observation, never a sparse list of successful stats.
// Omission cannot retire an owner; the receiver checks control-plane lifetimes.
type Inventory struct {
	Version int     `json:"version"`
	Owners  []Owner `json:"owners"`
}

func (v Inventory) Validate() error {
	if v.Version != Version || v.Owners == nil || len(v.Owners) > MaxOwners {
		return fmt.Errorf("invalid retained inventory version or owner count")
	}
	seen := make(map[string]bool, len(v.Owners))
	count := 0
	for _, o := range v.Owners {
		id, err := uuid.Parse(o.ID)
		if err != nil || id == uuid.Nil || id.String() != o.ID || (o.Kind != "sandbox" && o.Kind != "snapshot") || len(o.Generation) != 64 || o.Extents == nil {
			return fmt.Errorf("invalid retained owner")
		}
		if _, err := hex.DecodeString(o.Generation); err != nil {
			return fmt.Errorf("invalid retained generation")
		}
		key := o.Kind + o.ID
		if seen[key] {
			return fmt.Errorf("duplicate retained owner")
		}
		seen[key] = true
		count += len(o.Extents)
		if count > MaxExtents {
			return fmt.Errorf("retained extent budget exceeded")
		}
		for _, e := range o.Extents {
			if e.Device == "" || len(e.Device) > 128 || e.Start < 0 || e.Length <= 0 || e.Start > math.MaxInt64-e.Length {
				return fmt.Errorf("invalid retained extent")
			}
		}
	}
	payload, err := json.Marshal(v)
	if err != nil || len(payload) > MaxPayloadBytes {
		return fmt.Errorf("retained payload budget exceeded")
	}
	return nil
}
