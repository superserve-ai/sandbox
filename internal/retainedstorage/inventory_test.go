package retainedstorage

import (
	"github.com/google/uuid"
	"math"
	"strings"
	"testing"
)

func TestInventoryValidity(t *testing.T) {
	valid := func() Inventory {
		return Inventory{Version: Version, Owners: []Owner{{Kind: "sandbox", ID: uuid.NewString(), Generation: strings.Repeat("a", 64), Extents: []Extent{{Device: "fs", Start: 4096, Length: 4096}}}}}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Inventory)
	}{
		{"future version", func(v *Inventory) { v.Version++ }},
		{"unknown inventory", func(v *Inventory) { v.Owners = nil }},
		{"unknown allocation", func(v *Inventory) { v.Owners[0].Extents = nil }},
		{"duplicate owner", func(v *Inventory) { v.Owners = append(v.Owners, v.Owners[0]) }},
		{"negative offset", func(v *Inventory) { v.Owners[0].Extents[0].Start = -1 }},
		{"overflow", func(v *Inventory) { v.Owners[0].Extents[0].Start = math.MaxInt64 }},
		{"unscoped range", func(v *Inventory) { v.Owners[0].Extents[0].Device = "" }},
		{"future owner", func(v *Inventory) { v.Owners[0].Kind = "team" }},
		{"bad generation", func(v *Inventory) { v.Owners[0].Generation = strings.Repeat("z", 64) }},
		{"extent bound", func(v *Inventory) { v.Owners[0].Extents = make([]Extent, MaxExtents+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := valid()
			tc.mutate(&v)
			if v.Validate() == nil {
				t.Fatal("accepted invalid inventory")
			}
		})
	}
	v := valid()
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	v.Owners[0].Extents = []Extent{}
	if err := v.Validate(); err != nil {
		t.Fatalf("explicit zero: %v", err)
	}
	v.Owners = []Owner{}
	if err := v.Validate(); err != nil {
		t.Fatalf("explicit empty: %v", err)
	}
}
