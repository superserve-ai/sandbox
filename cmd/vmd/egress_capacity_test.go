package main

import (
	"github.com/superserve-ai/sandbox/internal/network"
	"testing"
)

func TestEgressCapacityConfig(t *testing.T) {
	for _, tc := range []struct {
		max, enforce string
		valid        bool
	}{{"", "", true}, {"8", "true", true}, {"8", "false", true}, {"0", "true", false}, {"-1", "false", false}, {"oops", "", false}, {"8", "1", false}, {"8", "True", false}} {
		t.Run(tc.max+"/"+tc.enforce, func(t *testing.T) {
			c, err := egressCapacityConfig(func(k string) string {
				if k == "VMD_EGRESS_ENFORCE" {
					return tc.enforce
				}
				return tc.max
			})
			if (err == nil) != tc.valid {
				t.Fatalf("config=%+v err=%v", c, err)
			}
			if tc.valid && (c.MaxConnections <= 0 || c.Enforce != (tc.enforce == "true")) {
				t.Fatalf("config=%+v", c)
			}
		})
	}
}

func TestEgressFDHeadroom(t *testing.T) {
	c := network.EgressCapacity{MaxConnections: 4096, Enforce: true}
	if err := validateEgressFDHeadroom(c, 65536); err != nil {
		t.Fatal(err)
	}
	if err := validateEgressFDHeadroom(c, 4096); err == nil {
		t.Fatal("no descriptor reserve")
	}
	c.MaxConnections = 65536
	if err := validateEgressFDHeadroom(c, 65536); err == nil {
		t.Fatal("accepted unsafe budget")
	}
}
