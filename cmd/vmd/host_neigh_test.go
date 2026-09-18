package main

import "testing"

func TestNeighTableShortfall(t *testing.T) {
	if got := neighTableShortfall(32768, 4587); got != 0 {
		t.Fatalf("cap above slots: got %d, want 0", got)
	}
	if got := neighTableShortfall(1024, 4587); got != 3563 {
		t.Fatalf("kernel default cap: got %d, want 3563", got)
	}
	if got := neighTableShortfall(1024, 1024); got != 0 {
		t.Fatalf("cap equal to slots: got %d, want 0", got)
	}
}
