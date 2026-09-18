package main

import "testing"

func TestNeighTableShortfall(t *testing.T) {
	cases := []struct{ cap, netns, want int }{
		{32768, 4587, 0},
		{1024, 4587, 3563},
		{1024, 100, 3072},
		{8192, 100, 0},
		{4096, 4096, 0},
	}
	for _, c := range cases {
		if got := neighTableShortfall(c.cap, c.netns); got != c.want {
			t.Errorf("cap %d netns %d: got %d, want %d", c.cap, c.netns, got, c.want)
		}
	}
}
