package main

import "testing"

func TestNeighTableShortfall(t *testing.T) {
	cases := []struct{ cap, netns, pool, want int }{
		{32768, 4587, 1024, 0},
		{1024, 4587, 1024, 10198},
		{1024, 100, 256, 3072},
		{8192, 100, 256, 0},
		{8192, 4000, 256, 320},
		{4096, 0, 5000, 5904},
		{8192, 0, 0, 0},
	}
	for _, c := range cases {
		if got := neighTableShortfall(c.cap, c.netns, c.pool); got != c.want {
			t.Errorf("cap %d netns %d pool %d: got %d, want %d", c.cap, c.netns, c.pool, got, c.want)
		}
	}
}
