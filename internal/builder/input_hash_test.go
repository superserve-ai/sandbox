package builder

import "testing"

func TestInputHashCanonicalSpecAndResources(t *testing.T) {
	a := []byte(`{"from":"example/image:latest","steps":[{"env":{"key":"X","value":"Y"}}]}`)
	b := []byte(`{"steps":[{"env":{"value":"Y","key":"X"}}],"from":"example/image:latest"}`)
	want, err := InputHash(a, 1, 1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InputHash(b, 1, 1024, 4096)
	if err != nil || got != want {
		t.Fatalf("equivalent input: %q, %v; want %q", got, err, want)
	}
	for _, shape := range [][3]int32{{2, 1024, 4096}, {1, 2048, 4096}, {1, 1024, 8192}} {
		got, err := InputHash(a, shape[0], shape[1], shape[2])
		if err != nil || got == want {
			t.Fatalf("changed shape %v: %q, %v", shape, got, err)
		}
	}
	got, err = InputHash([]byte(`{"from":"example/image:other"}`), 1, 1024, 4096)
	if err != nil || got == want {
		t.Fatalf("changed spec: %q, %v", got, err)
	}
}

func TestInputHashRejectsMalformedSpec(t *testing.T) {
	if _, err := InputHash([]byte(`{"from":`), 1, 1024, 4096); err == nil {
		t.Fatal("malformed spec accepted")
	}
}
