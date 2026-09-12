package secrets

import (
	"context"
	"sync"
)

// Fake is an in-memory Store for tests and local development.
type Fake struct {
	mu     sync.Mutex
	values map[string][]byte
	// Puts counts Put calls per name so tests can assert a secret was
	// written exactly once.
	Puts map[string]int
	// Err, when set, is returned by every operation.
	Err error
}

func NewFake() *Fake {
	return &Fake{values: map[string][]byte{}, Puts: map[string]int{}}
}

func (f *Fake) Put(_ context.Context, name string, value []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return "", f.Err
	}
	if err := ValidName(name); err != nil {
		return "", err
	}
	f.values[name] = append([]byte(nil), value...)
	f.Puts[name]++
	return "projects/fake/secrets/" + name + "/versions/latest", nil
}

func (f *Fake) Get(_ context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	v, ok := f.values[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (f *Fake) Delete(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	delete(f.values, name)
	return nil
}

// Has reports whether name currently holds a value.
func (f *Fake) Has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.values[name]
	return ok
}
