package secrets

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Fake is an in-memory Store for tests and local development.
type Fake struct {
	mu     sync.Mutex
	values map[string][]byte
	owners map[string]string
	// Puts counts Put calls per name so tests can assert a secret was
	// written exactly once.
	Puts map[string]int
	// Err, when set, is returned by every operation.
	Err error
	// BeforePut, when set, runs before a value is written; tests use it to
	// land a concurrent change while a write is in flight.
	BeforePut func()
}

func NewFake() *Fake {
	return &Fake{values: map[string][]byte{}, owners: map[string]string{}, Puts: map[string]int{}}
}

func (f *Fake) Put(_ context.Context, name string, value []byte, owner string) (string, error) {
	if f.BeforePut != nil {
		f.BeforePut()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return "", f.Err
	}
	if err := ValidName(name); err != nil {
		return "", err
	}
	if err := f.checkOwner(name, owner); err != nil {
		return "", err
	}
	f.owners[name] = owner
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

func (f *Fake) Delete(_ context.Context, name, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	if err := f.checkOwner(name, owner); err != nil {
		return err
	}
	delete(f.values, name)
	delete(f.owners, name)
	return nil
}

// checkOwner mirrors the GCP store: a secret that exists under another
// owner, or under none, is not the caller's to write or remove.
func (f *Fake) checkOwner(name, owner string) error {
	if _, exists := f.values[name]; !exists {
		return nil
	}
	if f.owners[name] == owner && owner != "" {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrNotOwned, name)
}

// SetOwner plants a secret under another owner, for tests.
func (f *Fake) SetOwner(name, owner string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[name] = []byte("someone else's")
	f.owners[name] = owner
}

// Names lists the secrets that currently hold a value, sorted.
func (f *Fake) Names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.values))
	for name := range f.values {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Has reports whether name currently holds a value.
func (f *Fake) Has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.values[name]
	return ok
}
