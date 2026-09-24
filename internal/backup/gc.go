package backup

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// BlobDeleter removes one object. A missing object is not an error, so a
// purge can be retried from any point.
type BlobDeleter interface {
	Delete(ctx context.Context, object string) error
}

// BlobAdmin is what garbage collection needs from a bucket.
type BlobAdmin interface {
	BlobReader
	BlobLister
	BlobDeleter
	Identity() string
}

// GCSAdmin reads, lists and deletes as the bucket's dedicated GC identity,
// which nothing else runs as: the runtime impersonates it for this client
// only, so no other code path in the process can delete.
type GCSAdmin struct {
	*GCSReader
	bucket *storage.BucketHandle
	name   string
}

func NewGCSAdmin(ctx context.Context, bucket, serviceAccount string) (*GCSAdmin, error) {
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: serviceAccount,
		Scopes:          []string{storage.ScopeReadWrite},
	})
	if err != nil {
		return nil, fmt.Errorf("impersonate %s: %w", serviceAccount, err)
	}
	client, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	return &GCSAdmin{GCSReader: NewGCSReader(client, bucket), bucket: client.Bucket(bucket), name: bucket}, nil
}

func (g *GCSAdmin) Identity() string { return g.name }

func (g *GCSAdmin) Delete(ctx context.Context, object string) error {
	err := g.bucket.Object(object).Delete(ctx)
	if err != nil && !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("delete %s: %w", object, err)
	}
	return nil
}

// purgeRounds bounds how often a purge re-lists its prefix: an upload
// retry can land an object after a listing, and the generation is only
// finished once a listing comes back empty.
const purgeRounds = 3

// PurgeGeneration removes a sandbox generation from the bucket: the
// manifest first, so no restore can select the generation while its
// artifacts go, then everything else under the prefix, until a listing
// finds nothing. Shared bases live outside the prefix and are never
// touched here. Returns how many objects were deleted.
func PurgeGeneration(ctx context.Context, store BlobAdmin, sandboxID, generation string) (int, error) {
	manifest, err := SandboxObject(sandboxID, generation, ManifestObject)
	if err != nil {
		return 0, err
	}
	prefix := strings.TrimSuffix(manifest, ManifestObject)
	deleted := 0
	for range purgeRounds {
		objects, err := store.List(ctx, prefix)
		if err != nil {
			return deleted, err
		}
		if len(objects) == 0 {
			return deleted, nil
		}
		names := make([]string, 0, len(objects))
		for _, obj := range objects {
			if obj.Name == manifest {
				names = append([]string{manifest}, names...)
			} else {
				names = append(names, obj.Name)
			}
		}
		for _, name := range names {
			if err := store.Delete(ctx, name); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, fmt.Errorf("%s: objects keep appearing under the generation", prefix)
}

// ManifestBaseDigests returns the shared base digests a complete
// generation's manifest names. An incomplete generation (no manifest)
// names none.
func ManifestBaseDigests(ctx context.Context, r BlobReader, sandboxID, generation string) ([]string, error) {
	manifest, err := fetchManifest(ctx, r, sandboxID, generation, func(string, ...any) {})
	if errors.Is(err, ErrGenerationIncomplete) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var digests []string
	for _, f := range manifest.Files {
		if !isSharedEntry(f) {
			continue
		}
		if sha, _, ok := strings.Cut(strings.TrimPrefix(f.Object, sharedBasePrefix), ".p"); ok && len(sha) == 64 {
			digests = append(digests, sha)
		}
	}
	return digests, nil
}

// SandboxGenerations describes every sandbox generation with objects in
// the bucket, from one listing: for each sandbox id, its generations and
// whether each is complete (carries a manifest).
func SandboxGenerations(ctx context.Context, lister BlobLister) (map[string]map[string]bool, error) {
	objects, err := lister.List(ctx, sandboxPrefix+"/")
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for _, obj := range objects {
		rest := strings.TrimPrefix(obj.Name, sandboxPrefix+"/")
		id, rest, ok := strings.Cut(rest, "/")
		if !ok {
			continue
		}
		generation, file, ok := strings.Cut(rest, "/")
		if !ok || validSegment(id) != nil || validSegment(generation) != nil {
			continue
		}
		if out[id] == nil {
			out[id] = map[string]bool{}
		}
		out[id][generation] = out[id][generation] || file == ManifestObject
	}
	return out, nil
}

// SharedBases lists the bucket's shared base objects grouped by content
// digest: one digest may be stored under several packing fingerprints.
func SharedBases(ctx context.Context, lister BlobLister) (map[string][]ObjectInfo, error) {
	objects, err := lister.List(ctx, sharedBasePrefix)
	if err != nil {
		return nil, err
	}
	bases := map[string][]ObjectInfo{}
	for _, obj := range objects {
		rest := strings.TrimPrefix(obj.Name, sharedBasePrefix)
		sha, _, ok := strings.Cut(rest, ".p")
		if !ok || len(sha) != 64 {
			continue
		}
		bases[sha] = append(bases[sha], obj)
	}
	return bases, nil
}
