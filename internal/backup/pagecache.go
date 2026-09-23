package backup

import "os"

// dropStagingPages is DropPageCache behind a hook so tests can observe which
// files staging lets go of.
var dropStagingPages = func(path string) error { return DropPageCache(path) }

// DropPageCache drops the cached pages of the file at path. For a staging
// copy the pipeline has finished reading; never for an original artifact,
// whose pages the next resume wants, or a shared base every generation
// re-reads.
func DropPageCache(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return dropPageCache(f)
}
