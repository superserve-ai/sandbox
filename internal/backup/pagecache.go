package backup

import "os"

// dropStagingPages is dropPageCache behind a hook so tests can observe which
// files the uploader lets go of.
var dropStagingPages = dropPageCache

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
