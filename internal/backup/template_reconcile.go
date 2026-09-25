package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var templateObjectFingerprint = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// FindTemplatePublication checks the completed generation for one execution
// identity. It runs only when its producer is lost, outside lifecycle paths.
func FindTemplatePublication(ctx context.Context, store interface {
	BlobReader
	BlobLister
}, templateID, buildVMID string) (*GenerationManifest, []PublicationFile, string, error) {
	prefix, err := TemplateObject(templateID, buildVMID, "generation", ManifestObject)
	if err != nil {
		return nil, nil, "", err
	}
	prefix = strings.TrimSuffix(prefix, "generation/"+ManifestObject)
	objects, err := store.List(ctx, prefix)
	if err != nil {
		return nil, nil, "", err
	}
	var manifestObject string
	for _, object := range objects {
		if !strings.HasSuffix(object.Name, "/"+ManifestObject) {
			continue
		}
		if manifestObject != "" {
			return nil, nil, "", fmt.Errorf("multiple completed generations for template execution")
		}
		manifestObject = object.Name
	}
	if manifestObject == "" {
		return nil, nil, "", nil
	}
	relative := strings.TrimPrefix(manifestObject, prefix)
	generation, suffix, ok := strings.Cut(relative, "/")
	if !ok || suffix != ManifestObject || !publicationHash.MatchString(generation) {
		return nil, nil, "", fmt.Errorf("invalid template generation object %q", manifestObject)
	}
	rc, err := store.NewReader(ctx, manifestObject)
	if err != nil {
		return nil, nil, "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes+1))
	if err != nil {
		return nil, nil, "", err
	}
	if len(data) > maxManifestBytes {
		return nil, nil, "", fmt.Errorf("template manifest exceeds size limit")
	}
	var manifest GenerationManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, "", err
	}
	if manifest.TemplateID != templateID || manifest.BuildID != buildVMID || manifest.Generation != generation || manifest.TemplateRuntime == nil {
		return nil, nil, "", fmt.Errorf("template manifest identity mismatch")
	}
	files := make([]PublicationFile, 0, len(manifest.Files))
	keyFiles := make([]TaskFile, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		fingerprint, ok := strings.CutPrefix(file.Object, file.Name+".p")
		if file.BasePath != "" || file.BaseSHA256 != "" || !ok || !templateObjectFingerprint.MatchString(fingerprint) {
			return nil, nil, "", fmt.Errorf("invalid template artifact object %q", file.Name)
		}
		files = append(files, PublicationFile{Name: file.Name, RuntimePath: file.RuntimePath,
			SizeBytes: file.Size, AllocatedBytes: file.AllocatedBytes, SHA256: file.SHA256, Object: prefix + generation + "/" + file.Object})
		keyFiles = append(keyFiles, TaskFile{Name: file.Name, SHA256: file.SHA256, Size: file.Size})
	}
	if GenerationKey(keyFiles) != generation {
		return nil, nil, "", fmt.Errorf("template manifest generation mismatch")
	}
	if err := ValidateTemplatePublication(*manifest.TemplateRuntime, files); err != nil {
		return nil, nil, "", err
	}
	return &manifest, files, manifestObject, nil
}
