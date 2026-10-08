package builder

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// fallbackAptMirror is Canonical's cloud-targeted mirror: a separate sync
// path from the public archive, and the one Ubuntu mirror that stayed up
// through the May 2026 archive.ubuntu.com / security.ubuntu.com outages.
const fallbackAptMirror = "nova.clouds.archive.ubuntu.com"

// aptMirrorEnv names the mirror host to use instead of choosing one.
const aptMirrorEnv = "TEMPLATE_APT_MIRROR"

const gceMetadataZoneURL = "http://metadata.google.internal/computeMetadata/v1/instance/zone"

// gceMirrorRegions are Google regions whose Ubuntu mirrors are tried, after
// the host's own region, when that one fails the transfer probe. A mirror
// can be reachable yet have a backend that stalls one connection in several,
// and the next region over serves the same archive a few hundred ms away.
var gceMirrorRegions = []string{"us-east4", "us-west2", "us-west1", "us-central1", "europe-west1"}

// selectAptMirror picks the Ubuntu mirror build VMs fetch packages from: the
// configured override, else the host's own Google regional mirror when it
// passes the transfer probe, else the first other Google region that does,
// else Canonical's cloud mirror. Canonical's public mirrors are partially
// unreachable often enough that a build pulling from them can run past its
// step deadline. The selection is synchronous on the build path, so its
// duration and outcome are logged.
func selectAptMirror(ctx context.Context, override string, logger *zerolog.Logger) string {
	start := time.Now()
	host, outcome := chooseAptMirror(ctx, override, gceMetadataZoneURL, mirrorTransfers, mirrorSelectDeadline)
	if logger != nil {
		logger.Info().Str("mirror", host).Str("outcome", outcome).Dur("duration", time.Since(start)).Msg("apt mirror selected")
	}
	return host
}

// mirrorSelectDeadline bounds the whole selection: the own region's probe,
// then, only if that fails, the other regions probed together.
const mirrorSelectDeadline = 25 * time.Second

// chooseAptMirror returns the mirror host and how it was chosen: override,
// off_gce, own_region, other_region or fallback.
func chooseAptMirror(ctx context.Context, override, metadataURL string, transfers func(context.Context, string) bool, deadline time.Duration) (string, string) {
	if override != "" {
		return override, "override"
	}
	region := gceRegion(ctx, metadataURL)
	if region == "" {
		return fallbackAptMirror, "off_gce"
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if own := region + ".gce.archive.ubuntu.com"; transfers(ctx, own) {
		return own, "own_region"
	}
	// The healthy case costs one probe; only a failing region fans out.
	var others []string
	for _, r := range gceMirrorRegions {
		if r != region {
			others = append(others, r+".gce.archive.ubuntu.com")
		}
	}
	results := make([]chan bool, len(others))
	for i, host := range others {
		results[i] = make(chan bool, 1)
		go func(host string, out chan<- bool) { out <- transfers(ctx, host) }(host, results[i])
	}
	for i, host := range others {
		if <-results[i] {
			return host, "other_region"
		}
	}
	return fallbackAptMirror, "fallback"
}

// gceRegion returns the region of the GCE instance the builder runs on
// ("us-east4" from "projects/…/zones/us-east4-c"), or "" off GCE.
func gceRegion(ctx context.Context, metadataURL string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return ""
	}
	zone := path.Base(strings.TrimSpace(string(body)))
	i := strings.LastIndex(zone, "-")
	if i <= 0 {
		return ""
	}
	return zone[:i]
}

// mirrorProbePath is a large file every Ubuntu mirror serves with range
// support, so the probe moves real bytes rather than asking for headers.
const mirrorProbePath = "/ubuntu/ls-lR.gz"

const (
	mirrorProbeFetches = 4
	mirrorProbeBytes   = 1 << 20
	mirrorProbeTimeout = 3 * time.Second
)

// mirrorTransfers reports whether host completed mirrorProbeFetches ranged
// fetches of mirrorProbeBytes each, every one within mirrorProbeTimeout.
// Each fetch is its own connection, so a backend that stalls some fraction
// of connections has that many chances to show itself.
func mirrorTransfers(ctx context.Context, host string) bool {
	for i := 0; i < mirrorProbeFetches; i++ {
		if !mirrorTransfer(ctx, host, int64(i)*mirrorProbeBytes) {
			return false
		}
	}
	return true
}

func mirrorTransfer(ctx context.Context, host string, offset int64) bool {
	ctx, cancel := context.WithTimeout(ctx, mirrorProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+mirrorProbePath, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+mirrorProbeBytes-1))
	req.Close = true
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return false
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, mirrorProbeBytes))
	return err == nil && n == mirrorProbeBytes
}
