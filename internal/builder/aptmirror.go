package builder

import (
	"context"
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

// selectAptMirror picks the Ubuntu mirror build VMs fetch packages from: the
// configured override, else Google's mirror for the region this host runs
// in when it answers, else Canonical's cloud mirror. Canonical's public
// mirrors are partially unreachable often enough that a build pulling from
// them can run past its step deadline; Google's in-region mirror has not
// been.
func selectAptMirror(ctx context.Context, override string, logger *zerolog.Logger) string {
	return chooseAptMirror(ctx, override, gceMetadataZoneURL, mirrorAnswers, logger)
}

func chooseAptMirror(ctx context.Context, override, metadataURL string, answers func(context.Context, string) bool, logger *zerolog.Logger) string {
	if override != "" {
		return override
	}
	region := gceRegion(ctx, metadataURL)
	if region == "" {
		if logger != nil {
			logger.Info().Str("mirror", fallbackAptMirror).Msg("not on GCE; using the fallback apt mirror")
		}
		return fallbackAptMirror
	}
	host := region + ".gce.archive.ubuntu.com"
	if !answers(ctx, host) {
		if logger != nil {
			logger.Warn().Str("mirror", host).Str("fallback", fallbackAptMirror).Msg("regional apt mirror did not answer; using the fallback")
		}
		return fallbackAptMirror
	}
	return host
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

func mirrorAnswers(ctx context.Context, host string) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+host+"/ubuntu/", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
