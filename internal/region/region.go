package region

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const (
	USE = "use"
	USW = "usw"
)

var validRegions = map[string]struct{}{
	USE: {},
	USW: {},
}

type APIKeyRegionParse struct {
	Region    string
	Known     bool
	Unknown   bool
	Absent    bool
	Malformed bool
}

func Valid(value string) bool {
	_, ok := validRegions[value]
	return ok
}

func ParseAPIKeyRegion(raw string) APIKeyRegionParse {
	const prefix = "ss_live_"
	if !strings.HasPrefix(raw, prefix) {
		return APIKeyRegionParse{Absent: true}
	}

	rest := strings.TrimPrefix(raw, prefix)
	if rest == "" {
		return APIKeyRegionParse{Malformed: true}
	}

	token, remainder, found := strings.Cut(rest, "_")
	if !found {
		// Legacy keys have no explicit region segment.
		return APIKeyRegionParse{Absent: true}
	}
	if token == "" || remainder == "" {
		return APIKeyRegionParse{Malformed: true}
	}
	if !isLowerAlphaNum(token) {
		return APIKeyRegionParse{Malformed: true}
	}
	if Valid(token) {
		return APIKeyRegionParse{Region: token, Known: true}
	}
	return APIKeyRegionParse{Region: token, Unknown: true}
}

func SandboxID(region string, id uuid.UUID) string {
	return fmt.Sprintf("sb-%s-%s", region, id.String())
}

type ParsedSandboxID struct {
	UUID    uuid.UUID
	Region  string
	Known   bool
	Legacy  bool
}

func ParseSandboxID(raw string) (ParsedSandboxID, error) {
	if id, err := uuid.Parse(raw); err == nil {
		return ParsedSandboxID{UUID: id, Legacy: true}, nil
	}

	if !strings.HasPrefix(raw, "sb-") {
		return ParsedSandboxID{}, fmt.Errorf("invalid sandbox_id: %q is not a valid sandbox ID", raw)
	}
	rest := strings.TrimPrefix(raw, "sb-")
	token, uuidPart, found := strings.Cut(rest, "-")
	if !found || !Valid(token) {
		return ParsedSandboxID{}, fmt.Errorf("invalid sandbox_id: %q is not a valid sandbox ID", raw)
	}
	id, err := uuid.Parse(uuidPart)
	if err != nil {
		return ParsedSandboxID{}, fmt.Errorf("invalid sandbox_id: %q is not a valid sandbox ID", raw)
	}
	return ParsedSandboxID{
		UUID:   id,
		Region: token,
		Known:  true,
	}, nil
}

func Hostname(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func isLowerAlphaNum(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}
