// Package hostidentity loads installation identity without creating or repairing it.
package hostidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Identity struct {
	HostID        string `json:"host_id"`
	IncarnationID string `json:"incarnation_id"`
	ProjectID     string `json:"project_id"`
	InstanceID    string `json:"instance_id"`
}

const VerificationTimeout = 3 * time.Second

func Load(path, hostID string, metadata func(context.Context, string) (string, error)) (Identity, error) {
	// Both provider fields must be verified before startup, within one budget.
	ctx, cancel := context.WithTimeout(context.Background(), VerificationTimeout)
	defer cancel()
	var id Identity
	data, err := os.ReadFile(path)
	if err != nil {
		return id, fmt.Errorf("host identity missing; operator recovery required: %w", err)
	}
	if err := json.Unmarshal(data, &id); err != nil {
		return id, fmt.Errorf("invalid host identity: %w", err)
	}
	incarnation, err := uuid.Parse(id.IncarnationID)
	if err != nil || incarnation == uuid.Nil || id.HostID != hostID || id.ProjectID == "" || id.InstanceID == "" {
		return Identity{}, fmt.Errorf("invalid or mismatched host identity; operator recovery required")
	}
	for key, expected := range map[string]string{"project/project-id": id.ProjectID, "instance/id": id.InstanceID} {
		actual, err := metadata(ctx, key)
		if err != nil {
			return Identity{}, fmt.Errorf("verify host machine identity: %w", err)
		}
		if actual != expected {
			return Identity{}, fmt.Errorf("host identity belongs to another provisioned machine")
		}
	}
	id.IncarnationID = incarnation.String()
	return id, nil
}

// Metadata reads only the link-local provider identity, once at daemon startup.
func Metadata(ctx context.Context, key string) (string, error) {
	client := &http.Client{Timeout: VerificationTimeout, Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/computeMetadata/v1/"+key, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Metadata-Flavor") != "Google" {
		return "", fmt.Errorf("machine metadata unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return strings.TrimSpace(string(data)), err
}
