package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/region"
)

func TestParseSandboxID_PublicAndLegacy(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)
	id := uuid.New()

	tests := []struct {
		name string
		raw  string
		want uuid.UUID
	}{
		{name: "public", raw: region.SandboxID(region.USW, id), want: id},
		{name: "legacy", raw: id.String(), want: id},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			req := httptest.NewRequest(http.MethodGet, "/sandboxes/"+tt.raw, nil)
			c.Request = req
			c.Params = gin.Params{{Key: "sandbox_id", Value: tt.raw}}
			got, err := parseSandboxID(c)
			if err != nil {
				t.Fatalf("parseSandboxID: %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseSandboxID(%q) = %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}

func TestSandboxToResponseUsesPublicID(t *testing.T) {
	t.Parallel()

	h := &Handlers{Config: &config.Config{}}
	id := uuid.New()
	resp := h.sandboxToResponse(db.Sandbox{
		ID:        id,
		Region:    region.USW,
		Name:      "test",
		Status:    db.SandboxStatusActive,
		VcpuCount: 1,
		MemoryMib: 1024,
	})
	if resp.ID != region.SandboxID(region.USW, id) {
		t.Fatalf("response id = %q", resp.ID)
	}
}

func TestRequestTeamHomeRegionFallback(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := requestTeamHomeRegion(c, &config.Config{Region: region.USW}); got != region.USW {
		t.Fatalf("fallback region = %q", got)
	}
}
