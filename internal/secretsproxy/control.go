package secretsproxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/superserve-ai/sandbox/internal/secretsproxy/api"
)

// ControlServer exposes the IPC vmd uses to register/update sandbox state.
// Mount on a Unix socket — file-mode permissions are the auth boundary.
type ControlServer struct {
	state *State
}

func NewControlServer(state *State) *ControlServer {
	return &ControlServer{state: state}
}

// Handler returns the http.Handler for the control endpoints.
func (cs *ControlServer) Handler() http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/health", cs.health)
	r.POST("/sandboxes/register", cs.register)
	r.POST("/sandboxes/:id/unregister", cs.unregister)
	r.POST("/sandboxes/:id/bindings", cs.updateBindings)
	r.POST("/sandboxes/:id/egress", cs.updateEgress)
	return r
}

func (cs *ControlServer) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (cs *ControlServer) register(c *gin.Context) {
	var req api.RegisterRequest
	if err := decodeJSON(c.Request, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SandboxID == "" || req.SourceIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sandbox_id and source_ip required"})
		return
	}
	cs.state.Register(req)
	c.Status(http.StatusNoContent)
}

func (cs *ControlServer) unregister(c *gin.Context) {
	cs.state.Unregister(c.Param("id"))
	c.Status(http.StatusNoContent)
}

func (cs *ControlServer) updateBindings(c *gin.Context) {
	var req api.UpdateBindingsRequest
	if err := decodeJSON(c.Request, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !cs.state.UpdateBindings(c.Param("id"), req.Bindings) {
		c.JSON(http.StatusNotFound, gin.H{"error": "sandbox not registered"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (cs *ControlServer) updateEgress(c *gin.Context) {
	var req api.UpdateEgressRequest
	if err := decodeJSON(c.Request, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !cs.state.UpdateEgress(c.Param("id"), req.Egress) {
		c.JSON(http.StatusNotFound, gin.H{"error": "sandbox not registered"})
		return
	}
	c.Status(http.StatusNoContent)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
