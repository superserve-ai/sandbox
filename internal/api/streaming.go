package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// ---------------------------------------------------------------------------
// Streaming Exec (Server-Sent Events)
// ---------------------------------------------------------------------------

type streamExecRequest struct {
	Command    string            `json:"command" binding:"required,min=1"`
	Args       []string          `json:"args"`
	Env        map[string]string `json:"env"`
	WorkingDir string            `json:"working_dir"`
	TimeoutS   int               `json:"timeout_s"`
}

// ExecSandboxStream runs a command inside a sandbox and streams output via SSE.
// The sandbox is loaded and auto-woken by the AutoWake middleware.
func (h *Handlers) ExecSandboxStream(c *gin.Context) {
	sandbox := sandboxFromContext(c)
	if sandbox == nil {
		respondError(c, ErrInternal)
		return
	}

	var req streamExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	if req.TimeoutS <= 0 {
		req.TimeoutS = 30
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		respondError(c, ErrInternal)
		return
	}

	vmd, vmdLookupErr := h.vmdForHost(c.Request.Context(), sandbox.HostID)
	if vmdLookupErr != nil {
		log.Error().Err(vmdLookupErr).Str("sandbox_id", sandbox.ID.String()).Msg("resolve VMD for exec stream failed")
		respondError(c, ErrInternal)
		return
	}

	start := time.Now()
	var lastExitCode int32

	err := vmd.ExecCommandStream(c.Request.Context(), sandbox.ID.String(),
		req.Command, req.Args, req.Env, req.WorkingDir, uint32(req.TimeoutS),
		func(stdout, stderr []byte, exitCode int32, finished bool) {
			event := gin.H{
				"timestamp": time.Now().Format(time.RFC3339Nano),
			}
			if len(stdout) > 0 {
				event["stdout"] = string(stdout)
			}
			if len(stderr) > 0 {
				event["stderr"] = string(stderr)
			}
			if finished {
				event["exit_code"] = exitCode
				event["finished"] = true
				lastExitCode = exitCode
			}

			data, marshalErr := json.Marshal(event)
			if marshalErr != nil {
				return
			}

			fmt.Fprintf(c.Writer, "data: %s\n\n", data)
			flusher.Flush()
		})

	if err != nil {
		// If VMD says the VM is gone, mark the sandbox failed. The HTTP
		// response has already committed 200 OK (SSE headers flushed
		// before the call), so we can't downgrade the status code —
		// instead emit a "gone" event in the stream so clients can
		// distinguish this from transient errors.
		if isVMDVMUnavailable(err) {
			log.Warn().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("VMD ExecCommandStream: VM unavailable, marking sandbox failed")
			h.markSandboxFailedAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID)
			errEvent, _ := json.Marshal(gin.H{
				"error":    "sandbox VM is no longer available",
				"code":     "gone",
				"finished": true,
			})
			fmt.Fprintf(c.Writer, "data: %s\n\n", errEvent)
			flusher.Flush()
		} else {
			log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("streaming sandbox exec failed")
			errEvent, _ := json.Marshal(gin.H{
				"error":    err.Error(),
				"finished": true,
			})
			fmt.Fprintf(c.Writer, "data: %s\n\n", errEvent)
			flusher.Flush()
		}
	}

	durationMs := int32(time.Since(start).Milliseconds())

	// Async observability writes.
	h.updateLastActivityAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID)
	actStatus := "success"
	if err != nil {
		actStatus = "error"
	}
	metadata, _ := json.Marshal(map[string]any{
		"command":     req.Command,
		"exit_code":   lastExitCode,
		"duration_ms": durationMs,
	})
	h.logActivityAsync(c.Request.Context(), sandbox.ID, sandbox.TeamID, "exec", "executed", actStatus, &sandbox.Name, &durationMs, metadata)
}
