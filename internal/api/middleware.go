package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// APIKeyAuth returns a Gin middleware that validates the X-API-Key header
// by hashing the provided key and comparing it against the api_keys table.
func APIKeyAuth(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			respondErrorMsg(c, "unauthorized", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		var id string
		err := pool.QueryRow(c.Request.Context(),
			"SELECT id FROM api_keys WHERE key_hash = $1 AND revoked = false AND (expires_at IS NULL OR expires_at > now())",
			keyHash,
		).Scan(&id)
		if err != nil {
			respondErrorMsg(c, "unauthorized", "Invalid or missing X-API-Key header.", http.StatusUnauthorized)
			c.Abort()
			return
		}

		c.Set("api_key_id", id)
		c.Next()
	}
}

// RequestLogger returns a Gin middleware that logs each request using zerolog,
// including method, path, status code, and latency.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		if raw != "" {
			path = path + "?" + raw
		}

		evt := log.Info()
		if status >= 500 {
			evt = log.Error()
		} else if status >= 400 {
			evt = log.Warn()
		}

		evt.
			Str("method", method).
			Str("path", path).
			Int("status", status).
			Dur("latency", latency).
			Str("client_ip", clientIP).
			Int("body_size", c.Writer.Size()).
			Msg("request")
	}
}

// AutoWake returns a Gin middleware that transparently resumes paused VMs before
// forwarding the request. Applied to exec and file endpoints so that callers
// don't need to explicitly resume idle sandboxes.
func AutoWake(pool *pgxpool.Pool, vmd VMDClient) gin.HandlerFunc {
	queries := db.New(pool)

	return func(c *gin.Context) {
		raw := c.Param("instance_id")
		instanceID, err := uuid.Parse(raw)
		if err != nil {
			// Let the handler deal with the bad ID.
			c.Next()
			return
		}

		ctx := c.Request.Context()

		status, err := queries.GetVMStatus(ctx, instanceID)
		if err != nil {
			// VM may not exist; let the handler return the proper error.
			c.Next()
			return
		}

		if status != db.VmStatusPaused {
			c.Next()
			return
		}

		// VM is paused — resume it before the handler runs.
		pauseState, err := queries.GetVMPauseState(ctx, instanceID)
		if err != nil {
			log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("auto-wake: failed to read pause state")
			respondError(c, ErrInternal)
			c.Abort()
			return
		}

		snapshotPath := ""
		if pauseState.SnapshotPath != nil {
			snapshotPath = *pauseState.SnapshotPath
		}
		memPath := ""
		if pauseState.MemFilePath != nil {
			memPath = *pauseState.MemFilePath
		}

		vmdCtx, vmdCancel := context.WithTimeout(ctx, vmdTimeout)
		defer vmdCancel()

		ipAddress, err := vmd.ResumeInstance(vmdCtx, instanceID.String(), snapshotPath, memPath)
		if err != nil {
			log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("auto-wake: VMD ResumeInstance failed")
			respondError(c, ErrInternal)
			c.Abort()
			return
		}

		// Update DB: mark running, clear snapshot paths.
		var ip *netip.Addr
		if ipAddress != "" {
			parsed, err := netip.ParseAddr(ipAddress)
			if err == nil {
				ip = &parsed
			}
		}
		if err := queries.ResumeVM(ctx, db.ResumeVMParams{
			ID:        instanceID,
			IpAddress: ip,
		}); err != nil {
			log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("auto-wake: DB ResumeVM failed")
			// VM is already resumed in VMD; proceed despite DB error.
		}

		// Log activity asynchronously to minimize latency.
		go func() {
			meta, _ := json.Marshal(map[string]string{"trigger": "auto_wake"})
			if err := queries.CreateActivity(context.Background(), db.CreateActivityParams{
				VmID:     instanceID,
				Category: "sandbox",
				Action:   "resumed",
				Metadata: meta,
			}); err != nil {
				log.Error().Err(err).Str("instance_id", instanceID.String()).Msg("auto-wake: activity log failed")
			}
		}()

		log.Info().
			Str("instance_id", instanceID.String()).
			Str("ip_address", ipAddress).
			Msg("auto-wake: resumed paused instance")

		c.Next()
	}
}

// ErrorHandler returns a Gin middleware that recovers from panics and returns
// a structured JSON error response.
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				zerolog.Ctx(c.Request.Context()).Error().
					Interface("panic", r).
					Str("path", c.Request.URL.Path).
					Msg("panic recovered")

				respondErrorMsg(c, "internal_error",
					"An internal error occurred. Please try again or contact support.",
					http.StatusInternalServerError,
				)
				c.Abort()
			}
		}()

		c.Next()
	}
}
