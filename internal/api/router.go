package api

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SetupRouter creates and configures the Gin router with all route groups.
func SetupRouter(h *Handlers, pool *pgxpool.Pool) *gin.Engine {
	r := gin.New()
	r.Use(RequestLogger(), ErrorHandler())

	api := r.Group("/")
	api.Use(APIKeyAuth(pool))
	{
		api.POST("/instances", h.CreateInstance)
		api.GET("/instances", h.ListInstances)
		api.GET("/instances/:instance_id", h.GetInstance)
		api.DELETE("/instances/:instance_id", h.DeleteInstance)
		api.POST("/instances/:instance_id/pause", h.PauseInstance)
		api.POST("/instances/:instance_id/resume", h.ResumeInstance)

		// Exec and file endpoints auto-wake paused instances.
		wake := AutoWake(pool, h.VMD)
		api.POST("/instances/:instance_id/exec", wake, h.ExecCommand)
		api.POST("/instances/:instance_id/exec/stream", wake, h.ExecCommandStream)
		api.PUT("/instances/:instance_id/files/*path", wake, h.UploadFile)
		api.GET("/instances/:instance_id/files/*path", wake, h.DownloadFile)
	}

	r.GET("/health", h.Health)

	return r
}
