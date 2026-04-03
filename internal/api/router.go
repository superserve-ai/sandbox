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

		api.POST("/instances/:instance_id/exec", h.ExecCommand)
		api.POST("/instances/:instance_id/exec/stream", h.ExecCommandStream)

		api.PUT("/instances/:instance_id/files/*path", h.UploadFile)
		api.GET("/instances/:instance_id/files/*path", h.DownloadFile)

		api.POST("/sandboxes/:sandbox_id/resume", h.ResumeSandbox)
		api.DELETE("/sandboxes/:sandbox_id", h.DeleteSandbox)
		api.POST("/sandboxes/:sandbox_id/exec", h.ExecSandbox)
		api.POST("/sandboxes/:sandbox_id/exec/stream", h.ExecSandboxStream)
	}

	r.GET("/health", h.Health)

	return r
}
