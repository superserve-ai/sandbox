package api

import (
	"github.com/gin-gonic/gin"

	"github.com/superserve-ai/sandbox/internal/db"
)

// SetupRouter creates and configures the Gin router with all route groups.
func SetupRouter(h *Handlers, queries *db.Queries) *gin.Engine {
	r := gin.New()
	r.Use(RequestLogger(), ErrorHandler())

	api := r.Group("/")
	api.Use(APIKeyAuth(queries))
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
	}

	r.GET("/health", h.Health)

	return r
}
