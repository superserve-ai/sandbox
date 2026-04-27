package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AppError is a structured error that maps to an HTTP response.
type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
}

func (e *AppError) Error() string {
	return e.Message
}

// Common application errors.
var (
	ErrSandboxNotFound    = &AppError{Code: "not_found", Message: "Sandbox not found", HTTPStatus: http.StatusNotFound}
	ErrInvalidState = &AppError{Code: "conflict", Message: "Sandbox is not in a valid state for this operation", HTTPStatus: http.StatusConflict}
	ErrBadRequest         = &AppError{Code: "bad_request", Message: "Invalid request", HTTPStatus: http.StatusBadRequest}
	ErrUnauthorized       = &AppError{Code: "unauthorized", Message: "Invalid or missing X-API-Key header", HTTPStatus: http.StatusUnauthorized}
	ErrInternal           = &AppError{Code: "internal_error", Message: "A problem occurred. Please try again, or contact the team if it persists.", HTTPStatus: http.StatusInternalServerError}
	ErrConflict           = &AppError{Code: "conflict", Message: "Operation conflicts with current state", HTTPStatus: http.StatusConflict}
)

// NewAppError creates a new AppError with a custom message.
func NewAppError(code string, message string, httpStatus int) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: httpStatus}
}

// respondError writes a structured JSON error response. If the error is an
// *AppError it uses the embedded HTTP status; otherwise it defaults to 500.
func respondError(c *gin.Context, err error) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		c.JSON(appErr.HTTPStatus, gin.H{
			"error": gin.H{
				"code":    appErr.Code,
				"message": appErr.Message,
			},
		})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{
		"error": gin.H{
			"code":    "internal_error",
			"message": "A problem occurred. Please try again, or contact the team if it persists.",
		},
	})
}

// respondErrorMsg is a convenience for returning a one-off error.
func respondErrorMsg(c *gin.Context, code string, message string, httpStatus int) {
	c.JSON(httpStatus, gin.H{
		"error": gin.H{
			"code":    code,
			"message": message,
		},
	})
}
