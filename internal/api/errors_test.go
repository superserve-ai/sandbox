package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAppError_Error(t *testing.T) {
	err := &AppError{Code: "test", Message: "test message", HTTPStatus: 400}
	if err.Error() != "test message" {
		t.Errorf("expected 'test message', got %q", err.Error())
	}
}

func TestNewAppError(t *testing.T) {
	err := NewAppError("custom", "custom message", 422)
	if err.Code != "custom" || err.Message != "custom message" || err.HTTPStatus != 422 {
		t.Errorf("NewAppError fields mismatch: %+v", err)
	}
}

func TestRespondError_AppError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	respondError(c, ErrSandboxNotFound)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj := resp["error"].(map[string]interface{})
	if errObj["code"] != "not_found" {
		t.Errorf("expected code=not_found, got %v", errObj["code"])
	}
}

func TestRespondError_GenericError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	respondError(c, errors.New("something went wrong"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj := resp["error"].(map[string]interface{})
	if errObj["code"] != "internal_error" {
		t.Errorf("expected code=internal_error, got %v", errObj["code"])
	}
}

func TestRespondErrorMsg(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	respondErrorMsg(c, "validation_error", "field X is required", 422)

	if w.Code != 422 {
		t.Fatalf("expected 422, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj := resp["error"].(map[string]interface{})
	if errObj["code"] != "validation_error" {
		t.Errorf("expected code=validation_error, got %v", errObj["code"])
	}
	if errObj["message"] != "field X is required" {
		t.Errorf("unexpected message: %v", errObj["message"])
	}
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        *AppError
		wantCode   string
		wantStatus int
	}{
		{"ErrInstanceNotFound", ErrInstanceNotFound, "not_found", 404},
		{"ErrSandboxNotFound", ErrSandboxNotFound, "not_found", 404},
		{"ErrInvalidState", ErrInvalidState, "conflict", 409},
		{"ErrBadRequest", ErrBadRequest, "bad_request", 400},
		{"ErrUnauthorized", ErrUnauthorized, "unauthorized", 401},
		{"ErrInternal", ErrInternal, "internal_error", 500},
		{"ErrConflict", ErrConflict, "conflict", 409},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.wantCode {
				t.Errorf("code: got %q, want %q", tt.err.Code, tt.wantCode)
			}
			if tt.err.HTTPStatus != tt.wantStatus {
				t.Errorf("status: got %d, want %d", tt.err.HTTPStatus, tt.wantStatus)
			}
		})
	}
}
