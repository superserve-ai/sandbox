package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

func (h *Handlers) GetPlatformAbuseMode(c *gin.Context) {
	if _, ok := h.requireAbuse(c, false); !ok {
		return
	}
	var mode abuse.ComputeMode
	if err := h.Pool.QueryRow(c, `SELECT mode FROM abuse_runtime_settings WHERE singleton`).Scan(&mode); err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

func (h *Handlers) SetPlatformAbuseMode(c *gin.Context) {
	actor, ok := h.requireAbuse(c, true)
	if !ok {
		return
	}
	var input struct {
		Mode abuse.ComputeMode `json:"mode"`
	}
	if err := c.ShouldBindJSON(&input); err != nil || !abuse.ValidComputeMode(input.Mode) {
		respondError(c, ErrBadRequest)
		return
	}
	value, _ := json.Marshal(input)
	err := h.withAbuseMutation(c, func(tx pgx.Tx) error {
		var previous string
		if err := tx.QueryRow(c, `SELECT mode FROM abuse_runtime_settings WHERE singleton FOR UPDATE`).Scan(&previous); err != nil {
			return err
		}
		if _, err := tx.Exec(c, `UPDATE abuse_runtime_settings SET mode=$1,updated_at=now() WHERE singleton`, input.Mode); err != nil {
			return err
		}
		if _, err := tx.Exec(c, `INSERT INTO abuse_state_changes(reason) VALUES('mode changed')`); err != nil {
			return err
		}
		old, _ := json.Marshal(map[string]string{"mode": previous})
		_, err := tx.Exec(c, `INSERT INTO audit_logs(actor_user_id,event_type,old_value,new_value) VALUES($1,'abuse.mode.changed',$2,$3)`, actor, old, value)
		return err
	})
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Status(http.StatusNoContent)
}
