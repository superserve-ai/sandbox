package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"google.golang.org/grpc/metadata"
)

// Only the logical DB status ends an SSE stream. VMD completion means the
// attempt stopped producing logs; publication or a replacement may remain.
func (h *Handlers) streamAttemptLogs(c *gin.Context, initial db.TemplateBuild) {
	ctx := c.Request.Context()
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return
	}
	write := func(event gin.H) {
		data, _ := json.Marshal(event)
		fmt.Fprintf(c.Writer, "data: %s\n\n", data)
		flusher.Flush()
	}
	type event struct {
		attempt uuid.UUID
		log     vmdclient.BuildLogEvent
	}
	type streamEnd struct {
		attempt  uuid.UUID
		sequence uint64
		finished bool
	}
	events := make(chan event, 64)
	ended := make(chan streamEnd, 1)
	var current uuid.UUID
	var completed uuid.UUID
	var logAttempt uuid.UUID
	var sequence uint64
	retryDelay := 2 * time.Second
	var retryAt time.Time
	// VMD replays buffered logs on each subscription.
	var lastLogSequence uint64
	var stop context.CancelFunc
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	forward := func(ev event) {
		if ev.attempt != current || (ev.log.Sequence != 0 && ev.log.Sequence <= lastLogSequence) {
			return
		}
		lastLogSequence = ev.log.Sequence
		write(gin.H{"timestamp": time.Unix(0, ev.log.TimestampUnixNanos).Format(time.RFC3339Nano), "stream": ev.log.Stream,
			"text": ev.log.Text, "finished": false, "attempt_id": ev.attempt})
	}
	drainQueued := func() {
		// Bound the drain so a late producer cannot delay logical completion.
		for remaining := len(events); remaining > 0; remaining-- {
			forward(<-events)
		}
	}
	refresh := func() bool {
		b, err := h.DB.GetTemplateBuild(ctx, db.GetTemplateBuildParams{ID: initial.ID, TemplateID: initial.TemplateID, TeamID: initial.TeamID})
		if err != nil {
			return true
		}
		if b.Status == db.TemplateBuildStatusReady || b.Status == db.TemplateBuildStatusFailed || b.Status == db.TemplateBuildStatusCancelled {
			if stop != nil {
				stop()
				stop = nil
			}
			drainQueued()
			write(gin.H{"stream": "system", "text": "build " + string(b.Status), "status": string(b.Status), "finished": true})
			return false
		}
		e, err := h.DB.GetBuildExecution(ctx, b.ID)
		if err != nil {
			return true
		}
		write(gin.H{"stream": "system", "text": e.Reason, "status": string(b.Status), "finished": false, "execution": e})
		next := uuid.Nil
		if e.CurrentAttempt != nil {
			next = *e.CurrentAttempt
		}
		if current != next {
			if stop != nil {
				stop()
				stop = nil
			}
			current = uuid.Nil
		}
		if logAttempt != next {
			logAttempt = next
			lastLogSequence = 0
			retryDelay = 2 * time.Second
			retryAt = time.Time{}
		}
		if next == uuid.Nil || current == next || completed == next || h.Hosts == nil {
			return true
		}
		if time.Now().Before(retryAt) {
			return true
		}
		a, err := h.DB.GetBuildAttempt(ctx, next)
		if err != nil {
			return true
		}
		lost, err := h.DB.BuildAttemptHostLost(ctx, a)
		if err != nil || lost {
			return true
		}
		client, err := h.Hosts.ClientFor(ctx, a.HostID)
		if err != nil {
			return true
		}
		streamCtx, cancel := context.WithCancel(ctx)
		stop = cancel
		current = next
		sequence++
		streamSequence := sequence
		go func() {
			finished := false
			err := client.StreamBuildLogs(metadata.AppendToOutgoingContext(streamCtx, "template-build-incarnation", a.IncarnationID.String()), a.VMID, func(log vmdclient.BuildLogEvent) error {
				finished = finished || log.Finished
				select {
				case events <- event{a.ID, log}:
					return nil
				case <-streamCtx.Done():
					return streamCtx.Err()
				}
			})
			if streamCtx.Err() == nil {
				select {
				case ended <- streamEnd{a.ID, streamSequence, finished && err == nil}:
				case <-streamCtx.Done():
				}
			}
		}()
		return true
	}
	if !refresh() {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !refresh() {
				return
			}
		case end := <-ended:
			if end.attempt != current || end.sequence != sequence {
				continue
			}
			// The stream goroutine has sent all its events before signaling termination.
			drainQueued()
			stop()
			stop = nil
			if end.finished {
				completed = end.attempt
			} else {
				current = uuid.Nil
				retryAt = time.Now().Add(retryDelay)
				if retryDelay < 8*time.Second {
					retryDelay *= 2
				}
			}
		case ev := <-events:
			forward(ev)
		}
	}
}
