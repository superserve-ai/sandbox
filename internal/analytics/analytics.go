// Package analytics emits product-usage events to PostHog from the control
// plane and the data-plane proxy, attributed to the user behind the request
// (matching the console's distinct_id) and grouped by team. Capture is
// non-blocking and a no-op when PostHog is unconfigured.
package analytics

import (
	"time"

	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog"
)

// closeTimeout bounds how long Close waits for the worker to drain, so a wedged
// PostHog can never hold up process shutdown.
const closeTimeout = 2 * time.Second

// bufferSize bounds the in-flight event queue. When full (PostHog slow/down),
// Capture drops events rather than blocking the caller.
const bufferSize = 1024

// Client wraps the PostHog client. The zero value (and a Client from New with
// an empty key) is a safe no-op.
type Client struct {
	ph     posthog.Client
	log    zerolog.Logger
	events chan event
	quit   chan struct{}
	done   chan struct{}
}

type event struct {
	actorID string
	teamID  string
	name    string
	props   map[string]any
}

// New returns a Client. When apiKey is empty, Capture is a no-op. host may be
// empty to use PostHog's default endpoint.
func New(apiKey, host string, log zerolog.Logger) (*Client, error) {
	if apiKey == "" {
		log.Info().Msg("analytics: PostHog not configured; usage events disabled")
		return &Client{log: log}, nil
	}
	cfg := posthog.Config{}
	if host != "" {
		cfg.Endpoint = host
	}
	ph, err := posthog.NewWithConfig(apiKey, cfg)
	if err != nil {
		return nil, err
	}
	c := &Client{
		ph:     ph,
		log:    log,
		events: make(chan event, bufferSize),
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go c.worker()
	return c, nil
}

// worker drains the buffer into PostHog until Close signals quit, then flushes
// what's buffered and exits. events is never closed, so Capture can't panic on
// a shutdown race; a slow Enqueue backs up only this worker, never a request.
func (c *Client) worker() {
	defer close(c.done)
	for {
		select {
		case ev := <-c.events:
			c.enqueue(ev)
		case <-c.quit:
			for {
				select {
				case ev := <-c.events:
					c.enqueue(ev)
				default:
					return
				}
			}
		}
	}
}

func (c *Client) enqueue(ev event) {
	p := posthog.NewProperties()
	for k, v := range ev.props {
		p.Set(k, v)
	}
	var groups posthog.Groups
	if ev.teamID != "" {
		groups = posthog.NewGroups().Set("team", ev.teamID)
	}
	if err := c.ph.Enqueue(posthog.Capture{
		DistinctId: distinctID(ev.actorID, ev.teamID),
		Event:      ev.name,
		Properties: p,
		Groups:     groups,
	}); err != nil {
		c.log.Debug().Err(err).Str("event", ev.name).Msg("analytics: enqueue failed")
	}
}

// Capture records an event attributed to actorID (the Supabase user id,
// matching the console's distinct_id) and team; an empty actorID falls back to
// a team-scoped id. Non-blocking: drops on a full buffer, no-op when unset.
func (c *Client) Capture(actorID, teamID, name string, props map[string]any) {
	if c == nil || c.events == nil {
		return
	}
	select {
	case c.events <- event{actorID: actorID, teamID: teamID, name: name, props: props}:
	default:
		// Buffer full (PostHog slow/down) — drop to protect the hot path.
	}
}

// Close stops the worker (after flushing buffered events) and closes the
// underlying client. Safe to call once; not safe for concurrent calls.
func (c *Client) Close() {
	if c == nil || c.events == nil {
		return
	}
	close(c.quit)
	select {
	case <-c.done:
	case <-time.After(closeTimeout):
	}
	_ = c.ph.Close()
}

// distinctID returns the actor when known, else a team-scoped id.
func distinctID(actorID, teamID string) string {
	if actorID != "" {
		return actorID
	}
	return "team:" + teamID
}
