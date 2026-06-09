package server

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// Delta is one projection-delta frame fanned out to subscribed WebSocket
// clients after an investigation aggregate commits. Clients apply deltas to
// their local projection cache and re-render; on reconnect they rehydrate the
// full projection plus a since-cursor to catch anything missed
// (design/05-component-architecture.md §9).
//
// Type is "ready" for the one frame sent at subscription time, "event" for a
// committed aggregate event.
type Delta struct {
	Type        string          `json:"type"`
	AggregateID string          `json:"aggregate_id,omitempty"`
	EventType   string          `json:"event_type,omitempty"`
	SequenceNo  int64           `json:"sequence_no,omitempty"`
	OccurredAt  time.Time       `json:"occurred_at,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

// subscription is one connected client's delta feed. investigation, when
// non-empty, filters the feed to a single aggregate; empty means every
// investigation in the (single, for OSS solo) tenant.
type subscription struct {
	ch            chan Delta
	investigation string
}

// hub is the in-process fan-out of committed deltas to subscribed WebSocket
// connections.
//
// Scope note: this is the "single-analyst direct WebSocket" path
// (design/05-component-architecture.md §3.1). Multi-analyst fan-out and
// capturing system-emitted events (Temporal-driven ActionDispatched, etc.)
// use the canonical Postgres LISTEN/NOTIFY path (design §9.1) where a backend
// LISTENer republishes into a hub like this one — deferred to v1 alongside the
// tenancy module. Today only client-initiated writes (the HTTP handlers) feed
// the hub, which is sufficient for OSS solo.
type hub struct {
	mu   sync.Mutex
	subs map[*subscription]struct{}
}

// newHub returns an empty hub.
func newHub() *hub {
	return &hub{subs: make(map[*subscription]struct{})}
}

// subscribe registers a new feed. investigation filters to one aggregate when
// non-empty. The returned subscription must be released with unsubscribe.
func (h *hub) subscribe(investigation string) *subscription {
	s := &subscription{ch: make(chan Delta, 32), investigation: investigation}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// unsubscribe removes a feed and closes its channel. Idempotent. Serialized
// with publish under h.mu, so a publish in flight never sends on a closed
// channel.
func (h *hub) unsubscribe(s *subscription) {
	h.mu.Lock()
	if _, ok := h.subs[s]; ok {
		delete(h.subs, s)
		close(s.ch)
	}
	h.mu.Unlock()
}

// publish fans a delta out to every matching subscriber. A subscriber whose
// buffer is full is skipped rather than blocking the hub: the dropped frame is
// recoverable because the client rehydrates from the projection on reconnect
// (design §9), so a slow consumer never stalls a fast writer or its peers.
func (h *hub) publish(d Delta) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.investigation != "" && s.investigation != d.AggregateID {
			continue
		}
		select {
		case s.ch <- d:
		default:
			log.Printf("stream: subscriber buffer full, dropping %s delta for %s",
				d.EventType, d.AggregateID)
		}
	}
}
