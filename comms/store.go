// Package comms tracks external-work conversation state (Phase F, design/ui
// binding §4): the thread that FOLLOWS an outbound message.
//
// The message itself is never sent from here — every outbound message is a
// notify.* x-action (T2: any dispatch that leaves reckon is T2+, 04 §1)
// through the full request → Gate 2 → approve → dispatch path, with the
// pre-send preview as its approval surface. This package owns what the action
// layer deliberately does not: the reply/follow-up/closure state of the
// conversation the message opened. CRUD + thin history — only the
// investigation aggregate is event-sourced; the audit record of every send is
// already in the event log as action.* events.
//
// Follow-up dueness and escalation are DERIVED at read time from stored
// timestamps (the lazy-derivation pattern the action expiry surface started
// with): nothing engine-side gates on them, so there is no convergence
// problem. A durable Temporal nudge (the expiry-emitter pattern) can layer on
// later without changing this schema. Escalation policies surface prompts and
// never auto-fire (v0 posture).
package comms

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Thread statuses. A follow-up returns a replied/followed_up thread to
// awaiting_reply only via a new outbound (a new notify.* action).
const (
	StatusAwaitingReply = "awaiting_reply"
	StatusReplied       = "replied"
	StatusFollowedUp    = "followed_up"
	StatusClosed        = "closed"
)

// Trail entry directions.
const (
	DirOutbound = "outbound"
	DirInbound  = "inbound"
	DirNote     = "note"
)

// StalePolicyID names the v0 shipped escalation policy: external work open
// past the threshold with repeated follow-ups and no resolution. Surfaced as
// a prompt; never auto-fired.
const StalePolicyID = "external-work-stale-72h"

const (
	staleAfter          = 72 * time.Hour
	staleFollowUpsFloor = 2
)

// TrailEntry is one entry of a thread's conversation trail.
type TrailEntry struct {
	Direction string    `json:"direction"` // outbound | inbound | note
	Author    string    `json:"author"`
	At        time.Time `json:"at"`
	Body      string    `json:"body"`
}

// Thread is one comms/external-work thread.
type Thread struct {
	ThreadID       uuid.UUID
	AggregateID    uuid.UUID
	ActionID       uuid.UUID
	ActionType     string
	Target         string
	Subject        string
	Status         string
	FollowUpHours  int
	FollowUps      int
	UnackedReply   bool
	SentAt         time.Time
	NextFollowUpAt sql.NullTime
	UpdatedAt      time.Time
	Trail          []TrailEntry

	// Derived at read time (never stored):
	FollowUpDue         bool   // the follow-up interval elapsed with no reply
	EscalationTriggered bool   // the stale policy matched — surface a prompt
	EscalationPolicy    string // policy id when triggered
}

// Store is the comms-thread CRUD over the main DB.
type Store struct {
	db *sql.DB
}

// NewStore wraps the main DB.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Outbound records one sent message: a new thread when threadRef is nil, or a
// follow-up on the referenced thread (count incremented, follow-up clock
// reset, thread back to awaiting_reply). Called from the action-result path —
// only a SUCCEEDED dispatch ever lands here, so the trail never claims a send
// that didn't happen.
func (s *Store) Outbound(ctx context.Context, t OutboundMessage) error {
	now := t.At.UTC()
	entry, err := json.Marshal([]TrailEntry{{Direction: DirOutbound, Author: t.Author, At: now, Body: t.Body}})
	if err != nil {
		return err
	}
	if t.ThreadRef == uuid.Nil {
		var next sql.NullTime
		if t.FollowUpHours > 0 {
			next = sql.NullTime{Valid: true, Time: now.Add(time.Duration(t.FollowUpHours) * time.Hour)}
		}
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO comms_threads (
				thread_id, aggregate_id, tenant_id, action_id, action_type, target,
				subject, status, follow_up_hours, sent_at, next_followup_at, updated_at, trail
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $10, $12)
		`, uuid.New(), t.AggregateID, t.TenantID, t.ActionID, t.ActionType, t.Target,
			t.Subject, StatusAwaitingReply, t.FollowUpHours, now, next, entry)
		return err
	}
	// A follow-up: append to the referenced thread and restart its clock.
	res, err := s.db.ExecContext(ctx, `
		UPDATE comms_threads
		SET follow_ups = follow_ups + 1,
		    status = $2,
		    next_followup_at = CASE WHEN follow_up_hours > 0
		        THEN $3::timestamptz + make_interval(hours => follow_up_hours) ELSE NULL END,
		    updated_at = $3,
		    trail = trail || $4::jsonb
		WHERE thread_id = $1 AND status <> $5
	`, t.ThreadRef, StatusAwaitingReply, now, entry, StatusClosed)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("comms thread %s not found or closed", t.ThreadRef)
	}
	return nil
}

// OutboundMessage parameterizes Outbound.
type OutboundMessage struct {
	AggregateID   uuid.UUID
	TenantID      uuid.UUID
	ActionID      uuid.UUID
	ActionType    string
	Target        string
	Subject       string
	Body          string
	Author        string
	FollowUpHours int
	At            time.Time
	// ThreadRef, when set, makes this a follow-up on an existing thread.
	ThreadRef uuid.UUID
}

// Inbound records a reply (the v0 ingestion seam — a real vendor webhook
// lands with its adapter in Phase E/F): trail entry, status → replied, and
// the unacked flag that drives the notification card.
func (s *Store) Inbound(ctx context.Context, threadID uuid.UUID, author, body string, at time.Time) error {
	return s.appendAndSet(ctx, threadID,
		TrailEntry{Direction: DirInbound, Author: author, At: at.UTC(), Body: body},
		`status = '`+StatusReplied+`', unacked_reply = TRUE, next_followup_at = NULL`)
}

// Ack acknowledges the latest reply — recorded in the trail, collapses the
// notification affordance. The thread stays replied.
func (s *Store) Ack(ctx context.Context, threadID uuid.UUID, principal string, at time.Time) error {
	return s.appendAndSet(ctx, threadID,
		TrailEntry{Direction: DirNote, Author: principal, At: at.UTC(), Body: "acknowledged"},
		`unacked_reply = FALSE`)
}

// Done closes the thread (external work resolved).
func (s *Store) Done(ctx context.Context, threadID uuid.UUID, principal string, at time.Time) error {
	return s.appendAndSet(ctx, threadID,
		TrailEntry{Direction: DirNote, Author: principal, At: at.UTC(), Body: "marked done"},
		`status = '`+StatusClosed+`', unacked_reply = FALSE, next_followup_at = NULL`)
}

// Snooze pushes the follow-up clock by the given hours.
func (s *Store) Snooze(ctx context.Context, threadID uuid.UUID, principal string, hours int, at time.Time) error {
	if hours <= 0 {
		return fmt.Errorf("snooze hours must be positive")
	}
	entry, err := json.Marshal([]TrailEntry{{Direction: DirNote, Author: principal, At: at.UTC(), Body: fmt.Sprintf("snoozed %dh", hours)}})
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE comms_threads
		SET next_followup_at = $2::timestamptz + make_interval(hours => $3),
		    updated_at = $2, trail = trail || $4::jsonb
		WHERE thread_id = $1 AND status <> '`+StatusClosed+`'
	`, threadID, at.UTC(), hours, entry)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("comms thread %s not found or closed", threadID)
	}
	return nil
}

// appendAndSet appends one trail entry and applies a fixed SET clause. The
// clause is always a package-internal constant expression — never input.
func (s *Store) appendAndSet(ctx context.Context, threadID uuid.UUID, e TrailEntry, set string) error {
	entry, err := json.Marshal([]TrailEntry{e})
	if err != nil {
		return err
	}
	//nolint:gosec // G201: set is a compile-time constant clause from this file.
	q := `UPDATE comms_threads SET ` + set + `, updated_at = $2, trail = trail || $3::jsonb
	      WHERE thread_id = $1 AND status <> '` + StatusClosed + `'`
	res, err := s.db.ExecContext(ctx, q, threadID, e.At, entry)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("comms thread %s not found or closed", threadID)
	}
	return nil
}

// List returns an investigation's threads, oldest first, with the derived
// flags (follow-up due, escalation prompt) computed against now.
func (s *Store) List(ctx context.Context, aggregateID uuid.UUID, now time.Time) ([]Thread, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT thread_id, aggregate_id, action_id, action_type, target, subject,
		       status, follow_up_hours, follow_ups, unacked_reply,
		       sent_at, next_followup_at, updated_at, trail
		FROM comms_threads
		WHERE aggregate_id = $1
		ORDER BY sent_at, thread_id
	`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query comms_threads: %w", err)
	}
	defer rows.Close()

	now = now.UTC()
	var out []Thread
	for rows.Next() {
		var t Thread
		var trail []byte
		if err := rows.Scan(&t.ThreadID, &t.AggregateID, &t.ActionID, &t.ActionType,
			&t.Target, &t.Subject, &t.Status, &t.FollowUpHours, &t.FollowUps,
			&t.UnackedReply, &t.SentAt, &t.NextFollowUpAt, &t.UpdatedAt, &trail); err != nil {
			return nil, fmt.Errorf("scan comms thread: %w", err)
		}
		if len(trail) > 0 {
			_ = json.Unmarshal(trail, &t.Trail)
		}
		open := t.Status == StatusAwaitingReply || t.Status == StatusFollowedUp
		t.FollowUpDue = open && t.NextFollowUpAt.Valid && t.NextFollowUpAt.Time.Before(now)
		if open && t.FollowUps >= staleFollowUpsFloor && now.Sub(t.SentAt) > staleAfter {
			t.EscalationTriggered = true
			t.EscalationPolicy = StalePolicyID
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// OpenCount returns how many threads still await a reply — the conclude
// dialog's honest input ("closure is blocked while comms are open" is
// decision support at v0, engine gate when Phase F completes).
func (s *Store) OpenCount(ctx context.Context, aggregateID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM comms_threads
		WHERE aggregate_id = $1 AND status IN ($2, $3)
	`, aggregateID, StatusAwaitingReply, StatusFollowedUp).Scan(&n)
	return n, err
}
