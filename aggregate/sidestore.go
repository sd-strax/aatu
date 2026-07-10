package aggregate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// SideStore persists the AI reasoning side stores (02 §6 Layer B): the raw
// transcript bytes and the per-turn tool-call log. These are bulky, content-
// addressed data that must NOT live in the event log — the InterpretationRecorded
// event references them by content hash, this store holds the bytes. Writes run
// inside the aggregate's Handle transaction (via WriteReasoningTx) so an
// interpretation event and its transcript/tool-call rows commit atomically: the
// audit trail can never reference a transcript that failed to persist.
//
// The store is content-addressed: ai_transcripts is keyed by (tenant_id, hash),
// so re-recording byte-identical content is idempotent (ON CONFLICT DO NOTHING).
type SideStore struct {
	db *sql.DB
}

// NewSideStore constructs a SideStore over the aggregate database (the same
// reckon_main DB the events + side-store tables share, migration 0004).
func NewSideStore(db *sql.DB) *SideStore { return &SideStore{db: db} }

// TranscriptContent is the raw transcript for one reasoning turn, carried on a
// RecordInterpretation command. Body is hashed at record time (HashContent);
// the resulting hash is what the interpretation event's transcript_ref stores.
type TranscriptContent struct {
	TranscriptID uuid.UUID `json:"transcript_id"`
	TurnID       string    `json:"turn_id,omitempty"`
	Body         []byte    `json:"body"`
}

// ToolCallContent is one tool dispatch the LLM made during the turn, carried on
// a RecordInterpretation command and logged to ai_tool_calls. Args is stored
// inline (JSONB); ResultHash references the (separately stored) raw result.
type ToolCallContent struct {
	CallID     string          `json:"call_id"`
	ToolName   string          `json:"tool_name"`
	Args       json.RawMessage `json:"args,omitempty"`
	ResultHash string          `json:"result_hash,omitempty"`
}

// TranscriptRef is the reference the interpretation event carries into the
// transcript side store (02 §6): the content hash locates the bytes, the
// transcript/turn ids locate the position within the conversation.
type TranscriptRef struct {
	TranscriptID uuid.UUID `json:"transcript_id"`
	TurnID       string    `json:"turn_id,omitempty"`
	ContentHash  string    `json:"content_hash"`
}

// ToolCallRef is the reference the interpretation event carries for one tool
// call: the call id plus the content hash of its arguments.
type ToolCallRef struct {
	CallID      string `json:"call_id"`
	ContentHash string `json:"content_hash"`
}

// HashContent returns the SHA-256 hex of b — the content address used for both
// the interpretation event's refs and the side-store rows. Pure (no IO/time/
// rand), so applyCommand can compute the ref hash and the SideStore can
// recompute the identical hash from the identical bytes without any shared
// stored value to drift out of sync.
func HashContent(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// WriteReasoningTx persists the transcript + tool-call side stores for one
// RecordInterpretation inside tx, linking the tool-call rows to the
// interpretation event that was just appended (interpEventID). Content-addressed
// and idempotent: the transcript upsert is ON CONFLICT DO NOTHING, so a retry of
// the same content is a no-op.
func (s *SideStore) WriteReasoningTx(ctx context.Context, tx *sql.Tx, env Envelope, interpEventID uuid.UUID, c RecordInterpretation) error {
	var transcriptHash string
	if c.Transcript != nil {
		transcriptHash = HashContent(c.Transcript.Body)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ai_transcripts (tenant_id, hash, body, size_bytes, stored_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, hash) DO NOTHING
		`, env.TenantID, transcriptHash, c.Transcript.Body, len(c.Transcript.Body), env.OccurredAt); err != nil {
			return fmt.Errorf("insert ai_transcripts: %w", err)
		}
	}

	for i := range c.ToolCalls {
		tc := c.ToolCalls[i]
		args := tc.Args
		if len(args) == 0 {
			args = json.RawMessage("{}")
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ai_tool_calls (
				id, tenant_id, investigation_id, event_id, tool_name, tool_args,
				result_hash, transcript_hash, occurred_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, uuid.Must(uuid.NewV7()), env.TenantID, env.AggregateID, interpEventID,
			tc.ToolName, []byte(args), nullString(tc.ResultHash), nullString(transcriptHash),
			env.OccurredAt); err != nil {
			return fmt.Errorf("insert ai_tool_calls: %w", err)
		}
	}
	return nil
}

// nullString maps "" to SQL NULL.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
