package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sd-strax/reckon/aggregate"
)

// Cross-investigation appearances + transcript-open: the two "memory" read
// surfaces (design/ui binding §6.1; 02 §2.8/§2.9's data).

// AppearanceView is one investigation a ref appears in.
type AppearanceView struct {
	InvestigationID string     `json:"investigation_id"`
	Title           string     `json:"title"`
	Status          string     `json:"status"`
	SeedSummary     string     `json:"seed_summary,omitempty"`
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	Mentions        int        `json:"mentions"`
}

// listRefAppearances serves GET /api/entities/{ref}/appearances: every
// investigation whose thread cites the ref — "appears in N other
// investigations", powered by deterministic identity (03 §7). Any reader.
func (b *Backend) listRefAppearances(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	p := strings.TrimSuffix(r.URL.Path, "/")
	ref, ok := strings.CutPrefix(p, "/entities/")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path must be /entities/{ref}/appearances")
		return
	}
	ref, ok = strings.CutSuffix(ref, "/appearances")
	if !ok || ref == "" {
		writeJSONError(w, http.StatusBadRequest, "path must be /entities/{ref}/appearances")
		return
	}

	apps, err := aggregate.ListRefAppearances(r.Context(), b.cfg.Handler.DB(), ref)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list appearances: "+err.Error())
		return
	}
	out := []AppearanceView{}
	for _, a := range apps {
		v := AppearanceView{
			InvestigationID: a.AggregateID.String(),
			Title:           a.Title,
			Status:          a.Status,
			SeedSummary:     a.SeedSummary,
			Mentions:        a.Mentions,
		}
		if a.FirstSeen.Valid {
			t := a.FirstSeen.Time
			v.FirstSeen = &t
		}
		if a.LastSeen.Valid {
			t := a.LastSeen.Time
			v.LastSeen = &t
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ref": ref, "appearances": out})
}

// getInterpretationTranscript serves GET /api/interpretations/{id}/transcript:
// the full committed turn record behind a thread step (02 §6 Layer B — the
// content-addressed side store; the event carries the hash, this serves the
// bytes). Any reader: the transcript is the audit record.
func (b *Backend) getInterpretationTranscript(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	interpID, ok := interpretationSubresourceID(r.URL.Path, "transcript")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid interpretation id in path")
		return
	}
	db := b.cfg.Handler.DB()

	var payload []byte
	err := db.QueryRowContext(r.Context(), `
		SELECT payload FROM events
		WHERE event_type = $1 AND payload->>'interpretation_id' = $2
		LIMIT 1
	`, aggregate.EventTypeInterpretationRecorded, interpID.String()).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "no such interpretation")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query interpretation: "+err.Error())
		return
	}
	var rec aggregate.InterpretationRecorded
	if err := json.Unmarshal(payload, &rec); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "decode interpretation: "+err.Error())
		return
	}
	if rec.TranscriptRef == nil {
		writeJSONError(w, http.StatusNotFound, "this reasoning act carries no transcript")
		return
	}

	var body []byte
	err = db.QueryRowContext(r.Context(),
		`SELECT body FROM ai_transcripts WHERE hash = $1 LIMIT 1`,
		rec.TranscriptRef.ContentHash).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "transcript body not in the side store")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query transcript: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"interpretation_id": interpID.String(),
		"turn_id":           rec.TranscriptRef.TurnID,
		"content_hash":      rec.TranscriptRef.ContentHash,
		"body":              string(body),
	})
}
