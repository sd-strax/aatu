package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/module"
)

// Evidence persistence + evidence-open (03 §4.13 eager promotion at ingest;
// design/ui 02 §2.8 "every citation opens"). Every capability invocation's
// results are persisted in the same request: raw OCSF events into ocsf_events
// (append-only ground truth) and normalized STIX objects into stix_objects /
// stix_edges (deterministic ids — re-seeing the same entity is a no-op).
// GET /api/evidence/{ref} then opens any cited ref read-only.

// persistInvokeResult writes one invocation's telemetry + interpretation
// objects in a single transaction. Failure fails the invocation: returning
// refs that were never persisted would mint citations that cannot open —
// exactly the broken promise this layer exists to prevent.
func persistInvokeResult(r *http.Request, db *sql.DB, res capability.CapabilityResult) error {
	ctx := r.Context()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	tenant := module.SingleTenantUUID
	for _, e := range res.Events {
		payload, err := json.Marshal(e.Payload)
		if err != nil {
			return fmt.Errorf("marshal ocsf payload: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ocsf_events (id, tenant_id, class_uid, class_name, time, recorded_at, source_tool, payload)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO NOTHING
		`, e.ID, tenant, e.ClassUID, e.ClassName, e.Time, e.RecordedAt, e.SourceTool, payload); err != nil {
			return fmt.Errorf("insert ocsf event: %w", err)
		}
	}

	stix := func(id string, created time.Time, obj any) error {
		return upsertStixObject(r, tx, tenant, id, created, obj)
	}
	for _, n := range res.Normalized {
		for _, od := range n.ObservedData {
			if err := stix(string(od.ID), od.FirstObserved, od); err != nil {
				return err
			}
		}
		for _, s := range n.SCOs {
			if err := stix(string(s.ID), time.Time{}, s); err != nil {
				return err
			}
		}
		for _, i := range n.Indicators {
			if err := stix(string(i.ID), i.ValidFrom, i); err != nil {
				return err
			}
		}
		for _, s := range n.Sightings {
			if err := stix(string(s.ID), time.Time{}, s); err != nil {
				return err
			}
		}
		for _, id := range n.Identities {
			if err := stix(string(id.ID), time.Time{}, id); err != nil {
				return err
			}
		}
		for _, rel := range n.Relationships {
			srcUUID, sok := stixRefUUID(string(rel.SourceRef))
			tgtUUID, tok := stixRefUUID(string(rel.TargetRef))
			relUUID, rok := stixRefUUID(string(rel.ID))
			if !sok || !tok || !rok {
				continue
			}
			payload, err := json.Marshal(rel)
			if err != nil {
				return fmt.Errorf("marshal relationship: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO stix_edges (id, tenant_id, source_ref, target_ref, relationship_type, payload, created, modified)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
				ON CONFLICT (id) DO NOTHING
			`, relUUID, tenant, srcUUID, tgtUUID, rel.Type, payload, commandNow()); err != nil {
				return fmt.Errorf("insert stix edge: %w", err)
			}
		}
	}
	return tx.Commit()
}

func upsertStixObject(r *http.Request, tx *sql.Tx, tenant uuid.UUID, stixID string, created time.Time, obj any) error {
	id, ok := stixRefUUID(stixID)
	if !ok {
		return fmt.Errorf("normalizer emitted a malformed STIX id %q", stixID)
	}
	typ := stixRefType(stixID)
	payload, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", typ, err)
	}
	if created.IsZero() {
		created = commandNow()
	}
	if _, err := tx.ExecContext(r.Context(), `
		INSERT INTO stix_objects (id, tenant_id, type, spec_version, payload, created, modified)
		VALUES ($1, $2, $3, '2.1', $4, $5, $5)
		ON CONFLICT (id) DO NOTHING
	`, id, tenant, typ, payload, created); err != nil {
		return fmt.Errorf("insert stix %s: %w", typ, err)
	}
	return nil
}

// stixRefUUID extracts the uuid of a `<type>--<uuid>` STIX ref.
func stixRefUUID(ref string) (uuid.UUID, bool) {
	_, rest, found := strings.Cut(ref, "--")
	if !found {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

func stixRefType(ref string) string {
	typ, _, _ := strings.Cut(ref, "--")
	return typ
}

// EvidenceView is one opened citation: either a STIX object or a raw OCSF
// telemetry record (EvidenceRef = StixId | OcsfEventId, 01).
type EvidenceView struct {
	Ref     string          `json:"ref"`
	Kind    string          `json:"kind"` // "stix" | "ocsf"
	Type    string          `json:"type"` // STIX type, or OCSF class_name
	Payload json.RawMessage `json:"payload"`

	// OCSF-only metadata.
	ClassUID   int        `json:"class_uid,omitempty"`
	Time       *time.Time `json:"time,omitempty"`
	RecordedAt *time.Time `json:"recorded_at,omitempty"`
	SourceTool string     `json:"source_tool,omitempty"`
}

// getEvidence serves GET /api/evidence/{ref}: the citation-open surface. A
// `<type>--<uuid>` ref reads stix_objects; a bare uuid reads ocsf_events.
// Any authenticated reader (enforced by the caller).
func (b *Backend) getEvidence(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	ref, ok := strings.CutPrefix(strings.TrimSuffix(r.URL.Path, "/"), "/evidence/")
	if !ok || ref == "" {
		writeJSONError(w, http.StatusBadRequest, "path must be /evidence/{ref}")
		return
	}
	db := b.cfg.Handler.DB()

	if strings.Contains(ref, "--") {
		id, ok := stixRefUUID(ref)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "malformed STIX ref")
			return
		}
		var typ string
		var payload []byte
		err := db.QueryRowContext(r.Context(),
			`SELECT type, payload FROM stix_objects WHERE id = $1`, id).Scan(&typ, &payload)
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "no persisted object for "+ref)
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "query stix object: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, EvidenceView{Ref: ref, Kind: "stix", Type: typ, Payload: payload})
		return
	}

	id, err := uuid.Parse(ref)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "ref is neither a STIX id nor an event id")
		return
	}
	var v EvidenceView
	var t, rec time.Time
	var payload []byte
	err = db.QueryRowContext(r.Context(), `
		SELECT class_uid, class_name, time, recorded_at, source_tool, payload
		FROM ocsf_events WHERE id = $1
	`, id).Scan(&v.ClassUID, &v.Type, &t, &rec, &v.SourceTool, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "no persisted telemetry record "+ref)
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query ocsf event: "+err.Error())
		return
	}
	v.Ref, v.Kind, v.Payload, v.Time, v.RecordedAt = ref, "ocsf", payload, &t, &rec
	writeJSON(w, http.StatusOK, v)
}
