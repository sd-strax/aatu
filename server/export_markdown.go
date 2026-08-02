package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
)

// Live markdown export (design/ui binding §6 item 10): the portable,
// GitHub-renderable projection of an investigation, rendered on demand at ANY
// lifecycle state — "paste into a ticket unedited" is an export action, not a
// file on disk. This generalizes the design/07 post-conclusion report: the
// signed archive bundle remains the finalized artifact; this is the working
// snapshot. The format follows the ui/05 §5.1 file schema, rebound to engine
// vocabulary (the engine's words are what the audit record stores).

// exportMarkdownVersion names the projection format so downstream consumers
// can detect drift.
const exportMarkdownVersion = "reckon-export-md/1"

// getInvestigationMarkdown serves GET /api/investigations/{id}/export.md as
// text/markdown. Any reader — it is a projection of state the same reader can
// already fetch piecemeal.
func (b *Backend) getInvestigationMarkdown(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	id, ok := investigationSubresourceID(r.URL.Path, "export.md")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}
	md, err := b.renderInvestigationMarkdown(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: served as text/markdown (never text/html), and the
	// consumer is an editor tab — no DOM sink on this path.
	_, _ = w.Write([]byte(md))
}

// renderInvestigationMarkdown assembles the projections and renders the
// document. Every line of it names engine truth — no client-invented state.
func (b *Backend) renderInvestigationMarkdown(ctx context.Context, id uuid.UUID) (string, error) {
	db := b.cfg.Handler.DB()
	ic, err := aggregate.LoadInvestigationCurrent(ctx, db, id)
	if err != nil {
		if errors.Is(err, errNoRows()) {
			return "", fmt.Errorf("investigation not found")
		}
		return "", fmt.Errorf("load investigation: %w", err)
	}
	pins, err := aggregate.ListEvidencePins(ctx, db, id)
	if err != nil {
		return "", fmt.Errorf("list pins: %w", err)
	}
	hyps, err := aggregate.ListHypotheses(ctx, db, id)
	if err != nil {
		return "", fmt.Errorf("list hypotheses: %w", err)
	}
	preds, err := aggregate.ListPredictions(ctx, db, id)
	if err != nil {
		return "", fmt.Errorf("list predictions: %w", err)
	}
	actions, err := aggregate.ListActionCurrents(ctx, db, id)
	if err != nil {
		return "", fmt.Errorf("list actions: %w", err)
	}
	thread, err := b.loadThread(ctx, id)
	if err != nil {
		return "", err
	}

	rl := newRefLabeler(ctx, db)
	var md strings.Builder

	// --- frontmatter (ui/05 §5.1, engine vocabulary) -----------------------
	md.WriteString("---\n")
	fmt.Fprintf(&md, "id: %s\n", ic.AggregateID)
	fmt.Fprintf(&md, "title: %s\n", yamlString(ic.Title))
	fmt.Fprintf(&md, "status: %s\n", strings.ToUpper(ic.Status))
	if ic.VerdictDisposition != "" {
		fmt.Fprintf(&md, "verdict: %s\n", ic.VerdictDisposition)
		if ic.VerdictRationale != "" {
			fmt.Fprintf(&md, "rationale: %s\n", yamlString(ic.VerdictRationale))
		}
		if ic.VerdictAt.Valid {
			fmt.Fprintf(&md, "verdict_at: %s\n", ic.VerdictAt.Time.UTC().Format(time.RFC3339))
		}
	}
	if s := ic.Seed; s != nil {
		md.WriteString("seed:\n")
		fmt.Fprintf(&md, "  type: %s\n", s.Type)
		if s.Source != "" {
			fmt.Fprintf(&md, "  source: %s\n", yamlString(s.Source))
		}
		if s.AlertID != "" {
			fmt.Fprintf(&md, "  id: %s\n", yamlString(s.AlertID))
		}
		if s.EntityRef != "" {
			fmt.Fprintf(&md, "  entity_ref: %s\n", s.EntityRef)
		}
		if s.HypothesisStatement != "" {
			fmt.Fprintf(&md, "  hypothesis: %s\n", yamlString(s.HypothesisStatement))
		}
	}
	if ic.ConclusionRef != "" {
		fmt.Fprintf(&md, "conclusion_ref: %s\n", ic.ConclusionRef)
	}
	fmt.Fprintf(&md, "schema: %s\n", exportMarkdownVersion)
	md.WriteString("---\n\n")

	fmt.Fprintf(&md, "# %s\n\n", ic.Title)
	if ic.SeedSummary != "" {
		fmt.Fprintf(&md, "%s\n\n", ic.SeedSummary)
	}

	// --- pinned evidence ---------------------------------------------------
	if len(pins) > 0 {
		md.WriteString("## Pinned evidence\n\n")
		for _, p := range pins {
			finding := p.Finding
			if p.Superseded {
				finding = "~~" + finding + "~~ *(superseded)*"
			}
			fmt.Fprintf(&md, "- %s", finding)
			if len(p.InputRefs) > 0 {
				fmt.Fprintf(&md, " — cites %s", labeledList(rl, p.InputRefs))
			}
			fmt.Fprintf(&md, " *(%s, %s)*\n", actorWord(p.Actor.Kind), p.PinnedAt.Time.UTC().Format(time.RFC3339))
		}
		md.WriteString("\n")
	}

	// --- hypotheses (predictions nested, statuses verbatim) ----------------
	if len(hyps) > 0 {
		md.WriteString("## Hypotheses\n\n")
		byHyp := make(map[string][]aggregate.PredictionCurrent, len(preds))
		for _, p := range preds {
			byHyp[p.HypothesisRef] = append(byHyp[p.HypothesisRef], p)
		}
		for _, h := range hyps {
			fmt.Fprintf(&md, "- **[%s]** %s\n", h.Status, h.Statement)
			for _, p := range byHyp[h.ID] {
				fmt.Fprintf(&md, "  - prediction **[%s]** %s", p.Status, p.Statement)
				if len(p.TestResultRefs) > 0 {
					fmt.Fprintf(&md, " — tested against %s", labeledList(rl, p.TestResultRefs))
				}
				md.WriteString("\n")
			}
		}
		md.WriteString("\n")
	}

	// --- reasoning (append-only trace, sequence order) ---------------------
	if len(thread) > 0 {
		fmt.Fprintf(&md, "## Reasoning\n\n")
		for _, e := range thread {
			who := actorWord(e.Actor.Kind)
			if e.Actor.Model != "" {
				who += " · " + e.Actor.Model
			}
			// A superseded act (e.g. a verdict a later one revised) stays in the
			// trace — the record is append-only — but is marked so a reader never
			// mistakes a retracted act for the current view.
			typeLabel := e.InterpretationType
			if e.Superseded {
				typeLabel += " — superseded"
			}
			fmt.Fprintf(&md, "### %s — %s [%s]\n\n",
				e.OccurredAt.UTC().Format(time.RFC3339), typeLabel, who)
			if e.Summary != "" {
				if e.Superseded {
					fmt.Fprintf(&md, "~~%s~~\n\n", e.Summary)
				} else {
					fmt.Fprintf(&md, "%s\n\n", e.Summary)
				}
			}
			var meta []string
			if e.Confidence != "" {
				meta = append(meta, "confidence "+e.Confidence)
			}
			if e.ToolCalls > 0 {
				meta = append(meta, fmt.Sprintf("%d tool call(s)", e.ToolCalls))
			}
			if len(e.InputRefs) > 0 {
				meta = append(meta, "cites "+labeledList(rl, e.InputRefs))
			}
			for _, s := range e.ConsultedSOPs {
				verb := "consulted"
				if s.Used {
					verb = "followed"
				}
				title := s.Title
				if title == "" {
					title = s.SOPID
				}
				meta = append(meta, verb+" SOP: "+title)
			}
			if len(meta) > 0 {
				fmt.Fprintf(&md, "*%s*\n\n", strings.Join(meta, " · "))
			}
		}
	}

	// --- remediation (the durable action queue) ----------------------------
	if len(actions) > 0 {
		md.WriteString("## Remediation\n\n")
		for _, a := range actions {
			targets := make([]string, 0, len(a.Targets))
			for _, t := range a.Targets {
				if t.ResolvedIdentifier != "" {
					targets = append(targets, t.ResolvedIdentifier)
				} else {
					targets = append(targets, rl.label(t.EntityRef))
				}
			}
			fmt.Fprintf(&md, "- **[%s]** %s (%s) → %s",
				a.Status, a.ActionType, a.Tier, strings.Join(targets, ", "))
			var notes []string
			if a.RetryOf != (uuid.UUID{}) {
				notes = append(notes, "retry of "+a.RetryOf.String())
			}
			if a.ReversedByRef != (uuid.UUID{}) {
				notes = append(notes, "reversed by "+a.ReversedByRef.String())
			}
			if a.ReversalAttemptedByRef != (uuid.UUID{}) {
				notes = append(notes, "reversal attempted (unverified) by "+a.ReversalAttemptedByRef.String())
			}
			if len(notes) > 0 {
				fmt.Fprintf(&md, " — %s", strings.Join(notes, "; "))
			}
			md.WriteString("\n")
		}
		md.WriteString("\n")
	}

	// --- external work (comms) ---------------------------------------------
	// The handoffs an investigation spawned — who was notified, and how they
	// replied. Load-bearing for an IR handoff ("IT confirmed the reimage is
	// scheduled"), and absent from the structured sections above. Best-effort:
	// the layer may be off, in which case the section is simply omitted.
	if b.cfg.Comms != nil {
		threads, cerr := b.cfg.Comms.List(ctx, id, time.Now().UTC())
		if cerr == nil && len(threads) > 0 {
			md.WriteString("## External work\n\n")
			for _, t := range threads {
				subject := t.Subject
				if subject == "" {
					subject = t.ActionType
				}
				fmt.Fprintf(&md, "- **%s** → %s — *%s*", subject, t.Target, t.Status)
				if t.FollowUps > 0 {
					fmt.Fprintf(&md, " · %d follow-up(s)", t.FollowUps)
				}
				md.WriteString("\n")
				for _, e := range t.Trail {
					arrow := "→"
					switch e.Direction {
					case "inbound":
						arrow = "←"
					case "note":
						arrow = "·"
					}
					fmt.Fprintf(&md, "  - %s %s %s: %s\n",
						e.At.UTC().Format(time.RFC3339), arrow, e.Author, oneLine(e.Body))
				}
			}
			md.WriteString("\n")
		}
	}

	// --- conclusion --------------------------------------------------------
	if ic.ConclusionRef != "" {
		md.WriteString("## Conclusion\n\n")
		fmt.Fprintf(&md, "Concluded with verdict **%s** — report reference `%s`.\n\n",
			ic.VerdictDisposition, ic.ConclusionRef)
	}

	fmt.Fprintf(&md, "---\n*Exported %s from reckon (%s). The event-sourced aggregate is the record; this is a projection.*\n",
		time.Now().UTC().Format(time.RFC3339), exportMarkdownVersion)
	return md.String(), nil
}

// yamlString quotes a scalar safely for the frontmatter.
func yamlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ").Replace(s) + `"`
}

// refLabeler resolves cited refs to human labels for the export (a raw
// `x-host--65c1…` id is unreadable in a ticket; `WIN-FILE01` is not). Caches
// within one render, and ALWAYS falls back to the raw ref — a missing or opaque
// object degrades to the id, never a broken document.
type refLabeler struct {
	ctx   context.Context
	db    *sql.DB
	cache map[string]string
}

func newRefLabeler(ctx context.Context, db *sql.DB) *refLabeler {
	return &refLabeler{ctx: ctx, db: db, cache: map[string]string{}}
}

func (rl *refLabeler) label(ref string) string {
	if ref == "" {
		return ref
	}
	if v, ok := rl.cache[ref]; ok {
		return v
	}
	v := rl.resolve(ref)
	rl.cache[ref] = v
	return v
}

func (rl *refLabeler) resolve(ref string) string {
	if strings.Contains(ref, "--") {
		id, ok := stixRefUUID(ref)
		if !ok {
			return ref
		}
		var typ string
		var payload []byte
		if err := rl.db.QueryRowContext(rl.ctx,
			`SELECT type, payload FROM stix_objects WHERE id = $1`, id).Scan(&typ, &payload); err != nil {
			return ref
		}
		if lbl := stixLabel(typ, payload); lbl != "" {
			return lbl
		}
		return ref
	}
	id, err := uuid.Parse(ref)
	if err != nil {
		return ref
	}
	var class string
	var t time.Time
	if err := rl.db.QueryRowContext(rl.ctx,
		`SELECT class_name, time FROM ocsf_events WHERE id = $1`, id).Scan(&class, &t); err != nil {
		return ref
	}
	return fmt.Sprintf("%s @ %s", class, t.UTC().Format("15:04:05Z"))
}

// labeledList renders refs as their human labels in backticks, comma-joined.
func labeledList(rl *refLabeler, refs []string) string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = "`" + rl.label(r) + "`"
	}
	return strings.Join(out, ", ")
}

// stixLabel derives an identifying label from a persisted STIX object's payload
// (id/type/properties/provenance). Identity-contributing fields live under
// "properties" (03 §7); the switch mirrors the workbench evidence card. Returns
// "" when nothing identifying is present, so the caller falls back to the ref.
func stixLabel(typ string, payload []byte) string {
	var obj struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(payload, &obj); err != nil {
		return ""
	}
	get := func(k string) string {
		if v, ok := obj.Properties[k].(string); ok {
			return v
		}
		return ""
	}
	switch typ {
	case "x-host":
		return firstNonEmpty(get("hostname"), get("name"))
	case "ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr":
		return get("value")
	case "user-account":
		return firstNonEmpty(get("display_name"), get("user_id"), get("account_login"))
	case "file":
		return get("name")
	case "process":
		if cl := get("command_line"); cl != "" {
			return oneLine(cl)
		}
		return get("pid")
	default:
		return firstNonEmpty(get("name"), get("value"))
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// oneLine collapses whitespace so a value never breaks a markdown list row.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// actorWord maps an actor kind to the reading word.
func actorWord(kind string) string {
	switch kind {
	case aggregate.ActorAIDelegated:
		return "AI"
	case aggregate.ActorSystem:
		return "system"
	default:
		return "analyst"
	}
}
