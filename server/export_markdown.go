package server

import (
	"context"
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
				fmt.Fprintf(&md, " — cites %s", codeList(p.InputRefs))
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
					fmt.Fprintf(&md, " — tested against %s", codeList(p.TestResultRefs))
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
			fmt.Fprintf(&md, "### %s — %s [%s]\n\n",
				e.OccurredAt.UTC().Format(time.RFC3339), e.InterpretationType, who)
			if e.Summary != "" {
				fmt.Fprintf(&md, "%s\n\n", e.Summary)
			}
			var meta []string
			if e.Confidence != "" {
				meta = append(meta, "confidence "+e.Confidence)
			}
			if e.ToolCalls > 0 {
				meta = append(meta, fmt.Sprintf("%d tool call(s)", e.ToolCalls))
			}
			if len(e.InputRefs) > 0 {
				meta = append(meta, "cites "+codeList(e.InputRefs))
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
					targets = append(targets, t.EntityRef)
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

// codeList renders refs as backticked code spans, comma-joined.
func codeList(refs []string) string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = "`" + r + "`"
	}
	return strings.Join(out, ", ")
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
