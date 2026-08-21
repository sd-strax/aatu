package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"time"

	reckon "github.com/sd-strax/reckon"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/module"
)

// DemoSeedResult reports what the demo-seed endpoint loaded into the knowledge
// corpus. The fixtures + capability config are materialized client-side by the
// CLI (runtime.SeedDemo); this endpoint owns only the DB-backed half.
//
// Only prior-case summaries are seeded. The demo's SOPs are NOT loaded here —
// they are staged to disk by the CLI and imported LIVE during the demo (the
// workbench "Import SOPs…" command), so the audience sees the import capability
// and watches the just-imported SOP light up the knowledge rail on the next turn.
type DemoSeedResult struct {
	Cases int `json:"cases"`
}

// demoInstallState is the virginity readout returned in a 409 when the install
// already holds real work, so the operator sees exactly why the seed refused.
type demoInstallState struct {
	Investigations int `json:"investigations"`
	SOPs           int `json:"sops"`
}

// seedDemoKnowledge handles POST /api/admin/demo/seed (analyst): load the
// embedded prior-case summaries into the knowledge corpus (the history the
// similarity-recall loop draws on). SOPs are deliberately NOT seeded here — they
// are imported live during the demo. It is the DB half of `reckon demo seed`;
// the CLI has already checked reachability and will write the fixtures +
// capability config and stage the SOP docs to disk.
//
// The virginity guard is enforced HERE, server-side, not just in the CLI: the
// seed only runs on an install with no investigations and no SOPs, so it can
// never contaminate a working instance. A non-virgin install gets a 409 with
// the counts that blocked it — the operator runs `reckon demo reset` first.
func (b *Backend) seedDemoKnowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
		if b.cfg.Knowledge == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "knowledge corpus not configured")
			return
		}
		state, err := b.demoInstallState(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "check install state: "+err.Error())
			return
		}
		if state.Investigations > 0 || state.SOPs > 0 {
			// Not virgin — refuse and say exactly why. The CLI turns this into the
			// "run `reckon demo reset` first" message.
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "install is not virgin — demo seed only runs on a fresh install",
				"state": state,
			})
			return
		}

		res, err := b.loadDemoKnowledge(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "seed knowledge: "+err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, res)
	})
}

// demoInstallState counts the two signals of a non-virgin install: any
// investigations (real case work) and any SOPs (institutional knowledge already
// imported). Either is enough to refuse a demo seed. Case summaries need not be
// counted separately — they only exist downstream of investigations.
func (b *Backend) demoInstallState(ctx context.Context) (demoInstallState, error) {
	var st demoInstallState
	if b.cfg.Handler == nil {
		return st, fmt.Errorf("aggregate handler not configured")
	}
	if err := b.cfg.Handler.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM investigation_current`).Scan(&st.Investigations); err != nil {
		return st, fmt.Errorf("count investigations: %w", err)
	}
	sops, err := b.cfg.Knowledge.List(ctx, module.SingleTenantUUID, true /*includeRetired*/)
	if err != nil {
		return st, fmt.Errorf("count sops: %w", err)
	}
	st.SOPs = len(sops)
	return st, nil
}

// demoCase is the on-disk shape of a prior-case summary in the knowledge pack —
// a clean JSON projection of knowledge.Summary (the domain struct carries no
// json tags), mapped across in loadDemoKnowledge.
type demoCase struct {
	InvestigationRef   string                    `json:"investigation_ref"`
	Title              string                    `json:"title"`
	ConcludedAt        time.Time                 `json:"concluded_at"`
	SeedKind           string                    `json:"seed_kind"`
	SeedValue          string                    `json:"seed_value"`
	Techniques         []string                  `json:"techniques"`
	PrimaryEntities    []string                  `json:"primary_entities"`
	ActionsTaken       []knowledge.SummaryAction `json:"actions_taken"`
	ConclusionOutcome  string                    `json:"conclusion_outcome"`
	DurationHours      float64                   `json:"duration_hours"`
	VerdictDisposition string                    `json:"verdict_disposition"`
	VerdictRationale   string                    `json:"verdict_rationale"`
	SummaryText        string                    `json:"summary_text"`
}

// loadDemoKnowledge reads the embedded prior-case summaries and writes them into
// the corpus via WriteSummary (idempotent revision on the source ref), re-runnable
// by construction though the virginity guard means it normally runs once. The
// summaries embed at write time when the substrate has an embedder configured, so
// similarity recall ranks them by cosine — the CLI refuses the seed without an
// embeddings backend, so the demo can never land in the keyword-only fallback.
//
// SOPs are NOT written here; they are imported live during the demo.
func (b *Backend) loadDemoKnowledge(ctx context.Context) (DemoSeedResult, error) {
	var res DemoSeedResult
	tenant := module.SingleTenantUUID

	cases, err := fs.ReadDir(reckon.DemoFS, reckon.DemoKnowledgeCases)
	if err != nil {
		return res, fmt.Errorf("read case pack: %w", err)
	}
	for _, e := range cases {
		if e.IsDir() {
			continue
		}
		raw, err := reckon.DemoFS.ReadFile(path.Join(reckon.DemoKnowledgeCases, e.Name()))
		if err != nil {
			return res, fmt.Errorf("read case %s: %w", e.Name(), err)
		}
		var dc demoCase
		if err := json.Unmarshal(raw, &dc); err != nil {
			return res, fmt.Errorf("parse case %s: %w", e.Name(), err)
		}
		if _, err := b.cfg.Knowledge.WriteSummary(ctx, tenant, knowledge.Summary{
			InvestigationRef:   dc.InvestigationRef,
			Title:              dc.Title,
			ConclusionAt:       dc.ConcludedAt,
			SummaryText:        dc.SummaryText,
			ExtractorVersion:   "demo-seed",
			SeedKind:           dc.SeedKind,
			SeedValue:          dc.SeedValue,
			Techniques:         dc.Techniques,
			PrimaryEntities:    dc.PrimaryEntities,
			ActionsTaken:       dc.ActionsTaken,
			ConclusionOutcome:  dc.ConclusionOutcome,
			DurationHours:      dc.DurationHours,
			VerdictDisposition: dc.VerdictDisposition,
			VerdictRationale:   dc.VerdictRationale,
		}); err != nil {
			return res, fmt.Errorf("write case summary %s: %w", e.Name(), err)
		}
		res.Cases++
	}

	return res, nil
}
