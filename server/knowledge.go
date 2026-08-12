package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/internal/sopdoc"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/module"
)

// SOPBody is the create/update payload for a SOP.
type SOPBody struct {
	Title          string   `json:"title"`
	Body           string   `json:"body"`
	Tags           []string `json:"tags,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

// SOPImportBody is the import payload (design/06 §2.4): SOPBody plus the
// original author and the source pointer. source.url keys the re-import
// lineage — importing the same URL revises the existing SOP.
type SOPImportBody struct {
	SOPBody
	Author string `json:"author,omitempty"` // the ORIGINAL document author, from the doc
	Source struct {
		System  string `json:"system,omitempty"`
		URL     string `json:"url"`
		Version string `json:"version,omitempty"`
	} `json:"source"`
}

// recallSOPs handles POST /api/knowledge/recall_sops (design/06 §4): keyword
// retrieval over the SOP corpus. Any authenticated reader — the agent loop
// consults it during reasoning.
func (b *Backend) recallSOPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b.requireRolesOrDeny(w, r, anyReader, func(w http.ResponseWriter, r *http.Request) {
		var req knowledge.RecallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
			return
		}
		res, err := b.cfg.Knowledge.RecallSOPs(r.Context(), module.SingleTenantUUID, req)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "recall_sops: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

// recallSimilar handles POST /api/knowledge/recall_similar_investigations
// (design/06 §4, K4): similarity retrieval over the concluded-investigation
// summary corpus — "have we handled something like this before?" Any
// authenticated reader; the agent loop consults it during reasoning.
func (b *Backend) recallSimilar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b.requireRolesOrDeny(w, r, anyReader, func(w http.ResponseWriter, r *http.Request) {
		var req knowledge.SimilarRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
			return
		}
		res, err := b.cfg.Knowledge.RecallSimilar(r.Context(), module.SingleTenantUUID, req)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "recall_similar_investigations: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

// SummaryNarrativeBody is the client-side enrichment payload (design/06 §3.2
// two-tier): the narrative the analyst's own BYOK client wrote at conclusion.
type SummaryNarrativeBody struct {
	InvestigationRef string `json:"investigation_ref"`
	Narrative        string `json:"narrative"`
	GeneratorModel   string `json:"generator_model,omitempty"`
}

// summaryNarrative handles POST /api/knowledge/summary_narrative (analyst):
// the BYOK client enriches the concluded investigation's structured summary
// with an LLM narrative. The server never holds a model key — the two-tier
// split is the design (06 §3.2): server writes structure at conclusion,
// client writes prose. 404 (ErrNoSummary) means the post-conclusion pipeline
// hasn't written the baseline yet; clients retry briefly.
func (b *Backend) summaryNarrative(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
		var body SummaryNarrativeBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
			return
		}
		id, err := b.cfg.Knowledge.EnrichSummary(r.Context(), module.SingleTenantUUID, body.InvestigationRef, body.Narrative, body.GeneratorModel)
		if errors.Is(err, knowledge.ErrNoSummary) {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "summary_narrative: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"summary_id": id.String()})
	})
}

// importSOP handles POST /api/sops/import (analyst): upsert institutional
// knowledge from an external source (design/06 §2.4). Attribution keeps three
// facts distinct: the document's original author (from the payload), the
// source pointer (the re-import lineage key), and the importer (the
// authenticated principal — recorded here, never client-supplied).
func (b *Backend) importSOP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
		var body SOPImportBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
			return
		}
		claims, _ := authz.FromContext(r.Context())
		importer := claims.PreferredUsername
		if importer == "" {
			importer = claims.Subject
		}
		id, created, err := b.cfg.Knowledge.Import(r.Context(), knowledge.SOP{
			TenantID: module.SingleTenantUUID,
			Title:    body.Title, Body: body.Body, Tags: body.Tags,
			Recommendation: body.Recommendation,
			AuthorID:       body.Author,
			ImportedBy:     importer,
			Source: &knowledge.SOPSource{
				System: body.Source.System, URL: body.Source.URL, Version: body.Source.Version,
			},
		})
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "import sop: "+err.Error())
			return
		}
		status := http.StatusOK
		outcome := "revised"
		if created {
			status = http.StatusCreated
			outcome = "created"
		}
		writeJSON(w, status, map[string]string{"id": id.String(), "outcome": outcome})
	})
}

// SOPMarkdownBody is the workbench import payload (design/06 §2.4): a raw
// markdown file's bytes plus its name. The server parses frontmatter + body
// with the shared parser — the workbench never reimplements it, and richer
// formats are converted to markdown at the edge (pandoc) before arriving here.
type SOPMarkdownBody struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// importMarkdownSOP handles POST /api/sops/import_markdown (analyst): parse one
// markdown document and upsert it. The importer is the authenticated principal
// (recorded server-side, never client-supplied); the source pointer defaults to
// file:<filename> when the frontmatter omits it — the re-import lineage key.
func (b *Backend) importMarkdownSOP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
		var body SOPMarkdownBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
			return
		}
		name := body.Filename
		if name == "" {
			name = "untitled.md"
		}
		doc, err := sopdoc.Parse([]byte(body.Content), sopdoc.TitleStem(name))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "parse sop document: "+err.Error())
			return
		}
		if doc.SourceURL == "" {
			doc.SourceSystem = "file"
			doc.SourceURL = "file:" + name
		}
		claims, _ := authz.FromContext(r.Context())
		importer := claims.PreferredUsername
		if importer == "" {
			importer = claims.Subject
		}
		id, created, err := b.cfg.Knowledge.Import(r.Context(), knowledge.SOP{
			TenantID: module.SingleTenantUUID,
			Title:    doc.Title, Body: doc.Body, Tags: doc.Tags,
			Recommendation: doc.Recommendation,
			AuthorID:       doc.Author,
			ImportedBy:     importer,
			Source: &knowledge.SOPSource{
				System: doc.SourceSystem, URL: doc.SourceURL, Version: doc.SourceVersion,
			},
		})
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "import sop: "+err.Error())
			return
		}
		status, outcome := http.StatusOK, "revised"
		if created {
			status, outcome = http.StatusCreated, "created"
		}
		writeJSON(w, status, map[string]string{"id": id.String(), "outcome": outcome, "title": doc.Title})
	})
}

// sopsCollection routes /api/sops: POST create (analyst), GET list (reader).
func (b *Backend) sopsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.createSOP)
	case http.MethodGet:
		b.requireRolesOrDeny(w, r, anyReader, b.listSOPs)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// sopsItem routes /api/sops/{id}: GET (reader), PUT update (analyst),
// DELETE retire (analyst).
func (b *Backend) sopsItem(w http.ResponseWriter, r *http.Request) {
	id, ok := sopID(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		b.requireRolesOrDeny(w, r, anyReader, func(w http.ResponseWriter, r *http.Request) { b.getSOP(w, r, id) })
	case http.MethodPut:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) { b.updateSOP(w, r, id) })
	case http.MethodDelete:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) { b.retireSOP(w, r, id) })
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (b *Backend) createSOP(w http.ResponseWriter, r *http.Request) {
	var body SOPBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	claims, _ := authz.FromContext(r.Context())
	sop := knowledge.SOP{
		TenantID: module.SingleTenantUUID,
		Title:    body.Title, Body: body.Body, Tags: body.Tags,
		Recommendation: body.Recommendation,
		// Lightweight governance: published on write. author_id is set only when
		// the principal is a UUID (Keycloak sub); otherwise left NULL.
		Status:   knowledge.StatusPublished,
		AuthorID: uuidStringOrEmpty(claims.Subject),
	}
	id, err := b.cfg.Knowledge.Create(r.Context(), sop)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "create sop: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func (b *Backend) listSOPs(w http.ResponseWriter, r *http.Request) {
	includeRetired := r.URL.Query().Get("include_retired") == "true"
	sops, err := b.cfg.Knowledge.List(r.Context(), module.SingleTenantUUID, includeRetired)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list sops: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sops": sops})
}

func (b *Backend) getSOP(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	sop, err := b.cfg.Knowledge.Get(r.Context(), module.SingleTenantUUID, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "sop not found")
		return
	}
	writeJSON(w, http.StatusOK, sop)
}

func (b *Backend) updateSOP(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var body SOPBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	err := b.cfg.Knowledge.Update(r.Context(), module.SingleTenantUUID, id, body.Title, body.Body, body.Tags, body.Recommendation)
	if errors.Is(err, knowledge.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "sop not found or retired")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "update sop: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (b *Backend) retireSOP(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	err := b.cfg.Knowledge.Retire(r.Context(), module.SingleTenantUUID, id)
	if errors.Is(err, knowledge.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "sop not found or already retired")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "retire sop: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// anyReader is the role set that may read (viewer, analyst, auditor).
var anyReader = []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}

// sopID extracts and parses the {id} path segment of /api/sops/{id}.
func sopID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := strings.TrimPrefix(r.URL.Path, "/sops/")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid sop id")
		return uuid.Nil, false
	}
	return id, true
}

// uuidStringOrEmpty returns s if it parses as a UUID, else "" (the author_id
// column is UUID; a non-UUID principal is recorded as NULL for v0).
func uuidStringOrEmpty(s string) string {
	if _, err := uuid.Parse(s); err == nil {
		return s
	}
	return ""
}
