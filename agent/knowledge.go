package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Knowledge-injection postures (design/06 §5.1, mirrors config.Knowledge).
const (
	injectionOptIn = "opt_in"
	injectionAuto  = "auto"
)

// implicitRecallLimit bounds each implicit retrieval (design/06 §5.1: "top N").
// Small: the rail is a curation surface, not a search results page, and each
// included item spends context.
const implicitRecallLimit = 3

// KnowledgeItem is one piece of institutional knowledge surfaced by implicit
// retrieval (design/06 §5.1), carrying the relevance signals the analyst uses
// to gauge it — the substrate already scores and explains, this just surfaces
// it. Kind is "sop" or "case"; Ref is the sop id / prior investigation ref.
type KnowledgeItem struct {
	Kind      string  `json:"kind"`
	Ref       string  `json:"ref"`
	Title     string  `json:"title"`
	Excerpt   string  `json:"excerpt"`
	Score     float64 `json:"score"`
	Band      string  `json:"band,omitempty"` // similarity band (case only)
	Rationale string  `json:"rationale,omitempty"`
	// Included is the item's current inclusion in the model's context. The dial
	// sets the initial value (opt_in: false; auto: strong matches true); the
	// analyst's toggles override it via SetIncludedKnowledge.
	Included bool `json:"included"`
}

// retrieveImplicit runs the §5.1 implicit recalls (SOPs + similar cases)
// against the seed context and sets each item's default inclusion per the
// posture dial. Best-effort: a knowledge layer that is off or failing leaves
// the rail empty, never blocks the session (retrieval is context, not control).
func (s *Session) retrieveImplicit(ctx context.Context, inv Investigation) {
	query := strings.TrimSpace(inv.SeedSummary)
	if query == "" {
		query = strings.TrimSpace(inv.Title)
	}
	s.injection = inv.KnowledgeInjection
	if s.injection == "" {
		s.injection = injectionOptIn
	}
	if query == "" {
		s.retrieved = nil
		return
	}

	var items []KnowledgeItem
	items = append(items, s.recallSOPItems(ctx, query)...)
	items = append(items, s.recallSimilarItems(ctx, query)...)
	auto := s.injection == injectionAuto
	for i := range items {
		items[i].Included = auto && isStrong(items[i])
	}
	s.retrieved = items
}

// isStrong marks a retrieved item worth auto-including under "auto" (design/06
// §5.1). SOPs are curated org doctrine already relevance-filtered by recall, so
// a match is strong. Cases ride the substrate band: NEAR_DUPLICATE/RELATED are
// strong, DISTINCT ("nearest neighbors are far") stays surfaced-but-off.
func isStrong(k KnowledgeItem) bool {
	if k.Kind == "sop" {
		return true
	}
	return k.Band == "NEAR_DUPLICATE" || k.Band == "RELATED"
}

func (s *Session) recallSOPItems(ctx context.Context, query string) []KnowledgeItem {
	raw, err := s.backend.RecallSOPs(ctx, map[string]any{"query": query, "limit": implicitRecallLimit})
	if err != nil {
		return nil
	}
	var res struct {
		Results []struct {
			SOPID          string  `json:"sop_id"`
			Title          string  `json:"title"`
			Excerpt        string  `json:"excerpt"`
			Score          float64 `json:"score"`
			MatchRationale string  `json:"match_rationale"`
		} `json:"results"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return nil
	}
	var out []KnowledgeItem
	for _, r := range res.Results {
		if r.SOPID == "" {
			continue
		}
		out = append(out, KnowledgeItem{
			Kind: "sop", Ref: r.SOPID, Title: r.Title, Excerpt: r.Excerpt,
			Score: r.Score, Rationale: r.MatchRationale,
		})
	}
	return out
}

func (s *Session) recallSimilarItems(ctx context.Context, query string) []KnowledgeItem {
	raw, err := s.backend.RecallSimilar(ctx, map[string]any{"query": query, "limit": implicitRecallLimit})
	if err != nil {
		return nil
	}
	var res struct {
		Results []struct {
			InvestigationRef string  `json:"investigation_ref"`
			Title            string  `json:"title"`
			Excerpt          string  `json:"excerpt"`
			Score            float64 `json:"score"`
			Band             string  `json:"band"`
			MatchRationale   string  `json:"match_rationale"`
		} `json:"results"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return nil
	}
	var out []KnowledgeItem
	for _, r := range res.Results {
		if r.InvestigationRef == "" {
			continue
		}
		out = append(out, KnowledgeItem{
			Kind: "case", Ref: r.InvestigationRef, Title: r.Title, Excerpt: r.Excerpt,
			Score: r.Score, Band: r.Band, Rationale: r.MatchRationale,
		})
	}
	return out
}

// RetrievedKnowledge returns what implicit retrieval surfaced this session,
// with each item's current inclusion — the data the workbench's knowledge rail
// renders. A copy, so the caller cannot mutate session state.
func (s *Session) RetrievedKnowledge() []KnowledgeItem {
	out := make([]KnowledgeItem, len(s.retrieved))
	copy(out, s.retrieved)
	return out
}

// SetIncludedKnowledge sets which retrieved items are included in the model's
// context (the analyst's curation, keyed by Ref). Unknown refs are ignored;
// items not named are excluded — the caller passes the full included set. The
// system prompt is rebuilt so the next turn reflects the choice.
func (s *Session) SetIncludedKnowledge(refs []string) {
	want := make(map[string]bool, len(refs))
	for _, r := range refs {
		want[r] = true
	}
	for i := range s.retrieved {
		s.retrieved[i].Included = want[s.retrieved[i].Ref]
	}
	sops, cases := s.includedKnowledge()
	s.system = systemPrompt(s.investigation, s.caps, s.hyps, sops, cases)
}

// includedKnowledge returns the currently-included items, cases and SOPs
// separated for the two prompt sections, each ordered by score.
func (s *Session) includedKnowledge() (sops, cases []KnowledgeItem) {
	for _, k := range s.retrieved {
		if !k.Included {
			continue
		}
		if k.Kind == "sop" {
			sops = append(sops, k)
		} else {
			cases = append(cases, k)
		}
	}
	sort.SliceStable(sops, func(i, j int) bool { return sops[i].Score > sops[j].Score })
	sort.SliceStable(cases, func(i, j int) bool { return cases[i].Score > cases[j].Score })
	return sops, cases
}

// knowledgeConsulted folds the INCLUDED implicit-retrieval items into the
// turn's consulted maps (design/06 §6): the analyst putting a SOP/case into the
// model's context is a consultation, recorded like an explicit recall. Merged
// with the model's own recalls, best score kept — Used stays the conservative
// "did the final text reference it" decided later.
func (s *Session) knowledgeConsulted() {
	for _, k := range s.retrieved {
		if !k.Included {
			continue
		}
		switch k.Kind {
		case "sop":
			if prev, ok := s.consulted[k.Ref]; !ok || k.Score > prev.RetrievalScore {
				s.consulted[k.Ref] = ConsultedSOP{SOPID: k.Ref, Title: k.Title, RetrievalScore: k.Score}
			}
		case "case":
			if prev, ok := s.consultedSimilar[k.Ref]; !ok || k.Score > prev.RetrievalScore {
				s.consultedSimilar[k.Ref] = ConsultedSimilarInvestigation{
					InvestigationRef: k.Ref, Title: k.Title, RetrievalScore: k.Score, Band: k.Band,
				}
			}
		}
	}
}

// renderKnowledgeSections writes the §5.1 system-prompt sections for the
// included knowledge. Empty when nothing is included (opt_in before the
// analyst pulls anything in).
func renderKnowledgeSections(b *strings.Builder, sops, cases []KnowledgeItem) {
	if len(sops) > 0 {
		b.WriteString("\n## Your organization's relevant SOPs for cases like this\n\n")
		b.WriteString("The analyst has included these standing procedures as context. Follow them where they apply; cite one only if you actually build on it.\n")
		for _, k := range sops {
			fmt.Fprintf(b, "\n### %s (sop %s)\n%s\n", k.Title, k.Ref, k.Excerpt)
		}
	}
	if len(cases) > 0 {
		b.WriteString("\n## Similar past investigations in your tenant\n\n")
		b.WriteString("The analyst has included these prior concluded cases as context — what your organization did before. They are precedent, not proof; verify against this investigation's own evidence.\n")
		for _, k := range cases {
			band := ""
			if k.Band != "" {
				band = " · " + k.Band
			}
			fmt.Fprintf(b, "\n### %s (case %s%s)\n%s\n", k.Title, k.Ref, band, k.Excerpt)
		}
	}
}
