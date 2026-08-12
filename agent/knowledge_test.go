package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// knowledgeBackend serves canned implicit-retrieval results.
func knowledgeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	f := newFakeBackend(t)
	prev := f.override
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/knowledge/recall_sops":
			_, _ = w.Write([]byte(`{"results":[
			  {"sop_id":"sop-1","title":"Ransomware Containment","excerpt":"Isolate first.","score":0.4,"match_rationale":"keyword match"}
			],"coverage":"COMPLETE"}`))
			return true
		case "/api/knowledge/recall_similar_investigations":
			_, _ = w.Write([]byte(`{"results":[
			  {"investigation_ref":"grouping--near","title":"Prior RDP pivot","excerpt":"WIN-FILE01.","score":0.94,"band":"NEAR_DUPLICATE","match_rationale":"cosine 0.94"},
			  {"investigation_ref":"grouping--far","title":"Unrelated BEC","excerpt":"mailbox.","score":0.1,"band":"DISTINCT","match_rationale":"cosine 0.10"}
			],"coverage":"COMPLETE"}`))
			return true
		}
		if prev != nil {
			return prev(w, r)
		}
		return false
	}
	return f
}

// seedInvestigation makes the fake backend's investigation carry a seed +
// posture, so refreshContext's implicit retrieval has a query.
func (f *fakeBackend) withInvestigation(inv Investigation) {
	f.investigation = &inv
}

func newKnowledgeSession(t *testing.T, posture string) (*Session, *fakeBackend) {
	t.Helper()
	f := knowledgeBackend(t)
	f.withInvestigation(Investigation{
		AggregateID: "inv-1", Title: "RDP lateral movement", Status: "ACTIVE",
		SeedSummary: "entity WIN-FILE01", KnowledgeInjection: posture,
	})
	s, err := NewSession(context.Background(), Config{
		Backend: f.client(), LLM: &scriptedLLM{}, InvestigationID: "inv-1",
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s, f
}

// TestImplicitRetrieval_OptIn: under the default posture, retrieval runs and is
// surfaced with relevance signals, but NOTHING enters the system prompt until
// the analyst includes it.
func TestImplicitRetrieval_OptIn(t *testing.T) {
	s, _ := newKnowledgeSession(t, injectionOptIn)

	items := s.RetrievedKnowledge()
	if len(items) != 3 {
		t.Fatalf("expected 3 surfaced items, got %d: %+v", len(items), items)
	}
	for _, k := range items {
		if k.Included {
			t.Errorf("opt_in must default every item OUT: %+v", k)
		}
		if k.Rationale == "" {
			t.Errorf("relevance rationale missing: %+v", k)
		}
	}
	if strings.Contains(s.System(), "relevant SOPs") || strings.Contains(s.System(), "Similar past investigations") {
		t.Error("opt_in leaked knowledge into the prompt before the analyst included anything")
	}

	// The analyst pulls two in; the prompt now carries exactly those.
	s.SetIncludedKnowledge([]string{"sop-1", "grouping--near"})
	sys := s.System()
	if !strings.Contains(sys, "Ransomware Containment") || !strings.Contains(sys, "Prior RDP pivot") {
		t.Errorf("included knowledge not in prompt:\n%s", sys)
	}
	if strings.Contains(sys, "Unrelated BEC") {
		t.Error("un-included item leaked into the prompt")
	}
}

// TestImplicitRetrieval_Auto: strong matches default in; DISTINCT stays out.
func TestImplicitRetrieval_Auto(t *testing.T) {
	s, _ := newKnowledgeSession(t, injectionAuto)

	byRef := map[string]KnowledgeItem{}
	for _, k := range s.RetrievedKnowledge() {
		byRef[k.Ref] = k
	}
	if !byRef["sop-1"].Included {
		t.Error("auto: a matched SOP should default in")
	}
	if !byRef["grouping--near"].Included {
		t.Error("auto: a NEAR_DUPLICATE case should default in")
	}
	if byRef["grouping--far"].Included {
		t.Error("auto: a DISTINCT case should stay surfaced-but-off")
	}
	sys := s.System()
	if !strings.Contains(sys, "Ransomware Containment") || !strings.Contains(sys, "Prior RDP pivot") {
		t.Errorf("auto-included knowledge not in prompt:\n%s", sys)
	}
	if strings.Contains(sys, "Unrelated BEC") {
		t.Error("DISTINCT case leaked into the prompt under auto")
	}

	// The analyst can veto a strong match — it leaves the context.
	s.SetIncludedKnowledge([]string{"grouping--near"}) // drop sop-1
	if strings.Contains(s.System(), "Ransomware Containment") {
		t.Error("vetoed SOP still in the prompt")
	}
}

// TestImplicitRetrieval_IncludedIsConsulted: included knowledge is folded into
// the turn's consulted provenance (design/06 §6).
func TestImplicitRetrieval_IncludedIsConsulted(t *testing.T) {
	s, f := newKnowledgeSession(t, injectionAuto)
	s.SetIncludedKnowledge([]string{"sop-1", "grouping--near"})

	if _, err := s.Turn(context.Background(), "look into this"); err != nil {
		t.Fatalf("turn: %v", err)
	}
	calls := f.callsTo("/api/interpretations")
	if len(calls) == 0 {
		t.Fatal("no interpretation committed")
	}
	var body InterpretationRequest
	if err := json.Unmarshal(calls[len(calls)-1].Body, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.ConsultedSOPs) != 1 || body.ConsultedSOPs[0].SOPID != "sop-1" {
		t.Errorf("included SOP not recorded as consulted: %+v", body.ConsultedSOPs)
	}
	if len(body.ConsultedSimilar) != 1 || body.ConsultedSimilar[0].InvestigationRef != "grouping--near" {
		t.Errorf("included case not recorded as consulted: %+v", body.ConsultedSimilar)
	}
}
