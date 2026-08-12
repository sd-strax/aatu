package server

import (
	"encoding/json"
	"io/fs"
	"path"
	"testing"

	reckon "github.com/sd-strax/reckon"
	"github.com/sd-strax/reckon/internal/sopdoc"
)

// TestDemoPack_SOPsParse: every embedded demo SOP parses and carries the fields
// the seed loader hands to knowledge.Import — title/body (required) and a source
// URL (the re-import lineage key). A malformed pack file would otherwise only
// surface at seed time on a live stack.
func TestDemoPack_SOPsParse(t *testing.T) {
	entries, err := fs.ReadDir(reckon.DemoFS, reckon.DemoKnowledgeSOPs)
	if err != nil {
		t.Fatalf("read sop pack: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("demo SOP pack is empty")
	}
	for _, e := range entries {
		raw, err := reckon.DemoFS.ReadFile(path.Join(reckon.DemoKnowledgeSOPs, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		doc, err := sopdoc.Parse(raw, sopdoc.TitleStem(e.Name()))
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		if doc.Title == "" || doc.Body == "" {
			t.Errorf("%s: title/body required by knowledge.Import (title=%q, body empty=%v)", e.Name(), doc.Title, doc.Body == "")
		}
		if doc.SourceURL == "" {
			t.Errorf("%s: source.url required as the re-import lineage key", e.Name())
		}
	}
}

// TestDemoPack_CasesParse: every embedded prior-case summary unmarshals into the
// demoCase DTO and carries the fields knowledge.WriteSummary requires
// (investigation_ref, title, summary_text). This is the DB-free half of the
// seed; the write itself is exercised by the lifecycle path.
func TestDemoPack_CasesParse(t *testing.T) {
	entries, err := fs.ReadDir(reckon.DemoFS, reckon.DemoKnowledgeCases)
	if err != nil {
		t.Fatalf("read case pack: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("demo case pack is empty")
	}
	for _, e := range entries {
		raw, err := reckon.DemoFS.ReadFile(path.Join(reckon.DemoKnowledgeCases, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var dc demoCase
		if err := json.Unmarshal(raw, &dc); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		if dc.InvestigationRef == "" || dc.Title == "" || dc.SummaryText == "" {
			t.Errorf("%s: investigation_ref/title/summary_text required by WriteSummary", e.Name())
		}
	}
}
