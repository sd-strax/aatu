package sopdoc

import (
	"strings"
	"testing"
)

func TestParse_Frontmatter(t *testing.T) {
	doc, err := Parse([]byte(`---
title: Ransomware Containment Runbook
author: Jane Okoro
tags: [ransomware, T1486]
recommendation: isolate
source:
  system: confluence
  url: https://wiki.example.com/RUNBOOK-42
  version: "3.2"
---
Isolate first, preserve volatile evidence.
`), "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "Ransomware Containment Runbook" || doc.Author != "Jane Okoro" {
		t.Errorf("attribution wrong: %+v", doc)
	}
	if len(doc.Tags) != 2 || doc.Recommendation != "isolate" {
		t.Errorf("tags/recommendation wrong: %+v", doc)
	}
	if doc.SourceSystem != "confluence" || doc.SourceURL != "https://wiki.example.com/RUNBOOK-42" || doc.SourceVersion != "3.2" {
		t.Errorf("source wrong: %+v", doc)
	}
	if !strings.Contains(doc.Body, "Isolate first") || strings.Contains(doc.Body, "---") {
		t.Errorf("body wrong: %q", doc.Body)
	}
}

func TestParse_TitleFallbacks(t *testing.T) {
	// Heading wins when frontmatter has no title.
	doc, err := Parse([]byte("# Phishing Triage\n\nQuarantine the message."), "stem-name")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "Phishing Triage" {
		t.Errorf("title should come from the heading: %q", doc.Title)
	}
	// No heading, no frontmatter → the fallback (filename stem).
	doc, err = Parse([]byte("Reset the mailbox and review inbox rules."), "bec response")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "bec response" {
		t.Errorf("title should fall back to the stem: %q", doc.Title)
	}
	// Source is NOT defaulted here — the caller owns that.
	if doc.SourceURL != "" {
		t.Errorf("Parse must not default source.url: %q", doc.SourceURL)
	}
}

func TestParse_Errors(t *testing.T) {
	if _, err := Parse([]byte(""), "x"); err == nil {
		t.Error("empty body accepted")
	}
	if _, err := Parse([]byte("---\ntitle: x\n"), "x"); err == nil {
		t.Error("unterminated frontmatter accepted")
	}
	if _, err := Parse([]byte("---\n: : :\n---\nbody\n"), "x"); err == nil {
		t.Error("malformed YAML accepted")
	}
}

func TestTitleStem(t *testing.T) {
	if got := TitleStem("/a/b/ransomware-containment.md"); got != "ransomware containment" {
		t.Errorf("TitleStem = %q", got)
	}
}
