package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDoc(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseSOPDocument_Frontmatter(t *testing.T) {
	path := writeDoc(t, "ransomware.md", `---
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
`)
	doc, err := parseSOPDocument(path)
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

func TestParseSOPDocument_PlainMarkdownFallbacks(t *testing.T) {
	path := writeDoc(t, "phishing-triage.md", "# Phishing Triage\n\nQuarantine the message.\n")
	doc, err := parseSOPDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "Phishing Triage" {
		t.Errorf("title should come from the heading: %q", doc.Title)
	}
	// The source URL — the re-import lineage key — defaults to the file path.
	if doc.SourceSystem != "file" || !strings.HasPrefix(doc.SourceURL, "file:") || !strings.HasSuffix(doc.SourceURL, "phishing-triage.md") {
		t.Errorf("source fallback wrong: %s %s", doc.SourceSystem, doc.SourceURL)
	}
}

func TestParseSOPDocument_NoHeadingUsesStem(t *testing.T) {
	path := writeDoc(t, "bec-response.md", "Reset the mailbox and review inbox rules.\n")
	doc, err := parseSOPDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "bec response" {
		t.Errorf("title should come from the filename stem: %q", doc.Title)
	}
}

func TestParseSOPDocument_Errors(t *testing.T) {
	if _, err := parseSOPDocument(writeDoc(t, "empty.md", "")); err == nil {
		t.Error("empty body accepted")
	}
	if _, err := parseSOPDocument(writeDoc(t, "bad.md", "---\ntitle: x\n")); err == nil {
		t.Error("unterminated frontmatter accepted")
	}
	if _, err := parseSOPDocument(writeDoc(t, "badyaml.md", "---\n: : :\n---\nbody\n")); err == nil {
		t.Error("malformed YAML accepted")
	}
}

func TestCollectImportFiles(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"a.md", "b.markdown", "c.txt", "skip.pdf", "sub/d.md"} {
		path := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := collectImportFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Errorf("collected %d files, want 4 (pdf skipped): %v", len(files), files)
	}
}
