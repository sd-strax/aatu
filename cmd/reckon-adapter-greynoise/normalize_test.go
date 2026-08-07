package main

import (
	"strings"
	"testing"
)

// Fixtures follow the vendor's shipped v3 response schema (0.5.4):
// classification/actor/last_seen/tags nested under
// internet_scanner_intelligence; tags are objects with a name.

func TestNormalizeMaliciousToDetectionFinding(t *testing.T) {
	text := `{"ip":"45.83.64.1","internet_scanner_intelligence":{"seen":true,"classification":"malicious","actor":"Mirai","last_seen":"2026-08-01","tags":[{"id":"t1","slug":"mirai","name":"Mirai","category":"actor"},{"id":"t2","slug":"ssh-bruteforcer","name":"SSH Bruteforcer","category":"activity"}]},"business_service_intelligence":{"found":false}}`
	evs, err := normalize("lookup-ip-context", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	e := evs[0]
	if e.ClassUID != 2004 {
		t.Fatalf("class_uid = %d, want 2004 (detection_finding)", e.ClassUID)
	}
	finding, _ := e.Raw["finding"].(map[string]any)
	if finding["uid"] != "greynoise:45.83.64.1" {
		t.Errorf("finding.uid = %v", finding["uid"])
	}
	if title, _ := finding["title"].(string); !strings.Contains(title, "Mirai") {
		t.Errorf("finding.title = %q, want it to name the actor", title)
	}
	if types, _ := finding["types"].([]string); len(types) != 2 || types[0] != "Mirai" {
		t.Errorf("finding.types = %v, want the tag NAMES", finding["types"])
	}
	if e.Time.IsZero() {
		t.Error("date-only last_seen must parse")
	}
	// The nested evidence must carry the IP so the engine mints an ipv4-addr SCO.
	ev, _ := e.Raw["evidence"].(map[string]any)
	se, _ := ev["src_endpoint"].(map[string]any)
	if se["ip"] != "45.83.64.1" {
		t.Errorf("evidence src_endpoint.ip = %v, want the IP", se["ip"])
	}
}

func TestNormalizeBenignToOpaqueNoIndicator(t *testing.T) {
	text := `{"ip":"8.8.8.8","internet_scanner_intelligence":{"seen":false,"classification":"benign"},"business_service_intelligence":{"found":true,"name":"Google Public DNS","trust_level":"1"}}`
	evs, err := normalize("lookup-ip-context", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 0 {
		t.Fatalf("benign must be opaque (class 0), got %+v", evs)
	}
	if evs[0].Raw["reputation"] != "benign" {
		t.Errorf("reputation = %v, want benign", evs[0].Raw["reputation"])
	}
}

func TestNormalizeGnqlWrapperUnwraps(t *testing.T) {
	text := `{"data":[{"ip":"1.2.3.4","internet_scanner_intelligence":{"classification":"malicious"}}],"request_metadata":{"count":1}}`
	evs, err := normalize("gnql-query", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 2004 {
		t.Fatalf("gnql data wrapper must unwrap to a finding, got %+v", evs)
	}
}

func TestNormalizeBSIIsBenignEnrichment(t *testing.T) {
	text := `{"ip":"8.8.8.8","business_service_intelligence":{"found":true,"category":"public_dns","name":"Google Public DNS","trust_level":"1"}}`
	evs, err := normalize("bsi-lookup", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 0 {
		t.Fatalf("BSI must be opaque enrichment, got %+v", evs)
	}
	if evs[0].Raw["reputation"] != "benign" {
		t.Errorf("BSI reputation = %v, want benign", evs[0].Raw["reputation"])
	}
}
