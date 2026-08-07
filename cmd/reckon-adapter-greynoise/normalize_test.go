package main

import (
	"strings"
	"testing"
)

func TestNormalizeMaliciousToDetectionFinding(t *testing.T) {
	text := `{"ip":"45.83.64.1","seen":true,"classification":"malicious","actor":"Mirai","tags":["Mirai","SSH Bruteforcer"],"last_seen":"2026-08-01T00:00:00Z"}`
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
	// The nested evidence must carry the IP so the engine mints an ipv4-addr SCO.
	ev, _ := e.Raw["evidence"].(map[string]any)
	se, _ := ev["src_endpoint"].(map[string]any)
	if se["ip"] != "45.83.64.1" {
		t.Errorf("evidence src_endpoint.ip = %v, want the IP", se["ip"])
	}
}

func TestNormalizeBenignToOpaqueNoIndicator(t *testing.T) {
	text := `{"ip":"8.8.8.8","seen":false,"classification":"benign","last_seen":"2026-08-01T00:00:00Z"}`
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
	text := `{"data":[{"ip":"1.2.3.4","classification":"malicious"}],"count":1}`
	evs, err := normalize("gnql-stats", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 2004 {
		t.Fatalf("gnql wrapper must unwrap to a finding, got %+v", evs)
	}
}

func TestNormalizeRiotIsBenignEnrichment(t *testing.T) {
	text := `{"ip":"8.8.8.8","riot":true,"category":"public_dns","name":"Google Public DNS","trust_level":"1"}`
	evs, err := normalize("riot-lookup", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 0 {
		t.Fatalf("RIOT must be opaque enrichment, got %+v", evs)
	}
	if evs[0].Raw["reputation"] != "benign" {
		t.Errorf("RIOT reputation = %v, want benign", evs[0].Raw["reputation"])
	}
}
