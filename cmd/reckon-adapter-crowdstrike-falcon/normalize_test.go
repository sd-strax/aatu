package main

import (
	"strings"
	"testing"
)

func TestNormalizeDetectionsToFindings(t *testing.T) {
	text := `{"resources":[{"composite_id":"abc:ind:123","description":"Credential theft via LSASS access","severity_name":"High","tactic":"Credential Access","technique":"OS Credential Dumping","device":{"hostname":"WIN-FILE01"},"created_timestamp":"2026-08-01T12:00:00Z"}]}`
	evs, err := normalize("search_detections", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 2004 {
		t.Fatalf("want one detection_finding, got %+v", evs)
	}
	f, _ := evs[0].Raw["finding"].(map[string]any)
	if f["uid"] != "falcon:abc:ind:123" {
		t.Errorf("uid = %v", f["uid"])
	}
	if title, _ := f["title"].(string); !strings.Contains(title, "Credential theft") {
		t.Errorf("title = %q", title)
	}
	if types, _ := f["types"].([]string); len(types) != 2 {
		t.Errorf("types = %v, want tactic+technique", f["types"])
	}
	if evs[0].Raw["hostname"] != "WIN-FILE01" {
		t.Errorf("hostname = %v", evs[0].Raw["hostname"])
	}
	if evs[0].Time.IsZero() {
		t.Error("created_timestamp must parse")
	}
}

func TestNormalizeHostsAreOpaque(t *testing.T) {
	text := `{"resources":[{"device_id":"d1","hostname":"WIN-FILE01","platform_name":"Windows"}]}`
	evs, err := normalize("search_hosts", text)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 0 {
		t.Fatalf("hosts must be opaque (class 0), got %+v", evs)
	}
	if evs[0].Raw["hostname"] != "WIN-FILE01" {
		t.Errorf("hostname not surfaced: %v", evs[0].Raw)
	}
}

func TestInferIOCType(t *testing.T) {
	cases := map[string]string{
		"44d88612fea8a8f36de82e1278abb02f":                                 "md5",
		"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "sha256",
		"198.51.100.7":     "ipv4",
		"2001:db8::1":      "ipv6",
		"evil.example.com": "domain",
		"not_an_ioc":       "",
	}
	for in, want := range cases {
		if got := inferIOCType(in); got != want {
			t.Errorf("inferIOCType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIOCIDsExtraction(t *testing.T) {
	ids := iocIDs(`{"resources":["id-1","id-2"]}`)
	if len(ids) != 2 || ids[0] != "id-1" {
		t.Errorf("string ids = %v", ids)
	}
	ids = iocIDs(`{"resources":[{"id":"id-3","value":"evil.example.com"}]}`)
	if len(ids) != 1 || ids[0] != "id-3" {
		t.Errorf("object ids = %v", ids)
	}
	if ids := iocIDs(`{"resources":[]}`); len(ids) != 0 {
		t.Errorf("empty = %v", ids)
	}
}
