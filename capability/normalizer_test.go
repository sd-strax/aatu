package capability

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/identity"
)

var testNS = uuid.MustParse("33333333-3333-4333-8333-333333333333")

func testRegistry() *Registry {
	return NewRegistry(identity.NewResolver(testNS))
}

// makeEvent builds an OcsfEvent from a raw OCSF payload, minting a telemetry id
// and reading class/time from the payload (as the adapter path would).
func makeEvent(payload map[string]any) OcsfEvent {
	return OcsfEvent{
		ID:         uuid.Must(uuid.NewV7()),
		ClassUID:   toInt(payload["class_uid"]),
		Time:       toTime(payload["time"]),
		RecordedAt: time.Now(),
		SourceTool: "fixture:s",
		Payload:    payload,
	}
}

func processPayload() map[string]any {
	return map[string]any{
		"class_uid": 1007,
		"time":      "2026-04-20T14:32:11Z",
		"process": map[string]any{
			"pid":          4242,
			"name":         "powershell.exe",
			"cmd_line":     "powershell -enc ZQBjAGgAbwA=",
			"created_time": "2026-04-20T14:32:11Z",
			"file": map[string]any{
				"path":   `C:\Windows\System32\powershell.exe`,
				"name":   "powershell.exe",
				"hashes": map[string]any{"SHA-256": "ABC123"},
			},
			"parent_process": map[string]any{
				"pid":          1000,
				"name":         "explorer.exe",
				"created_time": "2026-04-20T14:00:00Z",
			},
		},
		"device": map[string]any{"hostname": "WIN-DC01", "domain": "CONTOSO"},
		"actor":  map[string]any{"user": map[string]any{"name": "jdoe", "domain": "CONTOSO", "uid": "S-1-5-21"}},
	}
}

// TestProcessNormalizer covers §4.1: five SCOs (process, parent, file, host,
// user), one ObservedData referencing all, and a parent-process-of relationship.
func TestProcessNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(processPayload()))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	byType := map[string]int{}
	for _, s := range res.SCOs {
		byType[s.Type]++
	}
	want := map[string]int{
		identity.TypeProcess:     2, // subject + parent
		identity.TypeFile:        1,
		identity.TypeHost:        1,
		identity.TypeUserAccount: 1,
	}
	for typ, n := range want {
		if byType[typ] != n {
			t.Errorf("SCO type %s: got %d; want %d", typ, byType[typ], n)
		}
	}

	if len(res.ObservedData) != 1 {
		t.Fatalf("got %d ObservedData; want 1", len(res.ObservedData))
	}
	od := res.ObservedData[0]
	if len(od.ObjectRefs) != 5 {
		t.Errorf("ObservedData.object_refs = %d; want 5", len(od.ObjectRefs))
	}
	if od.NumberObserved != 1 {
		t.Errorf("number_observed = %d; want 1", od.NumberObserved)
	}
	if od.Provenance.DerivationMode != DerivationDirect {
		t.Errorf("derivation_mode = %q; want DIRECT", od.Provenance.DerivationMode)
	}

	// Exactly one parent-process-of relationship, parent → child.
	var rels int
	for _, r := range res.Relationships {
		if r.Type == RelParentProcessOf {
			rels++
		}
	}
	if rels != 1 {
		t.Errorf("parent-process-of relationships = %d; want 1", rels)
	}

	// Every SCO has an extracted-from edge; the ObservedData has a derived-from.
	var extracted, derived int
	for _, e := range res.Edges {
		switch e.Type {
		case EdgeExtractedFrom:
			extracted++
		case EdgeDerivedFrom:
			derived++
		}
	}
	if extracted != 5 || derived != 1 {
		t.Errorf("edges: extracted=%d derived=%d; want 5 and 1", extracted, derived)
	}
}

func authPayload(host string) map[string]any {
	return map[string]any{
		"class_uid":    3002,
		"time":         "2026-04-20T14:35:02Z",
		"actor":        map[string]any{"user": map[string]any{"name": "jdoe", "domain": "CONTOSO", "uid": "S-1-5-21"}},
		"dst_endpoint": map[string]any{"hostname": host, "domain": "CONTOSO"},
		"src_endpoint": map[string]any{"ip": "10.0.4.55"},
		"logon_type":   "RemoteInteractive",
		"status":       "SUCCESS",
	}
}

// TestAuthNormalizer covers §4.2: user, host, source-IP SCOs; an
// x-authenticated-to relationship; and logon_type/status in the ObservedData
// extensions.
func TestAuthNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(authPayload("WIN-FILE01")))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	byType := map[string]int{}
	for _, s := range res.SCOs {
		byType[s.Type]++
	}
	if byType[identity.TypeUserAccount] != 1 || byType[identity.TypeHost] != 1 || byType[identity.TypeIPv4Addr] != 1 {
		t.Errorf("auth SCO types = %v; want 1 user, 1 host, 1 ipv4", byType)
	}

	var authed int
	for _, r := range res.Relationships {
		if r.Type == RelAuthenticatedTo {
			authed++
		}
	}
	if authed != 1 {
		t.Errorf("x-authenticated-to relationships = %d; want 1", authed)
	}

	od := res.ObservedData[0]
	if od.Extensions["logon_type"] != "RemoteInteractive" || od.Extensions["status"] != "SUCCESS" {
		t.Errorf("ObservedData extensions = %v; want logon_type/status", od.Extensions)
	}
}

// TestOpaqueFallback: an unregistered class yields a single opaque ObservedData
// with no object_refs and a derived-from edge (§4.13).
func TestOpaqueFallback(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid": 9999,
		"time":      "2026-04-20T14:32:11Z",
		"weird":     "vendor payload",
	}))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(res.SCOs) != 0 {
		t.Errorf("opaque produced %d SCOs; want 0", len(res.SCOs))
	}
	if len(res.ObservedData) != 1 || len(res.ObservedData[0].ObjectRefs) != 0 {
		t.Errorf("opaque ObservedData not empty/singular: %+v", res.ObservedData)
	}
	if len(res.Edges) != 1 || res.Edges[0].Type != EdgeDerivedFrom {
		t.Errorf("opaque edges = %+v; want one derived-from", res.Edges)
	}
}

// TestCrossEventStitching is the whole point of the identity layer: the same
// host seen through a process event and an authentication event resolves to the
// SAME x-host SCO id — the graph stitches instead of fragmenting.
func TestCrossEventStitching(t *testing.T) {
	reg := testRegistry()

	procRes, err := reg.Normalize(makeEvent(processPayload()))
	if err != nil {
		t.Fatal(err)
	}
	authRes, err := reg.Normalize(makeEvent(authPayload("WIN-DC01")))
	if err != nil {
		t.Fatal(err)
	}

	procHost := scoOfType(procRes.SCOs, identity.TypeHost)
	authHost := scoOfType(authRes.SCOs, identity.TypeHost)
	if procHost == "" || authHost == "" {
		t.Fatalf("missing host SCO: proc=%q auth=%q", procHost, authHost)
	}
	if procHost != authHost {
		t.Errorf("same host did not stitch: process=%q auth=%q", procHost, authHost)
	}

	// The same user (CONTOSO\jdoe, same SID) stitches too. Note the contract:
	// user-account identity includes user_id, so tools must report a consistent
	// SID for stitching — a tool that omits it produces a distinct SCO (§7.2).
	if u1, u2 := scoOfType(procRes.SCOs, identity.TypeUserAccount), scoOfType(authRes.SCOs, identity.TypeUserAccount); u1 != u2 {
		t.Errorf("same user did not stitch: process=%q auth=%q", u1, u2)
	}
}

// TestNormalizeDeterminism: normalizing the same OCSF payload twice (distinct
// telemetry ids) yields the same ObservedData id — deduplicable across ingests.
func TestNormalizeDeterminism(t *testing.T) {
	reg := testRegistry()
	a, _ := reg.Normalize(makeEvent(processPayload()))
	b, _ := reg.Normalize(makeEvent(processPayload()))
	if a.ObservedData[0].ID != b.ObservedData[0].ID {
		t.Errorf("ObservedData id not stable across ingests: %q vs %q", a.ObservedData[0].ID, b.ObservedData[0].ID)
	}
}

// TestEndToEndFixtureToStix wires the fixture adapter to the registry: replay
// OCSF events, convert to OcsfEvents, normalize, and confirm STIX comes out.
func TestEndToEndFixtureToStix(t *testing.T) {
	a := newTestFixture(t, twoLogonsPlusOther)
	resp, err := a.Invoke(context.Background(), "replay", map[string]any{
		ParamVerb: "enumerate_logons",
		"target":  map[string]any{"hostname": "WIN-FILE01"},
		"outcome": "SUCCESS",
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := testRegistry()
	var totalOD, totalSCO int
	for _, evt := range resp.ToOcsfEvents(time.Now()) {
		res, err := reg.Normalize(evt)
		if err != nil {
			t.Fatalf("normalize %v: %v", evt.ClassUID, err)
		}
		totalOD += len(res.ObservedData)
		totalSCO += len(res.SCOs)
	}
	if totalOD != 2 {
		t.Errorf("got %d ObservedData from 2 logons; want 2", totalOD)
	}
	if totalSCO == 0 {
		t.Error("no SCOs produced from the fixture logons")
	}
}

func scoOfType(scos []SCO, typ string) identity.STIXID {
	for _, s := range scos {
		if s.Type == typ {
			return s.ID
		}
	}
	return ""
}
