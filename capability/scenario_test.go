package capability

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestShippedLateralMovementScenario loads the committed example config and the
// bundled fixture scenario and resolves every bound verb end to end — a
// regression guard that the shipped fixtures/config stay valid and wired.
func TestShippedLateralMovementScenario(t *testing.T) {
	cfg, err := LoadTenantConfig("../examples/capability/lateral-movement.yaml")
	if err != nil {
		t.Fatalf("load shipped config: %v", err)
	}
	res, catalog, err := BuildResolver(cfg, "../fixtures", uuid.New(), true)
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	// All four bound verbs advertise as available.
	avail := map[string]bool{}
	for _, v := range res.AvailableVerbs(catalog) {
		avail[v] = true
	}
	for _, v := range []string{"enumerate_logons", "get_process_ancestry", "get_network_connections", "search_alerts"} {
		if !avail[v] {
			t.Errorf("verb %s not available in shipped scenario", v)
		}
	}

	host := CallInput{Entity: map[string]any{"host": map[string]any{"hostname": "WIN-FILE01"}}}
	ctx := context.Background()

	// enumerate_logons → two logons on WIN-FILE01.
	logons, err := res.Resolve(ctx, "enumerate_logons", host)
	if err != nil {
		t.Fatal(err)
	}
	if logons.Coverage != CoverageComplete || len(logons.ObservedDataRefs) != 2 {
		t.Errorf("enumerate_logons: coverage=%q refs=%d; want COMPLETE/2", logons.Coverage, len(logons.ObservedDataRefs))
	}

	// get_process_ancestry → the powershell process + parent.
	proc, err := res.Resolve(ctx, "get_process_ancestry", host)
	if err != nil {
		t.Fatal(err)
	}
	if proc.Coverage != CoverageComplete || len(proc.EntityRefs) == 0 {
		t.Errorf("get_process_ancestry: coverage=%q entities=%d; want COMPLETE/>0", proc.Coverage, len(proc.EntityRefs))
	}

	// get_network_connections → the outbound exfil connection.
	net, err := res.Resolve(ctx, "get_network_connections", host)
	if err != nil {
		t.Fatal(err)
	}
	if net.Coverage != CoverageComplete {
		t.Errorf("get_network_connections: coverage=%q; want COMPLETE", net.Coverage)
	}

	// search_alerts → the detection, producing an INFERRED Indicator.
	alerts, err := res.Resolve(ctx, "search_alerts", CallInput{})
	if err != nil {
		t.Fatal(err)
	}
	var indicators int
	for _, nr := range alerts.Normalized {
		indicators += len(nr.Indicators)
	}
	if alerts.Coverage != CoverageComplete || indicators == 0 {
		t.Errorf("search_alerts: coverage=%q indicators=%d; want COMPLETE/>0", alerts.Coverage, indicators)
	}
}
