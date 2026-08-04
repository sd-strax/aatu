package main

import "testing"

// mapAt navigates nested map[string]any, failing the test on a miss.
func mapAt(t *testing.T, m map[string]any, keys ...string) map[string]any {
	t.Helper()
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("expected map at %v, missing %q in %v", keys, k, cur)
		}
		cur = next
	}
	return cur
}

func TestNormalizeAuthEvent(t *testing.T) {
	// A genuine authentication event → OCSF 3002 with the engine's paths.
	in := `{"items":[{"eventType":"user.session.start","published":"2026-08-04T10:00:00Z",` +
		`"actor":{"id":"00uABC","alternateId":"alice@acme.com","type":"User"},` +
		`"client":{"ipAddress":"1.2.3.4"},"outcome":{"result":"SUCCESS"}}]}`
	evs, err := normalize("get_logs", in)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 3002 {
		t.Fatalf("want one class-3002 event, got %+v", evs)
	}
	if got := mapAt(t, evs[0].Raw, "actor", "user")["name"]; got != "alice@acme.com" {
		t.Errorf("actor.user.name = %v", got)
	}
	if got := mapAt(t, evs[0].Raw, "src_endpoint")["ip"]; got != "1.2.3.4" {
		t.Errorf("src_endpoint.ip = %v", got)
	}
	if got := evs[0].Raw["status"]; got != "SUCCESS" {
		t.Errorf("status = %v", got)
	}
}

func TestNormalizeAccountLifecycleEvent(t *testing.T) {
	// user.lifecycle.create → OCSF 3005 with target user + initiator.
	in := `{"items":[{"eventType":"user.lifecycle.create","published":"2026-08-03T16:29:52Z",` +
		`"actor":{"id":"00uADMIN","alternateId":"admin@acme.com"},` +
		`"target":[{"id":"00uNEW","type":"User","alternateId":"bob@acme.com","displayName":"Bob"}],` +
		`"outcome":{"result":"SUCCESS"}}]}`
	evs, err := normalize("get_logs", in)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 3005 {
		t.Fatalf("want one class-3005 event, got %+v", evs)
	}
	if got := mapAt(t, evs[0].Raw, "user")["name"]; got != "bob@acme.com" {
		t.Errorf("target user.name = %v", got)
	}
	if got := mapAt(t, evs[0].Raw, "user")["uid"]; got != "00uNEW" {
		t.Errorf("target user.uid = %v", got)
	}
	if got := mapAt(t, evs[0].Raw, "actor", "user")["name"]; got != "admin@acme.com" {
		t.Errorf("initiator = %v", got)
	}
}

func TestNormalizePrivilegeGrant(t *testing.T) {
	in := `{"items":[{"eventType":"user.account.privilege.grant","published":"2026-08-03T16:00:00Z",` +
		`"actor":{"id":"00uADMIN","alternateId":"admin@acme.com"},"displayMessage":"Grant user privilege",` +
		`"target":[{"id":"00uT","type":"User","alternateId":"eve@acme.com"}],"outcome":{"result":"SUCCESS"}}]}`
	evs, _ := normalize("get_logs", in)
	if len(evs) != 1 || evs[0].ClassUID != 3005 {
		t.Fatalf("want class-3005, got %+v", evs)
	}
	if got := evs[0].Raw["privileges"]; got != "Grant user privilege" {
		t.Errorf("privileges = %v", got)
	}
}

func TestNormalizeAdminEventStaysOpaque(t *testing.T) {
	// A config/admin event is NOT an authentication — must not be force-fit to 3002.
	in := `{"items":[{"eventType":"system.brand.create","published":"2026-08-03T16:29:52Z",` +
		`"actor":{"id":"00uADMIN","alternateId":"admin@acme.com"},"outcome":{"result":"SUCCESS"}}]}`
	evs, _ := normalize("get_logs", in)
	if len(evs) != 1 || evs[0].ClassUID != 0 {
		t.Fatalf("admin event should be opaque (class 0), got %+v", evs)
	}
}

func TestNormalizeUserLookup(t *testing.T) {
	in := `[{"id":"00uX","status":"ACTIVE","profile":{"login":"carol@acme.com","email":"carol@acme.com"}}]`
	evs, err := normalize("get_user", in)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].ClassUID != 3005 {
		t.Fatalf("want class-3005 user, got %+v", evs)
	}
	if got := mapAt(t, evs[0].Raw, "user")["name"]; got != "carol@acme.com" {
		t.Errorf("user.name = %v", got)
	}
}
