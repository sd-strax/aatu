package capability

import (
	"testing"

	"github.com/sd-strax/reckon/identity"
)

// TestRegistryNormalizer (§4.6): host-scoped registry key + actor process, with
// activity in extensions.
func TestRegistryNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid":     1003,
		"time":          "2026-04-20T14:32:11Z",
		"activity_name": "Create",
		"reg_key":       map[string]any{"hive": "HKLM", "path": `Software\Microsoft\Windows\CurrentVersion\Run`},
		"reg_value":     map[string]any{"name": "Updater", "data": `C:\Temp\evil.exe`},
		"actor":         map[string]any{"process": map[string]any{"pid": 1234, "created_time": "2026-04-20T14:00:00Z"}},
		"device":        map[string]any{"hostname": "WS1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	bt := countTypes(res.SCOs)
	if bt[identity.TypeRegistryKey] != 1 || bt[identity.TypeProcess] != 1 || bt[identity.TypeHost] != 1 {
		t.Errorf("want 1 registry-key + 1 process + 1 host; got %v", bt)
	}
	if res.ObservedData[0].Extensions["activity"] != "Create" {
		t.Errorf("activity extension = %v; want Create", res.ObservedData[0].Extensions["activity"])
	}
}

// TestScheduledJobNormalizer (§4.7): host-scoped scheduled task + principal user.
func TestScheduledJobNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid": 1006,
		"time":      "2026-04-20T14:32:11Z",
		"job":       map[string]any{"name": "EvilTask", "path": `\Microsoft\Windows\EvilTask`, "command_line": "evil.exe", "user": map[string]any{"name": "SYSTEM"}},
		"device":    map[string]any{"hostname": "WS1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	bt := countTypes(res.SCOs)
	if bt[identity.TypeScheduledTask] != 1 || bt[identity.TypeUserAccount] != 1 || bt[identity.TypeHost] != 1 {
		t.Errorf("want 1 scheduled-task + 1 user + 1 host; got %v", bt)
	}
}

// TestModuleNormalizer (§4.8): module file + loading process, with a loads edge.
func TestModuleNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid": 1009,
		"time":      "2026-04-20T14:32:11Z",
		"module":    map[string]any{"file": map[string]any{"name": "evil.dll", "path": `C:\Temp\evil.dll`, "hashes": map[string]any{"SHA-256": "abcd"}}},
		"actor":     map[string]any{"process": map[string]any{"pid": 999, "created_time": "2026-04-20T14:00:00Z"}},
		"device":    map[string]any{"hostname": "WS1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if countTypes(res.SCOs)[identity.TypeFile] != 1 {
		t.Errorf("want 1 file SCO; got %v", countTypes(res.SCOs))
	}
	if !hasRel(res.Relationships, RelLoads) {
		t.Error("missing loads relationship (process → module)")
	}
}

// TestAccountChangeNormalizer (§4.9): target + initiator users, group membership.
func TestAccountChangeNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid":     3005,
		"time":          "2026-04-20T14:32:11Z",
		"activity_name": "GROUP_ADD",
		"user":          map[string]any{"name": "alice", "domain": "CONTOSO", "uid": "S-1-5-1"},
		"actor":         map[string]any{"user": map[string]any{"name": "admin", "domain": "CONTOSO", "uid": "S-1-5-500"}},
		"group":         map[string]any{"name": "Domain Admins", "domain": "contoso.com"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	bt := countTypes(res.SCOs)
	if bt[identity.TypeUserAccount] != 2 || bt[identity.TypeGroup] != 1 {
		t.Errorf("want 2 users + 1 group; got %v", bt)
	}
	if !hasRel(res.Relationships, RelMemberOfGroup) {
		t.Error("missing member-of-group relationship")
	}
	if res.ObservedData[0].Extensions["activity"] != "GROUP_ADD" {
		t.Errorf("activity = %v; want GROUP_ADD", res.ObservedData[0].Extensions["activity"])
	}
}

// TestEmailNormalizer (§4.10): message + addresses + attachment + url, with
// contains edges.
func TestEmailNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid": 4009,
		"time":      "2026-04-20T14:32:11Z",
		"email": map[string]any{
			"from":        "attacker@evil.example",
			"to":          []any{"alice@corp.com", "bob@corp.com"},
			"subject":     "Invoice",
			"message_uid": "<abc123@evil.example>",
			"attachments": []any{map[string]any{"name": "invoice.pdf.exe", "hashes": map[string]any{"SHA-256": "beef"}}},
			"urls":        []any{"https://evil.example/pay"},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	bt := countTypes(res.SCOs)
	if bt[identity.TypeEmailMessage] != 1 {
		t.Errorf("want 1 email-message; got %v", bt)
	}
	if bt[identity.TypeEmailAddr] != 3 { // from + 2 recipients
		t.Errorf("email-addr SCOs = %d; want 3", bt[identity.TypeEmailAddr])
	}
	if bt[identity.TypeFile] != 1 || bt[identity.TypeURL] != 1 {
		t.Errorf("want 1 attachment file + 1 url; got %v", bt)
	}
	var contains int
	for _, r := range res.Relationships {
		if r.Type == RelContains {
			contains++
		}
	}
	if contains != 2 { // attachment + url
		t.Errorf("contains relationships = %d; want 2", contains)
	}
}

// TestEmailURLNormalizer (§4.11): clicked url + clicker + stub message, with
// clicked and contains edges.
func TestEmailURLNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid": 4011,
		"time":      "2026-04-20T14:32:11Z",
		"url":       map[string]any{"url_string": "https://evil.example/pay"},
		"email":     map[string]any{"message_uid": "<abc123@evil.example>"},
		"actor":     map[string]any{"user": map[string]any{"name": "alice", "domain": "CORP", "uid": "S-1-5-1"}},
		"device":    map[string]any{"hostname": "WS1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	bt := countTypes(res.SCOs)
	if bt[identity.TypeURL] != 1 || bt[identity.TypeUserAccount] != 1 || bt[identity.TypeEmailMessage] != 1 {
		t.Errorf("want 1 url + 1 user + 1 email-message; got %v", bt)
	}
	if !hasRel(res.Relationships, RelClicked) || !hasRel(res.Relationships, RelContains) {
		t.Error("missing clicked or contains relationship")
	}
}

// TestEmailClickStitchesToMessage: the stub email-message from a click resolves
// to the same id as the full message from email_activity (message_id stitches).
func TestEmailClickStitchesToMessage(t *testing.T) {
	reg := testRegistry()
	mail, _ := reg.Normalize(makeEvent(map[string]any{
		"class_uid": 4009,
		"time":      "2026-04-20T14:32:11Z",
		"email":     map[string]any{"from": "attacker@evil.example", "message_uid": "<m1@evil.example>", "subject": "x"},
	}))
	click, _ := reg.Normalize(makeEvent(map[string]any{
		"class_uid": 4011,
		"time":      "2026-04-20T14:40:00Z",
		"url":       map[string]any{"url_string": "https://evil.example/x"},
		"email":     map[string]any{"message_uid": "<m1@evil.example>"},
		"actor":     map[string]any{"user": map[string]any{"name": "alice"}},
	}))
	if scoOfType(mail.SCOs, identity.TypeEmailMessage) != scoOfType(click.SCOs, identity.TypeEmailMessage) {
		t.Error("email click stub did not stitch to the full message by message_id")
	}
}
