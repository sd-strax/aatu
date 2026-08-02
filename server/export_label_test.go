package server

import "testing"

// TestStixLabel derives readable labels from persisted STIX payloads (the raw
// UUID a ticket reader can't use → the identifying value they can).
func TestStixLabel(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		payload string
		want    string
	}{
		{"host by hostname", "x-host", `{"properties":{"domain":"CONTOSO","hostname":"WIN-FILE01"}}`, "WIN-FILE01"},
		{"host falls back to name", "x-host", `{"properties":{"name":"srv-01"}}`, "srv-01"},
		{"ipv4 value", "ipv4-addr", `{"properties":{"value":"10.0.0.5"}}`, "10.0.0.5"},
		{"user by display name", "user-account", `{"properties":{"display_name":"Mike Torres","user_id":"mtorres"}}`, "Mike Torres"},
		{"user falls back to user_id", "user-account", `{"properties":{"user_id":"svc_backup"}}`, "svc_backup"},
		{"file by name", "file", `{"properties":{"name":"evil.exe"}}`, "evil.exe"},
		{"process command line collapses whitespace", "process", "{\"properties\":{\"command_line\":\"powershell   -enc\\n  AAA\"}}", "powershell -enc AAA"},
		{"process numeric pid formatted", "process", `{"properties":{"pid":4321}}`, "pid 4321"},
		{"unknown type, no identifier", "x-mystery", `{"properties":{"foo":"bar"}}`, ""},
		{"malformed payload", "x-host", `not json`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stixLabel(c.typ, []byte(c.payload)); got != c.want {
				t.Errorf("stixLabel(%s) = %q; want %q", c.typ, got, c.want)
			}
		})
	}
}
