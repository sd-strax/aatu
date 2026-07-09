package capability

import (
	"testing"

	"github.com/sd-strax/reckon/identity"
)

// TestNetworkNormalizer covers §4.3: src/dst IPs, a dst domain with a
// resolves-to edge, and a network-traffic SCO.
func TestNetworkNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid":       4001,
		"time":            "2026-04-20T14:32:11Z",
		"src_endpoint":    map[string]any{"ip": "10.0.0.5", "port": 51000},
		"dst_endpoint":    map[string]any{"ip": "93.184.216.34", "port": 443, "domain": "example.com"},
		"connection_info": map[string]any{"protocol_name": "tcp"},
		"device":          map[string]any{"hostname": "WS1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	byType := countTypes(res.SCOs)
	if byType[identity.TypeIPv4Addr] != 2 {
		t.Errorf("ipv4 SCOs = %d; want 2 (src+dst)", byType[identity.TypeIPv4Addr])
	}
	if byType[identity.TypeDomainName] != 1 || byType[identity.TypeNetworkTraffic] != 1 {
		t.Errorf("want 1 domain + 1 network-traffic; got %v", byType)
	}
	if !hasRel(res.Relationships, RelResolvesTo) {
		t.Error("missing resolves-to (domain → dst IP)")
	}
}

// TestDNSNormalizer covers §4.4: the query domain resolves-to each A answer.
func TestDNSNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid": 4003,
		"time":      "2026-04-20T14:32:11Z",
		"query":     map[string]any{"hostname": "evil.example.com"},
		"answers": []any{
			map[string]any{"type": "A", "rdata": "1.2.3.4"},
			map[string]any{"type": "A", "rdata": "5.6.7.8"},
			map[string]any{"type": "CNAME", "rdata": "cdn.example.net"},
		},
		"src_endpoint": map[string]any{"ip": "10.0.0.9"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	byType := countTypes(res.SCOs)
	// query + CNAME = 2 domains; 2 A answers + 1 requestor = 3 IPs.
	if byType[identity.TypeDomainName] != 2 {
		t.Errorf("domain SCOs = %d; want 2 (query + cname)", byType[identity.TypeDomainName])
	}
	if byType[identity.TypeIPv4Addr] != 3 {
		t.Errorf("ipv4 SCOs = %d; want 3 (2 answers + requestor)", byType[identity.TypeIPv4Addr])
	}
	var resolves int
	for _, r := range res.Relationships {
		if r.Type == RelResolvesTo {
			resolves++
		}
	}
	if resolves != 3 { // 2 A + 1 CNAME
		t.Errorf("resolves-to edges = %d; want 3", resolves)
	}
}

// TestFileNormalizer covers §4.5: file + parent directory (with a
// parent-directory-of edge), actor process, host, and activity in extensions.
func TestFileNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid":     1001,
		"time":          "2026-04-20T14:32:11Z",
		"activity_name": "Create",
		"file": map[string]any{
			"name":   "evil.dll",
			"path":   `C:\Windows\Temp\evil.dll`,
			"hashes": map[string]any{"SHA-256": "deadbeef"},
		},
		"actor":  map[string]any{"process": map[string]any{"pid": 1234, "created_time": "2026-04-20T14:00:00Z"}},
		"device": map[string]any{"hostname": "WS1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	byType := countTypes(res.SCOs)
	if byType[identity.TypeFile] != 1 || byType[identity.TypeDirectory] != 1 {
		t.Errorf("want 1 file + 1 directory; got %v", byType)
	}
	if byType[identity.TypeProcess] != 1 || byType[identity.TypeHost] != 1 {
		t.Errorf("want 1 process + 1 host; got %v", byType)
	}
	if !hasRel(res.Relationships, RelParentDirectoryOf) {
		t.Error("missing parent-directory-of edge")
	}
	if res.ObservedData[0].Extensions["activity"] != "Create" {
		t.Errorf("activity extension = %v; want Create", res.ObservedData[0].Extensions["activity"])
	}
}

func countTypes(scos []SCO) map[string]int {
	m := map[string]int{}
	for _, s := range scos {
		m[s.Type]++
	}
	return m
}

func hasRel(rels []Relationship, typ string) bool {
	for _, r := range rels {
		if r.Type == typ {
			return true
		}
	}
	return false
}
