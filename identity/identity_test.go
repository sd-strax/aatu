package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	nsA = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	nsB = uuid.MustParse("22222222-2222-4222-8222-222222222222")
)

// splitID parses "<type>--<uuid>" and asserts the uuid is a valid version-5
// UUID (deterministic, SHA-1 based) unless allowRandom is set.
func splitID(t *testing.T, id STIXID) (string, uuid.UUID) {
	t.Helper()
	parts := strings.SplitN(string(id), "--", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed STIXID %q", id)
	}
	u, err := uuid.Parse(parts[1])
	if err != nil {
		t.Fatalf("STIXID %q has invalid uuid: %v", id, err)
	}
	return parts[0], u
}

// TestFormatAndVersion: every deterministic id is "<type>--<uuidv5>".
func TestFormatAndVersion(t *testing.T) {
	r := NewResolver(nsA)
	cases := map[string]STIXID{
		TypeIPv4Addr:     r.IPv4Addr("8.8.8.8"),
		TypeDomainName:   r.DomainName("example.com"),
		TypeEmailAddr:    r.EmailAddr("a@b.com"),
		TypeUserAccount:  r.UserAccount("contoso\\jdoe", "S-1-5", "windows-domain"),
		TypeHost:         r.Host(HostIdentity{Hostname: "win-dc01"}),
		TypeObservedData: r.ObservedData(1007, time.Now(), "fixture", 1, map[string]any{"a": 1}),
	}
	for wantType, id := range cases {
		gotType, u := splitID(t, id)
		if gotType != wantType {
			t.Errorf("id %q has type %q; want %q", id, gotType, wantType)
		}
		if u.Version() != 5 {
			t.Errorf("id %q is UUID v%d; want v5 (deterministic)", id, u.Version())
		}
	}
}

// TestDeterminism: identical inputs always produce the identical id.
func TestDeterminism(t *testing.T) {
	r := NewResolver(nsA)
	ip1, ip2 := r.IPv4Addr("8.8.8.8"), r.IPv4Addr("8.8.8.8")
	if ip1 != ip2 {
		t.Error("IPv4Addr not deterministic")
	}
	ts := time.Date(2026, 4, 20, 14, 32, 11, 0, time.UTC)
	host := r.Host(HostIdentity{Hostname: "h1"})
	p1, ok1 := r.Process(host, 4242, ts)
	p2, ok2 := r.Process(host, 4242, ts)
	if p1 != p2 || !ok1 || !ok2 {
		t.Errorf("Process not deterministic: %q/%v vs %q/%v", p1, ok1, p2, ok2)
	}
}

// TestTenantScoping: the same value in different tenant namespaces must produce
// different ids — stitching can never leak across tenants (§7.1).
func TestTenantScoping(t *testing.T) {
	ra, rb := NewResolver(nsA), NewResolver(nsB)
	if ra.IPv4Addr("8.8.8.8") == rb.IPv4Addr("8.8.8.8") {
		t.Error("same IP in different tenants collided")
	}
	if ra.DomainName("evil.com") == rb.DomainName("evil.com") {
		t.Error("same domain in different tenants collided")
	}
}

// TestCanonicalizationEquivalence: values that differ only by case, whitespace,
// default port, query order, or trailing dot must resolve to the same id.
func TestCanonicalizationEquivalence(t *testing.T) {
	r := NewResolver(nsA)
	eq := []struct {
		name string
		a, b STIXID
	}{
		{"ipv6 case", r.IPv6Addr("2001:DB8::1"), r.IPv6Addr("2001:db8::1")},
		{"ip whitespace", r.IPv4Addr(" 8.8.8.8 "), r.IPv4Addr("8.8.8.8")},
		{"domain case+dot", r.DomainName("Example.COM."), r.DomainName("example.com")},
		{"url scheme/host/port/query", r.URL("HTTP://Example.com:80/p?b=2&a=1"), r.URL("http://example.com/p?a=1&b=2")},
		{"url ipv6 host keeps brackets", r.URL("http://[2001:DB8::1]:80/x"), r.URL("http://[2001:db8::1]/x")},
		{"email case", r.EmailAddr("Alice@Contoso.com"), r.EmailAddr("alice@contoso.com")},
		{"user case", r.UserAccount("CONTOSO\\Alice", "S-1", "windows-domain"), r.UserAccount("contoso\\alice", "s-1", "windows-domain")},
		{"host domain/hostname case", r.Host(HostIdentity{Domain: "CORP", Hostname: "WS1"}), r.Host(HostIdentity{Domain: "corp", Hostname: "ws1"})},
		{"mac format", r.Host(HostIdentity{MAC: "00-1A-2B-3C-4D-5E"}), r.Host(HostIdentity{MAC: "00:1a:2b:3c:4d:5e"})},
		{"registry case", r.RegistryKey("x-host--1", "HKLM", "Software\\Run", "Val"), r.RegistryKey("x-host--1", "hklm", "software\\run", "Val")},
	}
	for _, c := range eq {
		if c.a != c.b {
			t.Errorf("%s: expected equal ids, got %q vs %q", c.name, c.a, c.b)
		}
	}
}

// TestDistinctnessAcrossType: the same literal value under different object
// types must not collide.
func TestDistinctnessAcrossType(t *testing.T) {
	r := NewResolver(nsA)
	if r.IPv4Addr("1.2.3.4") == r.DomainName("1.2.3.4") {
		t.Error("ipv4 and domain with same value collided")
	}
}

// TestFileHashPriority: SHA-256 wins over SHA-1/MD5; hash matching is
// case/format-insensitive; absent hashes fall back to name/dir/size.
func TestFileHashPriority(t *testing.T) {
	r := NewResolver(nsA)
	full := r.File(FileIdentity{Hashes: map[string]string{"SHA-256": "ABC", "SHA-1": "def", "MD5": "123"}})
	sha256Only := r.File(FileIdentity{Hashes: map[string]string{"sha256": "abc"}})
	if full != sha256Only {
		t.Errorf("SHA-256 not prioritized / not case-insensitive: %q vs %q", full, sha256Only)
	}

	sha1Only := r.File(FileIdentity{Hashes: map[string]string{"SHA1": "def"}})
	if full == sha1Only {
		t.Error("file with SHA-256 collided with file identified by SHA-1 only")
	}

	// The algorithm participates in identity: an identical digest string under
	// a different algorithm is a different file, never a merge.
	if r.File(FileIdentity{Hashes: map[string]string{"sha1": "abc"}}) ==
		r.File(FileIdentity{Hashes: map[string]string{"md5": "abc"}}) {
		t.Error("same digest under different algorithms collided")
	}

	fallback1 := r.File(FileIdentity{Name: "evil.exe", ParentDirectory: "C:\\Temp", Size: 100})
	fallback2 := r.File(FileIdentity{Name: "evil.exe", ParentDirectory: "C:\\Temp", Size: 100})
	if fallback1 != fallback2 {
		t.Error("file name/dir/size fallback not deterministic")
	}
	if fallback1 == r.File(FileIdentity{Name: "evil.exe", ParentDirectory: "C:\\Temp", Size: 101}) {
		t.Error("different size produced same file id")
	}
}

// TestProcessDeviation covers the three specified behaviors: stitch within the
// same one-second bucket, split across seconds, and anonymous-random when
// created_time is zero.
func TestProcessDeviation(t *testing.T) {
	r := NewResolver(nsA)
	host := r.Host(HostIdentity{Hostname: "h1"})
	base := time.Date(2026, 4, 20, 14, 32, 11, 0, time.UTC)

	// Same second, sub-second differences → same id.
	a, okA := r.Process(host, 900, base.Add(200*time.Millisecond))
	b, okB := r.Process(host, 900, base.Add(900*time.Millisecond))
	if !okA || !okB || a != b {
		t.Errorf("processes in same second did not stitch: %q vs %q", a, b)
	}

	// Next second → different id (false-split behavior, as specified).
	c, _ := r.Process(host, 900, base.Add(time.Second))
	if a == c {
		t.Error("processes across a second boundary stitched; want split")
	}

	// Zero created_time → random, non-deterministic, ok=false.
	z1, okZ1 := r.Process(host, 900, time.Time{})
	z2, okZ2 := r.Process(host, 900, time.Time{})
	if okZ1 || okZ2 {
		t.Error("zero created_time should be non-deterministic (ok=false)")
	}
	if z1 == z2 {
		t.Error("anonymous processes should get distinct random ids")
	}
	if typ, _ := splitID(t, z1); typ != TypeProcess {
		t.Errorf("anonymous process id has type %q; want %q", typ, TypeProcess)
	}

	// Empty host_ref → anonymous too: hashing ("", pid, time) would false-merge
	// same-pid processes across different hosts.
	h1, okH1 := r.Process("", 900, base)
	h2, okH2 := r.Process("", 900, base)
	if okH1 || okH2 {
		t.Error("empty host_ref should be non-deterministic (ok=false)")
	}
	if h1 == h2 {
		t.Error("hostless processes should get distinct random ids, never merge")
	}
}

// TestUserAccountTypeNotFolded: account_login case folds, but a different
// account_type is a deliberately distinct account (no implicit merge).
func TestUserAccountTypeNotFolded(t *testing.T) {
	r := NewResolver(nsA)
	cloud := r.UserAccount("alice@corp.com", "", "cloud")
	domain := r.UserAccount("alice@corp.com", "", "windows-domain")
	if cloud == domain {
		t.Error("cloud and windows-domain accounts with same login collided; account_type must not fold")
	}
}

// TestObservedDataIdentity: same (class, second, tool, payload) → same id;
// changing any input changes the id.
func TestObservedDataIdentity(t *testing.T) {
	r := NewResolver(nsA)
	ts := time.Date(2026, 4, 20, 14, 32, 11, 500_000, time.UTC)
	payload := map[string]any{"src": "1.2.3.4", "n": 3}

	base := r.ObservedData(4001, ts, "crowdstrike", 1, payload)
	sameSecond := r.ObservedData(4001, ts.Add(400*time.Millisecond), "crowdstrike", 1, payload)
	if base != sameSecond {
		t.Error("ObservedData not stable within the same second")
	}
	if base == r.ObservedData(4001, ts, "splunk", 1, payload) {
		t.Error("different source_tool produced same ObservedData id")
	}
	if base == r.ObservedData(4001, ts, "crowdstrike", 1, map[string]any{"src": "9.9.9.9"}) {
		t.Error("different payload produced same ObservedData id")
	}
	if base == r.ObservedData(2004, ts, "crowdstrike", 1, payload) {
		t.Error("different class_uid produced same ObservedData id")
	}
	// Re-normalization: a newer normalizer version must mint a NEW id (§4.13) —
	// old ObservedData stays valid, the new id reflects the new interpretation.
	if base == r.ObservedData(4001, ts, "crowdstrike", 2, payload) {
		t.Error("newer normalizer version produced the same ObservedData id; re-normalization would be a no-op")
	}
}
