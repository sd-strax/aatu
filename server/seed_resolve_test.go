package server

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/identity"
)

func TestClassifySeedKind(t *testing.T) {
	cases := map[string]string{
		"WIN-FILE01":                         aggregate.SeedEntity,
		"185.220.101.5":                      aggregate.SeedEntity,
		"e3b0c44298fc1c149afbf4c8996fb924":   aggregate.SeedEntity, // md5-length hex
		"is anyone abusing service accounts": aggregate.SeedQuestion,
		"ransomware?":                        aggregate.SeedQuestion, // single token but a question
		"  ":                                 "",
	}
	for in, want := range cases {
		if got := classifySeedKind(in); got != want {
			t.Errorf("classifySeedKind(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestResolveSeedInput(t *testing.T) {
	res := identity.NewResolver(uuid.MustParse("6f1b2c3d-0000-4000-8000-000000000001"))

	// A hostname → entity seed rooted on a minted x-host id, with the human
	// identifier carried and a "host …" display.
	host, err := resolveSeedInput(res, "WIN-FILE01", "")
	if err != nil {
		t.Fatal(err)
	}
	if host.Seed.Type != aggregate.SeedEntity ||
		!strings.HasPrefix(host.Seed.EntityRef, "x-host--") ||
		host.Seed.EntityIdentifier != "WIN-FILE01" ||
		host.Display != "host WIN-FILE01" {
		t.Fatalf("host seed = %+v (display %q)", host.Seed, host.Display)
	}

	// An IP → ipv4-addr; a hash → file; each labelled for the chip.
	ip, _ := resolveSeedInput(res, "185.220.101.5", "")
	if !strings.HasPrefix(ip.Seed.EntityRef, "ipv4-addr--") || ip.Display != "IP 185.220.101.5" {
		t.Errorf("ip seed = %+v (display %q)", ip.Seed, ip.Display)
	}
	sha := strings.Repeat("a", 64)
	hash, _ := resolveSeedInput(res, sha, "")
	if !strings.HasPrefix(hash.Seed.EntityRef, "file--") || !strings.HasPrefix(hash.Display, "file ") {
		t.Errorf("hash seed = %+v (display %q)", hash.Seed, hash.Display)
	}

	// A sentence → question seed, verbatim.
	q, _ := resolveSeedInput(res, "Is anyone abusing service accounts for RDP?", "")
	if q.Seed.Type != aggregate.SeedQuestion || q.Seed.HypothesisStatement != "Is anyone abusing service accounts for RDP?" {
		t.Errorf("question seed = %+v", q.Seed)
	}

	// The human's confirmed kind overrides inference: force a single token to
	// be a question (the correction toggle).
	forced, _ := resolveSeedInput(res, "WIN-FILE01", aggregate.SeedQuestion)
	if forced.Seed.Type != aggregate.SeedQuestion || forced.Seed.HypothesisStatement != "WIN-FILE01" {
		t.Errorf("forced-question seed = %+v", forced.Seed)
	}

	// The same entity always mints the same id (determinism, 03 §7).
	again, _ := resolveSeedInput(res, "win-file01", aggregate.SeedEntity)
	if again.Seed.EntityRef != host.Seed.EntityRef {
		t.Errorf("host id not deterministic across case: %q vs %q", again.Seed.EntityRef, host.Seed.EntityRef)
	}

	// Forcing entity on a sentence is refused rather than minting a nonsense host.
	if _, err := resolveSeedInput(res, "two words", aggregate.SeedEntity); err == nil {
		t.Error("forcing entity on a multi-word value should error")
	}

	// No resolver → entity resolution fails cleanly (not a panic).
	if _, err := resolveSeedInput(nil, "WIN-FILE01", aggregate.SeedEntity); err == nil {
		t.Error("nil resolver should error on entity resolution")
	}
}
