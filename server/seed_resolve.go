package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/identity"
)

// seedResolution is the outcome of interpreting a raw analyst-typed seed: the
// aggregate Seed to persist, plus the human display line the workbench renders
// (the chip and the derived title). display never contains a STIX id.
type seedResolution struct {
	Seed    aggregate.Seed
	Display string
}

// hexHash matches a bare md5/sha1/sha256 digest (the three algorithms the
// identity resolver ranks). Any other length is not treated as a hash.
var hexHash = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// classifySeedKind applies the two rules an analyst can hold in their head: a
// value that contains whitespace or ends in a question mark is a question
// (a hunt); anything else is an entity (a host/IP/hash to root on). It never
// tries to extract an entity out of a sentence — the host enters the graph the
// moment the agent touches it anyway (design/ui/02 §2.7).
func classifySeedKind(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	if strings.ContainsAny(v, " \t\n") || strings.HasSuffix(v, "?") {
		return aggregate.SeedQuestion
	}
	return aggregate.SeedEntity
}

// resolveSeedInput turns a raw analyst identifier into a persistable seed. kind
// is the human's confirmed choice ("entity" | "question"); when empty it is
// inferred by classifySeedKind. The entity path mints the STIX id through the
// identity resolver (the single arbiter of ids, 03 §7) so a human never types
// or sees one. Alerts do not flow through here — they carry an explicit
// id+source seed built by the caller.
func resolveSeedInput(res *identity.Resolver, value, kind string) (seedResolution, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return seedResolution{}, fmt.Errorf("empty seed")
	}
	if kind == "" {
		kind = classifySeedKind(v)
	}

	switch kind {
	case aggregate.SeedQuestion:
		return seedResolution{
			Seed:    aggregate.Seed{Type: aggregate.SeedQuestion, HypothesisStatement: v},
			Display: v,
		}, nil

	case aggregate.SeedEntity:
		if res == nil {
			return seedResolution{}, fmt.Errorf("identity resolver unavailable")
		}
		if strings.ContainsAny(v, " \t\n") {
			return seedResolution{}, fmt.Errorf("%q looks like a question, not a host/IP/hash", v)
		}
		ref, label := resolveEntityToken(res, v)
		return seedResolution{
			Seed: aggregate.Seed{
				Type:             aggregate.SeedEntity,
				EntityRef:        ref,
				EntityIdentifier: v,
			},
			Display: label + " " + v,
		}, nil

	default:
		return seedResolution{}, fmt.Errorf("unknown seed kind %q (entity | question)", kind)
	}
}

// deriveSeedTitle turns a seed's display line into an investigation title,
// clipped so a long hunt question does not become an unwieldy title. Clipped by
// RUNES, not bytes — a byte slice could split a multi-byte character and stamp
// an invalid-UTF-8 title.
func deriveSeedTitle(display string) string {
	t := strings.TrimSpace(display)
	const max = 80
	if r := []rune(t); len(r) > max {
		t = strings.TrimSpace(string(r[:max])) + "…"
	}
	return t
}

// seedSummaryOf is the nil-safe Summary() used in the create response.
func seedSummaryOf(s *aggregate.Seed) string {
	if s == nil {
		return ""
	}
	return s.Summary()
}

// resolveEntityToken mints the STIX id for a single artifact token and returns
// a human type label for the chip. The sub-classification (IP → IPv4/IPv6, a
// 32/40/64-hex string → file, everything else → host) mirrors the identity
// resolver's own shaping; the label is display only.
func resolveEntityToken(res *identity.Resolver, token string) (ref, label string) {
	if ip := net.ParseIP(token); ip != nil {
		if ip.To4() != nil {
			return string(res.IPv4Addr(token)), "IP"
		}
		return string(res.IPv6Addr(token)), "IP"
	}
	if hexHash.MatchString(token) {
		switch len(token) {
		case 32:
			return string(res.File(identity.FileIdentity{Hashes: map[string]string{"md5": token}})), "file"
		case 40:
			return string(res.File(identity.FileIdentity{Hashes: map[string]string{"sha1": token}})), "file"
		case 64:
			return string(res.File(identity.FileIdentity{Hashes: map[string]string{"sha256": token}})), "file"
		}
	}
	return string(res.Host(identity.HostIdentity{Hostname: token})), "host"
}
