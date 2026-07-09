package capability

import (
	"strings"

	"github.com/sd-strax/reckon/identity"
)

// dnsNormalizer handles OCSF dns_activity (class_uid 4003) → STIX (§4.4): the
// queried domain, an SCO per answer (IPs for A/AAAA, domains for CNAME) with a
// resolves-to edge from the query, the requesting IP, and the host.
type dnsNormalizer struct{ r *identity.Resolver }

func (*dnsNormalizer) ClassUID() int { return 4003 }
func (*dnsNormalizer) Version() int  { return 1 }

func (n *dnsNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "dns_activity", n.Version())

	query := b.addDomain(pathStr(p, "query.hostname"))

	if answers, ok := lookupPath(p, "answers"); ok {
		if arr, ok := answers.([]any); ok {
			for _, item := range arr {
				am, ok := item.(map[string]any)
				if !ok {
					continue
				}
				rdata := toString(am["rdata"])
				switch strings.ToUpper(toString(am["type"])) {
				case "A", "AAAA":
					if ip := b.addIPValue(rdata); ip != "" {
						b.addRel(RelResolvesTo, query, ip)
					}
				case "CNAME":
					if cname := b.addDomain(rdata); cname != "" {
						b.addRel(RelResolvesTo, query, cname)
					}
				}
			}
		}
	}

	b.ipAddr("src_endpoint.ip") // requestor
	b.host("device")

	return b.finish(nil), nil
}
