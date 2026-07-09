package capability

import "github.com/sd-strax/reckon/identity"

// networkNormalizer handles OCSF network_activity (class_uid 4001) → STIX
// (§4.3): source and destination IPs, an optional destination domain (with a
// resolves-to edge to the dst IP), a network-traffic SCO wrapping the
// connection, and the process/host if reported.
type networkNormalizer struct{ r *identity.Resolver }

func (*networkNormalizer) ClassUID() int { return 4001 }
func (*networkNormalizer) Version() int  { return 1 }

func (n *networkNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "network_activity", n.Version())

	src := b.ipAddr("src_endpoint.ip")
	dst := b.ipAddr("dst_endpoint.ip")

	if dom := b.addDomain(pathStr(p, "dst_endpoint.domain")); dom != "" && dst != "" {
		b.addRel(RelResolvesTo, dom, dst)
	}

	if src != "" || dst != "" {
		srcPort := pathInt(p, "src_endpoint.port")
		dstPort := pathInt(p, "dst_endpoint.port")
		proto := pathStr(p, "connection_info.protocol_name")
		b.addSCO(n.r.NetworkTraffic(src, dst, srcPort, dstPort, proto), identity.TypeNetworkTraffic, map[string]any{
			"src_ref":   string(src),
			"dst_ref":   string(dst),
			"src_port":  srcPort,
			"dst_port":  dstPort,
			"protocols": proto,
		})
	}

	if pid := pathInt(p, "process.pid"); pid != 0 {
		host := b.host("device")
		procID, _ := n.r.Process(host, pid, pathTime(p, "process.created_time"))
		b.addSCO(procID, identity.TypeProcess, map[string]any{"pid": pid})
	} else {
		b.host("device")
	}

	return b.finish(nil), nil
}
