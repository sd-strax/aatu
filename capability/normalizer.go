package capability

import (
	"net"
	"strings"
	"time"

	"github.com/sd-strax/reckon/identity"
)

// Normalizer turns one OCSF event into interpretation-layer objects. It is a
// pure function of the event (given its resolver); normalizers are registered
// by class_uid (§4.13). Identity is never computed here directly — normalizers
// delegate to the identity resolver, the single arbiter (§7.4).
type Normalizer interface {
	ClassUID() int
	Version() int
	Normalize(evt OcsfEvent) (NormalizationResult, error)
}

// Registry dispatches OcsfEvents to the normalizer registered for their class,
// falling back to an opaque default for unrecognized classes (§4.13). One
// Registry is built per tenant, bound to that tenant's identity resolver.
type Registry struct {
	resolver *identity.Resolver
	byClass  map[int]Normalizer
	def      Normalizer
}

// NewRegistry builds a Registry bound to a tenant resolver and pre-registers the
// v0 normalizers. Adding a class is a Register call, not a change to dispatch.
func NewRegistry(r *identity.Resolver) *Registry {
	reg := &Registry{resolver: r, byClass: make(map[int]Normalizer)}
	reg.def = &opaqueNormalizer{r: r}
	reg.Register(&processNormalizer{r: r})
	reg.Register(&authNormalizer{r: r})
	reg.Register(&networkNormalizer{r: r})
	reg.Register(&dnsNormalizer{r: r})
	reg.Register(&fileActivityNormalizer{r: r})
	reg.Register(&registryNormalizer{r: r})
	reg.Register(&scheduledJobNormalizer{r: r})
	reg.Register(&moduleNormalizer{r: r})
	reg.Register(&accountChangeNormalizer{r: r})
	reg.Register(&emailNormalizer{r: r})
	reg.Register(&emailURLNormalizer{r: r})
	// detection_finding recurses into the registry to normalize nested
	// evidence, so it takes a back-reference to reg.
	reg.Register(&detectionNormalizer{r: r, reg: reg})
	return reg
}

// Register adds a normalizer, keyed by its ClassUID. A later registration for
// the same class replaces the earlier one.
func (reg *Registry) Register(n Normalizer) { reg.byClass[n.ClassUID()] = n }

// Normalize dispatches to the class's normalizer, or the opaque default when no
// normalizer is registered for the event's class.
func (reg *Registry) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	if n, ok := reg.byClass[evt.ClassUID]; ok {
		return n.Normalize(evt)
	}
	return reg.def.Normalize(evt)
}

// HandledClasses returns the class_uids with a dedicated normalizer, sorted for
// stable introspection/testing.
func (reg *Registry) HandledClasses() []int {
	out := make([]int, 0, len(reg.byClass))
	for c := range reg.byClass {
		out = append(out, c)
	}
	// small n; insertion order-independent, so a simple sort keeps it stable
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// opaqueNormalizer is the §4.13 default: it emits a single ObservedData with no
// object_refs and a derived-from edge, so the LLM still sees the raw payload
// without typed entities.
type opaqueNormalizer struct{ r *identity.Resolver }

func (*opaqueNormalizer) ClassUID() int { return 0 }
func (*opaqueNormalizer) Version() int  { return 1 }
func (n *opaqueNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	return newBuilder(n.r, evt, "opaque", n.Version()).finish(nil), nil
}

// --- result builder ----------------------------------------------------------

// resultBuilder accumulates a NormalizationResult, handling the boilerplate
// shared by every normalizer: minting the ObservedData, wiring extracted-from /
// derived-from edges, and deduping repeated entities within one event.
type resultBuilder struct {
	r    *identity.Resolver
	evt  OcsfEvent
	prov Provenance

	seen  map[identity.STIXID]bool
	scos  []SCO
	rels  []Relationship
	edges []Edge
	refs  []identity.STIXID
}

func newBuilder(r *identity.Resolver, evt OcsfEvent, normalizer string, version int) *resultBuilder {
	return &resultBuilder{
		r:    r,
		evt:  evt,
		seen: make(map[identity.STIXID]bool),
		prov: Provenance{
			DerivationMode:    DerivationDirect,
			Tool:              evt.SourceTool,
			Normalizer:        normalizer,
			NormalizerVersion: version,
			ObservedAt:        evt.Time,
		},
	}
}

// addSCO records an SCO plus its extracted-from edge and object_ref, deduping if
// the same id was already added for this event. Returns the id for convenience.
func (b *resultBuilder) addSCO(id identity.STIXID, typ string, props map[string]any) identity.STIXID {
	if id == "" || b.seen[id] {
		return id
	}
	b.seen[id] = true
	b.scos = append(b.scos, SCO{ID: id, Type: typ, Properties: props, Provenance: b.prov})
	b.edges = append(b.edges, Edge{Type: EdgeExtractedFrom, SourceRef: id, OcsfEventID: b.evt.ID.String()})
	b.refs = append(b.refs, id)
	return id
}

// addRel records a STIX relationship between two already-extracted objects.
func (b *resultBuilder) addRel(relType string, src, tgt identity.STIXID) {
	if src == "" || tgt == "" {
		return
	}
	b.rels = append(b.rels, Relationship{
		ID:         b.r.Relationship(relType, src, tgt),
		Type:       relType,
		SourceRef:  src,
		TargetRef:  tgt,
		Provenance: b.prov,
	})
}

// finish mints the ObservedData over the collected refs, adds its derived-from
// edge, and returns the assembled result. extensions carries custom fields
// (e.g. logon_type/status).
func (b *resultBuilder) finish(extensions map[string]any) NormalizationResult {
	odID := b.r.ObservedData(b.evt.ClassUID, b.evt.Time, b.evt.SourceTool, b.prov.NormalizerVersion, b.evt.Payload)
	b.edges = append(b.edges, Edge{Type: EdgeDerivedFrom, SourceRef: odID, OcsfEventID: b.evt.ID.String()})
	return NormalizationResult{
		ObservedData: []ObservedData{{
			ID:             odID,
			FirstObserved:  b.evt.Time,
			LastObserved:   b.evt.Time,
			NumberObserved: 1,
			ObjectRefs:     b.refs,
			Extensions:     extensions,
			Provenance:     b.prov,
		}},
		SCOs:          b.scos,
		Relationships: b.rels,
		Edges:         b.edges,
	}
}

// --- shared OCSF entity extraction ------------------------------------------
// These read the builder's event payload, mint identity via the resolver, add
// the SCO, and return its id (or "" when the source fields are absent).

// host extracts an x-host SCO from an OCSF endpoint/device object at prefix
// (e.g. "device", "dst_endpoint").
func (b *resultBuilder) host(prefix string) identity.STIXID {
	p := b.evt.Payload
	hostname := pathStr(p, prefix+".hostname")
	assetID := pathStr(p, prefix+".uid")
	domain := pathStr(p, prefix+".domain")
	mac := pathStr(p, prefix+".mac")
	if hostname == "" && assetID == "" && mac == "" {
		return ""
	}
	id := b.r.Host(identity.HostIdentity{AssetID: assetID, Domain: domain, Hostname: hostname, MAC: mac})
	props := map[string]any{"hostname": hostname}
	if domain != "" {
		props["domain"] = domain
	}
	return b.addSCO(id, identity.TypeHost, props)
}

// userAccount extracts a user-account SCO from an OCSF user object at prefix
// (e.g. "actor.user"). It performs the §7.4 login shaping the resolver relies
// on: Windows domain accounts as "domain\user", email-style as the address,
// bare username otherwise.
func (b *resultBuilder) userAccount(prefix string) identity.STIXID {
	p := b.evt.Payload
	name := pathStr(p, prefix+".name")
	if name == "" {
		return ""
	}
	domain := pathStr(p, prefix+".domain")
	uid := pathStr(p, prefix+".uid")

	login := name
	accountType := "local"
	switch {
	case domain != "":
		login = domain + "\\" + name
		accountType = "windows-domain"
	case strings.Contains(name, "@"):
		accountType = "cloud"
	}
	id := b.r.UserAccount(login, uid, accountType)
	return b.addSCO(id, identity.TypeUserAccount, map[string]any{
		"account_login": login,
		"user_id":       uid,
		"account_type":  accountType,
	})
}

// ipAddr extracts an ipv4-addr or ipv6-addr SCO from a string path (e.g.
// "src_endpoint.ip").
func (b *resultBuilder) ipAddr(path string) identity.STIXID {
	return b.addIPValue(pathStr(b.evt.Payload, path))
}

// addIPValue adds an ipv4-addr or ipv6-addr SCO for a literal address value
// (used when the value comes from an array element, not a fixed path).
func (b *resultBuilder) addIPValue(v string) identity.STIXID {
	if v == "" {
		return ""
	}
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip != nil && ip.To4() == nil {
		return b.addSCO(b.r.IPv6Addr(v), identity.TypeIPv6Addr, map[string]any{"value": v})
	}
	return b.addSCO(b.r.IPv4Addr(v), identity.TypeIPv4Addr, map[string]any{"value": v})
}

// addDomain adds a domain-name SCO for a literal domain value.
func (b *resultBuilder) addDomain(v string) identity.STIXID {
	if v == "" {
		return ""
	}
	return b.addSCO(b.r.DomainName(v), identity.TypeDomainName, map[string]any{"value": v})
}

// emailAddr adds an email-addr SCO for a literal address value.
func (b *resultBuilder) emailAddr(v string) identity.STIXID {
	if v == "" {
		return ""
	}
	return b.addSCO(b.r.EmailAddr(v), identity.TypeEmailAddr, map[string]any{"value": v})
}

// emailAddrs adds an email-addr SCO for each string in the array at path,
// returning their ids.
func (b *resultBuilder) emailAddrs(path string) []identity.STIXID {
	v, ok := lookupPath(b.evt.Payload, path)
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var refs []identity.STIXID
	for _, item := range arr {
		if id := b.emailAddr(toString(item)); id != "" {
			refs = append(refs, id)
		}
	}
	return refs
}

// url adds a url SCO for a literal URL value.
func (b *resultBuilder) url(v string) identity.STIXID {
	if v == "" {
		return ""
	}
	return b.addSCO(b.r.URL(v), identity.TypeURL, map[string]any{"value": v})
}

// addFileFromMap adds a file SCO from an OCSF file object (used for array items
// like email attachments, where the object isn't at a fixed payload path).
func (b *resultBuilder) addFileFromMap(m map[string]any) identity.STIXID {
	name := toString(m["name"])
	filePath := toString(m["path"])
	hashes := hashesFromValue(m["hashes"])
	if name == "" && filePath == "" && len(hashes) == 0 {
		return ""
	}
	id := b.r.File(identity.FileIdentity{
		Hashes:          hashes,
		Name:            name,
		ParentDirectory: parentDir(filePath),
		Size:            int64(toInt(m["size"])),
	})
	props := map[string]any{"name": name}
	if len(hashes) > 0 {
		props["hashes"] = hashes
	}
	return b.addSCO(id, identity.TypeFile, props)
}

// activityExt captures the OCSF activity (create/modify/disable/…) as an
// ObservedData extension — the high-information field for the persistence and
// account-change classes (§4.6/§4.7/§4.9). Returns nil when absent.
func activityExt(p map[string]any) map[string]any {
	if a := pathStr(p, "activity_name"); a != "" {
		return map[string]any{"activity": a}
	}
	if id := pathInt(p, "activity_id"); id != 0 {
		return map[string]any{"activity_id": id}
	}
	return nil
}

// file extracts a file SCO from an OCSF file object at prefix (e.g.
// "process.file").
func (b *resultBuilder) file(prefix string) identity.STIXID {
	p := b.evt.Payload
	name := pathStr(p, prefix+".name")
	filePath := pathStr(p, prefix+".path")
	hashes := pathHashes(p, prefix+".hashes")
	size := pathInt(p, prefix+".size")
	if name == "" && filePath == "" && len(hashes) == 0 {
		return ""
	}
	id := b.r.File(identity.FileIdentity{
		Hashes:          hashes,
		Name:            name,
		ParentDirectory: parentDir(filePath),
		Size:            int64(size),
	})
	props := map[string]any{"name": name}
	if filePath != "" {
		props["path"] = filePath
	}
	if len(hashes) > 0 {
		props["hashes"] = hashes
	}
	return b.addSCO(id, identity.TypeFile, props)
}

// --- payload accessors ------------------------------------------------------

func pathStr(m map[string]any, path string) string {
	if v, ok := lookupPath(m, path); ok {
		return toString(v)
	}
	return ""
}

func pathInt(m map[string]any, path string) int {
	if v, ok := lookupPath(m, path); ok {
		return toInt(v)
	}
	return 0
}

func pathTime(m map[string]any, path string) time.Time {
	if v, ok := lookupPath(m, path); ok {
		return toTime(v)
	}
	return time.Time{}
}

// pathHashes reads an OCSF hashes value at path.
func pathHashes(m map[string]any, path string) map[string]string {
	if v, ok := lookupPath(m, path); ok {
		return hashesFromValue(v)
	}
	return nil
}

// hashesFromValue coerces an OCSF hashes value to a map, accepting both the
// object form ({"SHA-256": "..."}) and the array form
// ([{"algorithm": "...", "value": "..."}]).
func hashesFromValue(v any) map[string]string {
	out := map[string]string{}
	switch hv := v.(type) {
	case map[string]any:
		for k, val := range hv {
			if s := toString(val); s != "" {
				out[k] = s
			}
		}
	case []any:
		for _, item := range hv {
			im, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if algo, val := toString(im["algorithm"]), toString(im["value"]); algo != "" && val != "" {
				out[algo] = val
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parentDir returns the directory portion of an OCSF file path, tolerating both
// Windows ("\") and POSIX ("/") separators.
func parentDir(p string) string {
	if p == "" {
		return ""
	}
	i := strings.LastIndexAny(p, `/\`)
	if i <= 0 {
		return ""
	}
	return p[:i]
}
