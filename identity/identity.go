// Package identity is the deterministic UUIDv5 identity resolver for the
// interpretation layer (design/03-capability-layer.md §7, design/01 §3/§5).
//
// The same entity — an IP, a host, a process — must resolve to the same STIX id
// across every tool and every investigation *within a tenant*, so the graph
// stitches instead of fragmenting. Identity is therefore a deterministic
// UUIDv5 over the object's identity-contributing fields, computed against a
// per-tenant namespace UUID. Same value + same tenant → same id; same value +
// different tenant → different id (stitching can never leak across tenants).
//
// The Resolver is pure, deterministic, and stateless: it holds only the tenant
// namespace and derives ids by hashing. Adapters MUST NOT compute ids — the
// normalizer, via this resolver, is the single arbiter of identity (§7.4).
// Aliasing two ids is an explicit edge created by the agent or analyst, never a
// destructive merge.
package identity

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// STIXID is a STIX identifier in the form "<type>--<uuid>", e.g.
// "ipv4-addr--0f8fad5b-d9cb-469f-a165-70867728950e".
type STIXID string

// STIX/OCSF object type prefixes this resolver mints ids for. Standard STIX SCO
// types use their canonical names; custom objects use the x- prefix per STIX
// convention (design/01).
const (
	TypeIPv4Addr      = "ipv4-addr"
	TypeIPv6Addr      = "ipv6-addr"
	TypeDomainName    = "domain-name"
	TypeURL           = "url"
	TypeFile          = "file"
	TypeEmailAddr     = "email-addr"
	TypeUserAccount   = "user-account"
	TypeProcess       = "process"
	TypeHost          = "x-host"
	TypeRegistryKey   = "x-registry-key"
	TypeScheduledTask = "x-scheduled-task"
	TypeGroup         = "x-group"
	TypeObservedData  = "observed-data"
	TypeIdentity      = "identity"
)

// Resolver computes tenant-scoped deterministic ids. Construct one per tenant
// with the tenant's immutable namespace UUID (§7.1). It is safe for concurrent
// use — it never mutates.
type Resolver struct {
	namespace uuid.UUID
}

// NewResolver returns a Resolver bound to a tenant namespace. The namespace is
// the fresh UUIDv4 assigned at tenant creation and stored in the tenant record
// (§7.1); mapping tenant → namespace is a caller concern (tenancy/config), kept
// out of this pure component.
func NewResolver(namespace uuid.UUID) *Resolver {
	return &Resolver{namespace: namespace}
}

// Namespace returns the tenant namespace this resolver is bound to.
func (r *Resolver) Namespace() uuid.UUID { return r.namespace }

// mint computes "<stixType>--<uuidv5>" over the canonical JSON of the
// identity-contributing fields, hashed against the tenant namespace.
func (r *Resolver) mint(stixType string, contributing map[string]any) STIXID {
	id := uuid.NewSHA1(r.namespace, canonicalJSON(contributing))
	return STIXID(stixType + "--" + id.String())
}

// --- standard SCOs (no STIX deviation) --------------------------------------

// IPv4Addr resolves an IPv4 address SCO.
func (r *Resolver) IPv4Addr(value string) STIXID {
	return r.mint(TypeIPv4Addr, map[string]any{"value": canonicalIP(value)})
}

// IPv6Addr resolves an IPv6 address SCO.
func (r *Resolver) IPv6Addr(value string) STIXID {
	return r.mint(TypeIPv6Addr, map[string]any{"value": canonicalIP(value)})
}

// DomainName resolves a domain-name SCO (lowercased, trailing dot stripped, IDN
// punycoded).
func (r *Resolver) DomainName(value string) STIXID {
	return r.mint(TypeDomainName, map[string]any{"value": canonicalDomain(value)})
}

// URL resolves a url SCO (scheme/host lowercased, default ports stripped, query
// keys sorted, fragment preserved).
func (r *Resolver) URL(value string) STIXID {
	return r.mint(TypeURL, map[string]any{"value": canonicalURL(value)})
}

// FileIdentity carries the identity-contributing fields of a file. Hashes take
// priority (SHA-256 > SHA-1 > MD5); the (Name, ParentDirectory, Size) triple is
// the fallback when no hash is present.
type FileIdentity struct {
	Hashes          map[string]string // algorithm → digest (algorithm matched case-insensitively)
	Name            string
	ParentDirectory string
	Size            int64
}

// File resolves a file SCO using the strongest available hash, else the
// (name, parent_directory, size) fallback. Hash digests are lowercased. The
// algorithm participates in identity alongside the digest (mirroring STIX 2.1,
// whose id-contributing property for file is the hashes dict) so digests from
// different algorithms can never merge two files.
func (r *Resolver) File(f FileIdentity) STIXID {
	if algo, digest := pickHash(f.Hashes); digest != "" {
		return r.mint(TypeFile, map[string]any{
			"hashes": map[string]string{algo: digest},
		})
	}
	return r.mint(TypeFile, map[string]any{
		"name":             strings.TrimSpace(f.Name),
		"parent_directory": strings.TrimSpace(f.ParentDirectory),
		"size":             f.Size,
	})
}

// pickHash returns the strongest available (algorithm, digest), both
// canonicalized (algorithm as bare lowercase name, digest lowercased), or
// ("", "") when no hash is present.
func pickHash(hashes map[string]string) (algo, digest string) {
	// Normalize keys once so lookup is case/format-insensitive ("SHA-256",
	// "sha256", "SHA256" all match).
	norm := make(map[string]string, len(hashes))
	for k, v := range hashes {
		key := strings.ToLower(strings.ReplaceAll(k, "-", ""))
		if v = strings.TrimSpace(v); v != "" {
			norm[key] = strings.ToLower(v)
		}
	}
	for _, a := range []string{"sha256", "sha1", "md5"} {
		if v, ok := norm[a]; ok {
			return a, v
		}
	}
	return "", ""
}

// --- deviations from strict STIX (§7.2) -------------------------------------

// EmailAddr resolves an email-addr SCO. Deviation: the whole address (localpart
// and domain) is lowercased and trimmed, because real-world mail infrastructure
// is uniformly case-insensitive.
func (r *Resolver) EmailAddr(value string) STIXID {
	return r.mint(TypeEmailAddr, map[string]any{
		"value": strings.ToLower(strings.TrimSpace(value)),
	})
}

// UserAccount resolves a user-account SCO. Deviation: account_login and user_id
// are lowercased (Windows/AD/Entra are case-insensitive). account_type is NOT
// case-folded — a cloud account and a domain account for the same human are
// deliberately distinct SCOs, linked only by an explicit aliases edge.
//
// Per-type login shaping (§7.2: Windows domain accounts as "domain\user",
// email-style accounts as the address, Unix accounts as the bare username) is
// the CALLER's contract: normalizers must shape account_login before calling
// here, because only they see the vendor fields needed to do it. This resolver
// applies the case/whitespace folding only.
func (r *Resolver) UserAccount(accountLogin, userID, accountType string) STIXID {
	return r.mint(TypeUserAccount, map[string]any{
		"account_login": strings.ToLower(strings.TrimSpace(accountLogin)),
		"user_id":       strings.ToLower(strings.TrimSpace(userID)),
		"account_type":  strings.TrimSpace(accountType),
	})
}

// Process resolves a process SCO. Deviation: strict STIX assigns processes a
// random UUID; we stitch on (host_ref, pid, created_time truncated to the
// second) because cross-tool process stitching is load-bearing. When
// createdTime is zero (no tool reported a start time) the process is treated as
// a transient anonymous SCO with a random id and ok=false — matching strict
// STIX, no stitching but no false merge.
func (r *Resolver) Process(hostRef STIXID, pid int, createdTime time.Time) (id STIXID, deterministic bool) {
	if createdTime.IsZero() {
		return STIXID(TypeProcess + "--" + uuid.NewString()), false
	}
	return r.mint(TypeProcess, map[string]any{
		"host_ref":     string(hostRef),
		"pid":          pid,
		"created_time": createdTime.UTC().Truncate(time.Second).Format(time.RFC3339),
	}), true
}

// --- custom SCOs (§7.2) -----------------------------------------------------

// HostIdentity carries the identity-contributing fields of an x-host, in
// priority order: AssetID (CMDB) > (Domain, Hostname) > MAC > Hostname.
type HostIdentity struct {
	AssetID  string
	Domain   string
	Hostname string
	MAC      string
}

// Host resolves an x-host SCO using the strongest available identifier.
func (r *Resolver) Host(h HostIdentity) STIXID {
	switch {
	case strings.TrimSpace(h.AssetID) != "":
		return r.mint(TypeHost, map[string]any{"asset_id": strings.TrimSpace(h.AssetID)})
	case strings.TrimSpace(h.Domain) != "" && strings.TrimSpace(h.Hostname) != "":
		return r.mint(TypeHost, map[string]any{
			"domain":   strings.ToLower(strings.TrimSpace(h.Domain)),
			"hostname": strings.ToLower(strings.TrimSpace(h.Hostname)),
		})
	case strings.TrimSpace(h.MAC) != "":
		return r.mint(TypeHost, map[string]any{"mac_address": canonicalMAC(h.MAC)})
	default:
		return r.mint(TypeHost, map[string]any{"hostname": strings.ToLower(strings.TrimSpace(h.Hostname))})
	}
}

// RegistryKey resolves an x-registry-key SCO. hive and key_path are lowercased;
// value_name is preserved.
func (r *Resolver) RegistryKey(hostRef STIXID, hive, keyPath, valueName string) STIXID {
	return r.mint(TypeRegistryKey, map[string]any{
		"host_ref":   string(hostRef),
		"hive":       strings.ToLower(strings.TrimSpace(hive)),
		"key_path":   strings.ToLower(strings.TrimSpace(keyPath)),
		"value_name": strings.TrimSpace(valueName),
	})
}

// ScheduledTask resolves an x-scheduled-task SCO. name and path are lowercased.
func (r *Resolver) ScheduledTask(hostRef STIXID, name, path string) STIXID {
	return r.mint(TypeScheduledTask, map[string]any{
		"host_ref": string(hostRef),
		"name":     strings.ToLower(strings.TrimSpace(name)),
		"path":     strings.ToLower(strings.TrimSpace(path)),
	})
}

// Group resolves an x-group SCO. directory and group_name are lowercased.
func (r *Resolver) Group(directory, groupName string) STIXID {
	return r.mint(TypeGroup, map[string]any{
		"directory":  strings.ToLower(strings.TrimSpace(directory)),
		"group_name": strings.ToLower(strings.TrimSpace(groupName)),
	})
}

// --- SDOs -------------------------------------------------------------------

// ObservedData resolves an observed-data SDO id from
// (class_uid, time truncated to the second, source_tool, content_hash(payload)).
// Two adapters observing the same OCSF event in the same tenant produce the
// same id, supporting cross-investigation dedup (§7.3). A newer normalizer
// version changes the payload/inputs and thus the id — old ObservedData stays
// valid.
func (r *Resolver) ObservedData(classUID int, observed time.Time, sourceTool string, payload any) STIXID {
	return r.mint(TypeObservedData, map[string]any{
		"class_uid":    classUID,
		"time":         observed.UTC().Truncate(time.Second).Format(time.RFC3339),
		"source_tool":  strings.TrimSpace(sourceTool),
		"content_hash": contentHash(payload),
	})
}

// Relationship resolves a deterministic id for a STIX Relationship (SRO) from
// its (type, source, target). STIX 2.1 assigns SROs random ids, but computing
// them deterministically lets the same edge observed twice dedupe to one
// relationship — the same pragmatic trade as ObservedData (§7.3). The prefix is
// "relationship" (STIX-native) regardless of the custom relationship_type.
func (r *Resolver) Relationship(relType string, source, target STIXID) STIXID {
	return r.mint("relationship", map[string]any{
		"relationship_type": strings.TrimSpace(relType),
		"source_ref":        string(source),
		"target_ref":        string(target),
	})
}

// Identity resolves the per-tenant vendor identity SDO id from a vendor name.
// The detection_finding normalizer (§4.12) attributes imported Indicators and
// Sightings to this Identity via created_by_ref; it is auto-created on first
// ingest and deterministic within the tenant.
func (r *Resolver) Identity(name string) STIXID {
	return r.mint(TypeIdentity, map[string]any{
		"name": strings.ToLower(strings.TrimSpace(name)),
	})
}
