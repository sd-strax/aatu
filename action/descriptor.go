package action

import (
	"sort"

	"github.com/sd-strax/reckon/capability"
)

// ActionDescriptor is the write analog of capability.CapabilityDescriptor
// (08 §3): the action surface the LLM sees plus the auth/taxonomy fields it
// declares for discoverability. DefaultTier/Reversibility/D3FEND are surfaced
// here but OWNED by 04 §2 — this must not diverge from that categorization.
type ActionDescriptor struct {
	ActionType    string                  `json:"action_type"`   // e.g. "host.isolate"
	Intent        string                  `json:"intent"`        // LLM-facing: effect + when to use
	Inputs        []capability.InputParam `json:"inputs"`        // schema for request_action.parameters
	DefaultTier   string                  `json:"default_tier"`  // T2 | T3 (04 §2)
	Reversibility string                  `json:"reversibility"` // reversible | irreversible (04 §7)
	// ReversibleBy is the inverse action type (04 §7); empty when irreversible.
	// A reversal request creates an x-action of this type against the original's
	// targets, at the SAME tier (reversing is never lower-tier than the original).
	ReversibleBy string `json:"reversible_by,omitempty"`
	D3FEND       string `json:"d3fend,omitempty"`
}

// ActionCatalog holds the registered action descriptors, keyed by action_type.
type ActionCatalog struct {
	byType map[string]ActionDescriptor
}

// NewActionCatalog returns an empty catalog.
func NewActionCatalog() *ActionCatalog {
	return &ActionCatalog{byType: make(map[string]ActionDescriptor)}
}

// Register adds or replaces a descriptor.
func (c *ActionCatalog) Register(d ActionDescriptor) { c.byType[d.ActionType] = d }

// Descriptor returns the descriptor for an action type, if registered.
func (c *ActionCatalog) Descriptor(actionType string) (ActionDescriptor, bool) {
	d, ok := c.byType[actionType]
	return d, ok
}

// ActionTypes returns the registered action types, sorted.
func (c *ActionCatalog) ActionTypes() []string {
	out := make([]string, 0, len(c.byType))
	for t := range c.byType {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// DefaultActionCatalog registers the v0 action descriptors the fixture write
// path can service (a representative subset; the rest land with their bindings,
// 08 §8). Tiers follow 04 §2.
//
// FROZEN v0 CATALOG. This function is the single authoritative source of truth
// for the dispatchable action vocabulary — the `action_type` strings, tiers,
// reversibility, and D3FEND annotations. `design/04-action-authorization.md §2.1`
// is the broader roadmap taxonomy and MUST match these rows where they overlap;
// TestDefaultActionCatalog_Frozen pins the set so neither can drift silently.
// D3FEND ids are MITRE technique ids (d3fend.mitre.org), illustrative metadata
// only (04 §2.1) — not load-bearing for control flow. Reversal actions carry a
// D3FEND id only where the ontology's Restore tactic names the restoration as a
// first-class technique (D3-RNA, D3-RE, D3-ULA); other reversals carry none.
func DefaultActionCatalog() *ActionCatalog {
	c := NewActionCatalog()
	for _, d := range []ActionDescriptor{
		{
			ActionType:    "host.isolate",
			Intent:        "Network-isolate a host, cutting it off from everything but reckon's control channel. Reversible.",
			Inputs:        []capability.InputParam{{Name: "host", Type: "entity", Required: true}},
			DefaultTier:   "T2",
			Reversibility: "reversible",
			ReversibleBy:  "host.unisolate",
			D3FEND:        "D3-NI",
		},
		{
			ActionType:    "host.unisolate",
			Intent:        "Restore a host's network connectivity — the inverse of host.isolate.",
			Inputs:        []capability.InputParam{{Name: "host", Type: "entity", Required: true}},
			DefaultTier:   "T2", // reversing is the same tier as the original (04 §7)
			Reversibility: "reversible",
			ReversibleBy:  "host.isolate",
			D3FEND:        "D3-RNA", // Restore Network Access (Restore tactic)
		},
		{
			ActionType:    "account.disable",
			Intent:        "Disable a user account, blocking new sessions until re-enabled. Reversible (account.enable); already-established sessions need session revocation separately.",
			Inputs:        []capability.InputParam{{Name: "account", Type: "entity", Required: true}},
			DefaultTier:   "T2",
			Reversibility: "reversible",
			ReversibleBy:  "account.enable",
			D3FEND:        "D3-AL", // Account Locking
		},
		{
			ActionType:    "account.enable",
			Intent:        "Re-enable a disabled user account — the inverse of account.disable. Use to retract over-containment once the account is cleared.",
			Inputs:        []capability.InputParam{{Name: "account", Type: "entity", Required: true}},
			DefaultTier:   "T2", // reversing is the same tier as the original (04 §7)
			Reversibility: "reversible",
			ReversibleBy:  "account.disable",
			D3FEND:        "D3-ULA", // Unlock Account (Restore tactic)
		},
		{
			ActionType:    "email.quarantine",
			Intent:        "Quarantine a single message from a mailbox. Reversible (release).",
			Inputs:        []capability.InputParam{{Name: "message", Type: "entity", Required: true}},
			DefaultTier:   "T2",
			Reversibility: "reversible",
			ReversibleBy:  "email.release",
			D3FEND:        "D3-ER", // Email Removal (reversible application)
		},
		{
			ActionType:    "email.release",
			Intent:        "Release a quarantined message back to its mailbox — the inverse of email.quarantine.",
			Inputs:        []capability.InputParam{{Name: "message", Type: "entity", Required: true}},
			DefaultTier:   "T2",
			Reversibility: "reversible",
			ReversibleBy:  "email.quarantine",
			D3FEND:        "D3-RE", // Restore Email (Restore tactic)
		},
		{
			ActionType:    "email.purge",
			Intent:        "Permanently delete a message from mailboxes. IRREVERSIBLE.",
			Inputs:        []capability.InputParam{{Name: "message", Type: "entity", Required: true}},
			DefaultTier:   "T3",
			Reversibility: "irreversible",
			D3FEND:        "D3-ER", // Email Removal (terminal application)
		},
		{
			ActionType:    "ioc.block",
			Intent:        "Block an IOC (hash/IP/domain) at the perimeter — firewall/proxy/DNS denylist. Use this to block a malicious IP, domain, or file hash. Reversible when the block list has a TTL/removal API.",
			Inputs:        []capability.InputParam{{Name: "indicator", Type: "entity", Required: true}},
			DefaultTier:   "T2",
			Reversibility: "reversible",
			// No ReversibleBy: ioc.unblock exists as a standalone action, not a
			// tracked reversal — whether entry removal truly undoes the block's
			// effect (TTL lists, propagated RPZ, partner feeds) is per-binding;
			// linking the pair awaits per-binding reversibility overrides (04 §7).
			D3FEND: "D3-NTF", // Network Traffic Filtering
		},
		{
			ActionType:    "ioc.unblock",
			Intent:        "Remove an IOC (hash/IP/domain) from the perimeter denylist. A standalone action, not a tracked reversal: it does not mark a prior ioc.block as REVERSED, and whether removal fully undoes propagation depends on the tenant's tooling.",
			Inputs:        []capability.InputParam{{Name: "indicator", Type: "entity", Required: true}},
			DefaultTier:   "T2", // re-opening traffic carries the same weight as blocking it
			Reversibility: "reversible",
		},
	} {
		c.Register(d)
	}
	return c
}
