package action

import "testing"

// TestDefaultActionCatalog_Frozen pins the v0 action catalog — the single
// authoritative source of truth for the dispatchable action vocabulary. A change
// to any action_type string, tier, reversibility pairing, or D3FEND id is a
// breaking change to the agent-facing contract and to design/04 §2.1; this test
// forces that change to be deliberate (update the golden below) rather than a
// silent drift like the ioc.block/block.add and D3-ANCI/D3-AL splits that
// predated the freeze.
func TestDefaultActionCatalog_Frozen(t *testing.T) {
	type want struct {
		tier          string
		reversibility string
		reversibleBy  string
		d3fend        string
	}
	// Reversals carry a D3FEND id where the Restore tactic names the restoration
	// as a first-class technique (04 §2.1): D3-RNA, D3-RE, D3-ULA. account.disable
	// is reversible per D3FEND Restore listing Unlock Account (04 §7). ioc.block
	// and its inverse are best_effort (04 §7 Position C): linked + affordant, but
	// the REVERSED status claim is gated on per-binding reliability.
	golden := map[string]want{
		"host.isolate":     {"T2", "reversible", "host.unisolate", "D3-NI"},
		"host.unisolate":   {"T2", "reversible", "host.isolate", "D3-RNA"},
		"account.disable":  {"T2", "reversible", "account.enable", "D3-AL"},
		"account.enable":   {"T2", "reversible", "account.disable", "D3-ULA"},
		"email.quarantine": {"T2", "reversible", "email.release", "D3-ER"},
		"email.release":    {"T2", "reversible", "email.quarantine", "D3-RE"},
		"email.purge":      {"T3", "irreversible", "", "D3-ER"},
		"ioc.block":        {"T2", "best_effort", "ioc.unblock", "D3-NTF"},
		"ioc.unblock":      {"T2", "best_effort", "ioc.block", "D3-RNA"},
		// The ticketing family (04 §2, 07 §7.1): all T2 (external dispatch is
		// always T2+), all irreversible-ADDITIVE (append-only SoR; ticket.close is
		// a forward transition, never a reversal — hence no reversal pairs), no
		// D3FEND (operational handoff, not a defensive technique).
		"ticket.create":     {"T2", "irreversible", "", ""},
		"ticket.comment":    {"T2", "irreversible", "", ""},
		"ticket.transition": {"T2", "irreversible", "", ""},
		"ticket.close":      {"T2", "irreversible", "", ""},
		// The comms family (Phase F, binding §4): T2 — there is no T1 external
		// action (04 §1 names chat explicitly; the pre-send preview is the
		// light approval surface, not a lower tier) — and irreversible: a sent
		// message is permanent. No D3FEND (coordination, not a technique).
		"notify.slack": {"T2", "irreversible", "", ""},
		"notify.email": {"T2", "irreversible", "", ""},
	}

	cat := DefaultActionCatalog()
	got := cat.ActionTypes()
	if len(got) != len(golden) {
		t.Fatalf("catalog has %d action types %v; frozen set has %d — update the golden deliberately",
			len(got), got, len(golden))
	}
	for at, w := range golden {
		d, ok := cat.Descriptor(at)
		if !ok {
			t.Errorf("frozen action type %q missing from catalog", at)
			continue
		}
		if d.DefaultTier != w.tier {
			t.Errorf("%s: tier = %q; frozen %q", at, d.DefaultTier, w.tier)
		}
		if d.Reversibility != w.reversibility {
			t.Errorf("%s: reversibility = %q; frozen %q", at, d.Reversibility, w.reversibility)
		}
		if d.ReversibleBy != w.reversibleBy {
			t.Errorf("%s: reversible_by = %q; frozen %q", at, d.ReversibleBy, w.reversibleBy)
		}
		if d.D3FEND != w.d3fend {
			t.Errorf("%s: d3fend = %q; frozen %q", at, d.D3FEND, w.d3fend)
		}
		if d.Intent == "" {
			t.Errorf("%s: intent is empty — the agent-facing description must exist", at)
		}
	}

	// The REVERSED-claim gate (04 §7.1 Position C): ReliablyReversible must be
	// true exactly for the RELIABLE classification. This is the input the
	// ReversalSaga's status-claim gate is fed (server startActionWorkflow →
	// ReversalSagaInput.OriginalReliable), so a drift here silently changes
	// whether originals get marked REVERSED.
	for at, w := range golden {
		d, _ := cat.Descriptor(at)
		if got, want := d.ReliablyReversible(), w.reversibility == ReversibilityReversible; got != want {
			t.Errorf("%s: ReliablyReversible() = %v; want %v (classification %q)", at, got, want, w.reversibility)
		}
	}

	// Reversal pairs must be mutually consistent: if A reverses to B, B must
	// reverse to A and both share tier (04 §7).
	for at, w := range golden {
		if w.reversibleBy == "" {
			continue
		}
		inv, ok := golden[w.reversibleBy]
		if !ok {
			t.Errorf("%s reverses to %q which is not in the catalog", at, w.reversibleBy)
			continue
		}
		if inv.reversibleBy != at {
			t.Errorf("reversal pair broken: %s→%s but %s→%s", at, w.reversibleBy, w.reversibleBy, inv.reversibleBy)
		}
		if inv.tier != w.tier {
			t.Errorf("reversal pair %s/%s tier mismatch: %s vs %s (04 §7: same tier)", at, w.reversibleBy, w.tier, inv.tier)
		}
	}
}
