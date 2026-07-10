package action

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyEffect is what a matching, firing policy does (04 §4.1).
type PolicyEffect string

const (
	EffectAutoApprove     PolicyEffect = "AUTO_APPROVE"
	EffectRequireTwoParty PolicyEffect = "REQUIRE_TWO_PARTY"
	EffectDeny            PolicyEffect = "DENY"
)

// Policy is a versioned auto-approval policy (04 §4.1): a CEL predicate over the
// evaluation context plus an effect. Authors write side-effect-free predicates;
// the backend evaluates in priority order (DENY > REQUIRE_TWO_PARTY >
// AUTO_APPROVE > fall through to manual).
type Policy struct {
	ID                    string       `yaml:"id" json:"id"`
	ActionMatch           []string     `yaml:"action_match" json:"action_match"` // action_type globs
	Predicate             string       `yaml:"predicate" json:"predicate"`       // CEL, returns bool
	Effect                PolicyEffect `yaml:"effect" json:"effect"`
	Shadow                bool         `yaml:"shadow" json:"shadow"`
	SecondaryApproverPool []string     `yaml:"secondary_approver_pool" json:"secondary_approver_pool,omitempty"`
	AuthoredBy            string       `yaml:"authored_by" json:"authored_by"`
	SignedOffBy           []string     `yaml:"signed_off_by" json:"signed_off_by,omitempty"`
	EffectiveFrom         time.Time    `yaml:"effective_from" json:"effective_from"`
	EffectiveUntil        *time.Time   `yaml:"effective_until" json:"effective_until,omitempty"`
}

// ContentHash is the sha256 of the policy's canonical form (04 §4.1), used as
// policy_version in the audit trail so a decision pins the exact policy text
// that drove it.
func (p Policy) ContentHash() string {
	// Marshal the value (not the pointer); struct field order is stable, so the
	// JSON is canonical enough for a version fingerprint.
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// matchesType reports whether any action_match glob matches actionType.
func (p Policy) matchesType(actionType string) bool {
	for _, g := range p.ActionMatch {
		if g == "*" {
			return true
		}
		if ok, _ := path.Match(g, actionType); ok {
			return true
		}
	}
	return false
}

// active reports whether now falls within the policy's effective window. A zero
// EffectiveFrom means "always active from the start".
func (p Policy) active(now time.Time) bool {
	if !p.EffectiveFrom.IsZero() && now.Before(p.EffectiveFrom) {
		return false
	}
	if p.EffectiveUntil != nil && now.After(*p.EffectiveUntil) {
		return false
	}
	return true
}

// BaselineActionMatchAll is the glob a baseline policy uses to match everything.
const BaselineActionMatchAll = "*"

// BaselineDenyPolicyID is the id of the non-deletable AI-no-T3 baseline.
const BaselineDenyPolicyID = "policy/ai-no-tier3/1.0.0"

// BaselineDenyPolicy is the built-in, non-deletable baseline (04 §4.3 Example 2):
// an AI-delegated T3 request is never auto-approved by any policy — it falls
// through to the manual flow where a human must approve. It is prepended to
// every Gate2's policy set and cannot be removed, only superseded by a
// higher-priority DENY with explicit override governance (not in v0).
func BaselineDenyPolicy() Policy {
	return Policy{
		ID:          BaselineDenyPolicyID,
		ActionMatch: []string{BaselineActionMatchAll},
		Effect:      EffectDeny,
		Predicate:   `ctx.action.requested_by.kind == "AI_DELEGATED" && ctx.action.tier == "T3"`,
		AuthoredBy:  "system",
	}
}

// LoadPolicies reads every *.policy.yaml in dir (one policy per file). The
// baseline is NOT loaded from disk — NewGate2 prepends it.
func LoadPolicies(dir string) ([]Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir %s: %w", dir, err)
	}
	var policies []Policy
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".policy.yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", name, err)
		}
		var p Policy
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("parse policy %s: %w", name, err)
		}
		if p.ID == BaselineDenyPolicyID {
			return nil, fmt.Errorf("policy %s: id %q is reserved for the built-in baseline", name, BaselineDenyPolicyID)
		}
		policies = append(policies, p)
	}
	return policies, nil
}
