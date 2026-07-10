package action

// Authorization modes a Decision maps to (mirrors aggregate.AuthMode*). Kept as
// string constants here to avoid an import cycle; the endpoint maps them onto
// the aggregate command.
const (
	ModeAutoPolicy = "AUTO_POLICY"
	ModeTwoParty   = "TWO_PARTY"
	ModeManual     = "MANUAL"
)

// PolicyEvaluation is one policy's outcome for the PolicyEvaluated audit event
// (02 §3): whether the predicate fired, its effect, and whether it was shadow.
// Both firing and shadow evaluations are recorded — the shadow audit (04 §4.4)
// reads would_have_fired == true && shadow == true from the event stream.
type PolicyEvaluation struct {
	PolicyRef      string       `json:"policy_ref"`
	PolicyVersion  string       `json:"policy_version"` // content hash
	WouldHaveFired bool         `json:"would_have_fired"`
	Effect         PolicyEffect `json:"effect"`
	Shadow         bool         `json:"shadow"`
}

// Decision is the outcome of Gate 2 policy evaluation (04 §4). Effect is the
// non-shadow effect that actually drove authorization (empty when the action
// fell through to the manual flow); Mode is the authorization mode the endpoint
// records on approval. Evaluations is the full audit list for PolicyEvaluated.
type Decision struct {
	Effect                PolicyEffect
	Mode                  string // AUTO_POLICY | TWO_PARTY | MANUAL
	MatchedPolicyRef      string // "" when manual
	SecondaryApproverPool []string
	// PolicyAccountable is the human an AUTO_POLICY approval is attributed to —
	// the matched policy's signed-off-by (or authored-by) analyst (04 §3.3:
	// "primary_approver_ref points at the human who authored or last signed off
	// on the policy, not the system"). Empty unless Mode == AUTO_POLICY.
	PolicyAccountable string
	Evaluations       []PolicyEvaluation
}

// AutoApproves reports whether the decision is a clean auto-approval (the
// endpoint may issue the ApproveAction immediately without human interaction).
func (d Decision) AutoApproves() bool { return d.Mode == ModeAutoPolicy }
