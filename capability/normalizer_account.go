package capability

import "github.com/sd-strax/reckon/identity"

// accountChangeNormalizer handles OCSF account_change (class_uid 3005) → STIX
// (§4.9): the target user, the initiator, the host, and — for group activities —
// a member-of-group relationship to an x-group. The activity_id (and privilege
// name, when present) rides on the ObservedData, the high-information field the
// agent loop reasons on.
type accountChangeNormalizer struct{ r *identity.Resolver }

func (*accountChangeNormalizer) ClassUID() int { return 3005 }
func (*accountChangeNormalizer) Version() int  { return 1 }

func (n *accountChangeNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "account_change", n.Version())

	target := b.userAccount("user")
	b.userAccount("actor.user") // initiator
	b.host("device")

	if group := pathStr(p, "group.name"); group != "" {
		directory := pathStr(p, "group.domain")
		groupID := b.addSCO(n.r.Group(directory, group), identity.TypeGroup, map[string]any{
			"group_name": group,
			"directory":  directory,
		})
		if target != "" {
			b.addRel(RelMemberOfGroup, target, groupID)
		}
	}

	ext := activityExt(p)
	if priv := pathStr(p, "privileges"); priv != "" {
		if ext == nil {
			ext = map[string]any{}
		}
		ext["privilege"] = priv
	}

	return b.finish(ext), nil
}
