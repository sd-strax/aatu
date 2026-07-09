package capability

import "github.com/sd-strax/reckon/identity"

// processNormalizer handles OCSF process_activity (class_uid 1007) → STIX (§4.1):
// the process, its parent, the image file, the host, and the executing user,
// grouped under one ObservedData, with a parent-process-of relationship.
type processNormalizer struct{ r *identity.Resolver }

func (*processNormalizer) ClassUID() int { return 1007 }
func (*processNormalizer) Version() int  { return 1 }

func (n *processNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "process_activity", n.Version())

	host := b.host("device")
	b.userAccount("actor.user")
	b.file("process.file")

	// The subject process. created_time drives deterministic identity; when
	// absent the resolver returns an anonymous SCO (§7.2), which is still a
	// valid node — just not stitchable.
	procID, _ := n.r.Process(host, pathInt(p, "process.pid"), pathTime(p, "process.created_time"))
	b.addSCO(procID, identity.TypeProcess, map[string]any{
		"pid":          pathInt(p, "process.pid"),
		"name":         pathStr(p, "process.name"),
		"command_line": pathStr(p, "process.cmd_line"),
	})

	// The parent process, if reported, plus the parent-process-of edge.
	if ppid := pathInt(p, "process.parent_process.pid"); ppid != 0 {
		parentID, _ := n.r.Process(host, ppid, pathTime(p, "process.parent_process.created_time"))
		b.addSCO(parentID, identity.TypeProcess, map[string]any{
			"pid":  ppid,
			"name": pathStr(p, "process.parent_process.name"),
		})
		b.addRel(RelParentProcessOf, parentID, procID)
	}

	return b.finish(nil), nil
}
