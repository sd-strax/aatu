package capability

import "github.com/sd-strax/reckon/identity"

// fileActivityNormalizer handles OCSF file_activity (class_uid 1001) → STIX
// (§4.5): the file (with its parent directory), the actor process, the host, and
// the executing user, with activity_id preserved on the ObservedData.
type fileActivityNormalizer struct{ r *identity.Resolver }

func (*fileActivityNormalizer) ClassUID() int { return 1001 }
func (*fileActivityNormalizer) Version() int  { return 1 }

func (n *fileActivityNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "file_activity", n.Version())

	fileID := b.file("file")
	if dir := parentDir(pathStr(p, "file.path")); dir != "" {
		dirID := b.addSCO(n.r.Directory(dir), identity.TypeDirectory, map[string]any{"path": dir})
		b.addRel(RelParentDirectoryOf, dirID, fileID)
	}

	if pid := pathInt(p, "actor.process.pid"); pid != 0 {
		host := b.host("device")
		procID, _ := n.r.Process(host, pid, pathTime(p, "actor.process.created_time"))
		b.addSCO(procID, identity.TypeProcess, map[string]any{
			"pid":  pid,
			"name": pathStr(p, "actor.process.name"),
		})
	} else {
		b.host("device")
	}
	b.userAccount("actor.user")

	return b.finish(activityExt(p)), nil
}
