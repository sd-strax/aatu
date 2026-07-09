package capability

import "github.com/sd-strax/reckon/identity"

// registryNormalizer handles OCSF registry_key_activity (class_uid 1003) → STIX
// (§4.6): the host-scoped registry key, the actor process, and the host, with
// activity_id preserved on the ObservedData.
type registryNormalizer struct{ r *identity.Resolver }

func (*registryNormalizer) ClassUID() int { return 1003 }
func (*registryNormalizer) Version() int  { return 1 }

func (n *registryNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "registry_key_activity", n.Version())

	host := b.host("device")
	hive := pathStr(p, "reg_key.hive")
	keyPath := pathStr(p, "reg_key.path")
	valueName := pathStr(p, "reg_value.name")
	if hive != "" || keyPath != "" {
		b.addSCO(n.r.RegistryKey(host, hive, keyPath, valueName), identity.TypeRegistryKey, map[string]any{
			"hive":       hive,
			"key_path":   keyPath,
			"value_name": valueName,
			"value_data": pathStr(p, "reg_value.data"),
		})
	}
	addActorProcess(b, host)

	return b.finish(activityExt(p)), nil
}

// scheduledJobNormalizer handles OCSF scheduled_job_activity (class_uid 1006) →
// STIX (§4.7): the host-scoped scheduled task, its principal user, and the host.
type scheduledJobNormalizer struct{ r *identity.Resolver }

func (*scheduledJobNormalizer) ClassUID() int { return 1006 }
func (*scheduledJobNormalizer) Version() int  { return 1 }

func (n *scheduledJobNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "scheduled_job_activity", n.Version())

	host := b.host("device")
	principal := b.userAccount("job.user")
	name := pathStr(p, "job.name")
	path := pathStr(p, "job.path")
	if name != "" || path != "" {
		b.addSCO(n.r.ScheduledTask(host, name, path), identity.TypeScheduledTask, map[string]any{
			"name":               name,
			"path":               path,
			"command_line":       pathStr(p, "job.command_line"),
			"principal_user_ref": string(principal),
		})
	}

	return b.finish(activityExt(p)), nil
}

// moduleNormalizer handles OCSF module_activity (class_uid 1009) → STIX (§4.8):
// the loaded module file, the loading process, and the host, with a loads edge.
type moduleNormalizer struct{ r *identity.Resolver }

func (*moduleNormalizer) ClassUID() int { return 1009 }
func (*moduleNormalizer) Version() int  { return 1 }

func (n *moduleNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	b := newBuilder(n.r, evt, "module_activity", n.Version())

	host := b.host("device")
	fileID := b.file("module.file")
	procID := addActorProcess(b, host)
	if procID != "" && fileID != "" {
		b.addRel(RelLoads, procID, fileID)
	}

	return b.finish(nil), nil
}

// addActorProcess extracts the actor.process SCO (if a pid is present) on host,
// returning its id. Shared by the classes that carry an acting process.
func addActorProcess(b *resultBuilder, host identity.STIXID) identity.STIXID {
	pid := pathInt(b.evt.Payload, "actor.process.pid")
	if pid == 0 {
		return ""
	}
	procID, _ := b.r.Process(host, pid, pathTime(b.evt.Payload, "actor.process.created_time"))
	return b.addSCO(procID, identity.TypeProcess, map[string]any{
		"pid":  pid,
		"name": pathStr(b.evt.Payload, "actor.process.name"),
	})
}
