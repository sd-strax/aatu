package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/capability"
)

// The enablement surface (11 §5, §5.1): the operator view of installed
// adapters and the human-confirmed apply path. Three rules bind this file:
//
//   - Chat is the place, never the author: the workbench renders the form from
//     the schema served here; free-text model output is never parsed into
//     config.
//   - The agent proposes; only the human applies: the POST refuses an
//     AI-delegated token outright — an agent that could enable ops would have
//     a side door around the entire authorization design.
//   - Every change is recorded: an attributed config-plane audit line lands
//     next to the tenant config file (the file is the source of truth; its
//     audit trail lives beside it).

// EnablementAdapterView is one installed adapter instance.
type EnablementAdapterView struct {
	Name     string `json:"name"`
	Class    string `json:"class"`
	Enabled  bool   `json:"enabled"`
	Scenario string `json:"scenario,omitempty"`
	// ConfigSchema is the 11 §4.3 JSON-schema-shaped form source for this
	// class (nil when the class has no editable config in v0).
	ConfigSchema map[string]any `json:"config_schema,omitempty"`
	// Supportable is false for classes v0 cannot spawn (native_api/mcp/custom
	// land in Phase E) — the form offers no enable affordance, honestly.
	Supportable bool `json:"supportable"`
}

// EnablementVerbView maps a verb to the adapter instances bound to serve it —
// the gap-hint source: a verb whose every bound adapter is disabled is
// closable from the workbench.
type EnablementVerbView struct {
	Verb     string   `json:"verb"`
	Adapters []string `json:"adapters"`
	// Enabled: at least one bound adapter is enabled.
	Enabled bool `json:"enabled"`
	// ClosableBy names the disabled-but-supportable adapters that would serve
	// this verb if enabled — the "installed, not enabled" hint (11 §6.2:
	// mentionable, never actionable by the agent).
	ClosableBy []string `json:"closable_by,omitempty"`
}

// EnablementResponse is GET /api/enablement.
type EnablementResponse struct {
	ConfigPath string                  `json:"config_path"`
	Adapters   []EnablementAdapterView `json:"adapters"`
	Verbs      []EnablementVerbView    `json:"verbs"`
}

// enablementRoute routes /api/enablement (GET) and
// /api/enablement/adapters/{name} (POST).
func (b *Backend) enablementRoute(w http.ResponseWriter, r *http.Request) {
	if b.cfg.CapabilityConfigPath == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "capability layer not configured")
		return
	}
	p := strings.TrimSuffix(r.URL.Path, "/")
	if p == "/enablement" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.getEnablement)
		return
	}
	if name, ok := strings.CutPrefix(p, "/enablement/adapters/"); ok && name != "" && !strings.Contains(name, "/") {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
			b.applyEnablement(w, r, name)
		})
		return
	}
	writeJSONError(w, http.StatusNotFound, "path must be /enablement or /enablement/adapters/{name}")
}

// getEnablement serves the operator view, straight from the tenant config
// FILE (the authority) — never from the in-memory resolver, which only knows
// enabled adapters.
func (b *Backend) getEnablement(w http.ResponseWriter, _ *http.Request) {
	tc, err := capability.LoadTenantConfig(b.cfg.CapabilityConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "load tenant config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, buildEnablementView(b.cfg.CapabilityConfigPath, tc))
}

func buildEnablementView(path string, tc capability.TenantConfig) EnablementResponse {
	resp := EnablementResponse{ConfigPath: path, Adapters: []EnablementAdapterView{}, Verbs: []EnablementVerbView{}}
	enabled := map[string]bool{}
	supportable := map[string]bool{}
	for name, spec := range tc.Adapters {
		enabled[name] = spec.Enabled
		supportable[name] = spec.Class == capability.ClassFixture
		resp.Adapters = append(resp.Adapters, EnablementAdapterView{
			Name:         name,
			Class:        string(spec.Class),
			Enabled:      spec.Enabled,
			Scenario:     spec.Scenario,
			ConfigSchema: capability.AdapterConfigSchema(spec.Class),
			Supportable:  supportable[name],
		})
	}
	for verb, bindings := range tc.Bindings {
		v := EnablementVerbView{Verb: verb, Adapters: []string{}}
		for _, bd := range bindings {
			v.Adapters = append(v.Adapters, bd.Adapter)
			if enabled[bd.Adapter] {
				v.Enabled = true
			} else if supportable[bd.Adapter] {
				v.ClosableBy = append(v.ClosableBy, bd.Adapter)
			}
		}
		if v.Enabled {
			v.ClosableBy = nil // nothing to close — the verb is already served
		}
		resp.Verbs = append(resp.Verbs, v)
	}
	sortEnablement(&resp)
	return resp
}

// ApplyEnablementBody is the human-confirmed change for one adapter.
type ApplyEnablementBody struct {
	Enabled bool `json:"enabled"`
	// Config carries the schema's fields (fixture: scenario). Values for
	// x-secret fields must be secret REFERENCES (keychain:// env:// vault://) —
	// a literal is refused at config load (11 §4.3); v0's fixture schema has
	// no secret fields.
	Config map[string]string `json:"config,omitempty"`
}

// applyEnablement rewrites the adapter's stanza in the tenant config file,
// rebuilds the capability surface from the file, hot-swaps it, and records
// the attributed audit line. Only a HUMAN principal may apply (11 §5.1).
func (b *Backend) applyEnablement(w http.ResponseWriter, r *http.Request, adapter string) {
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "no verified claims")
		return
	}
	if claims.DelegateKind != "" {
		// The structural guarantee of 11 §6.2: the agent has NO tool that
		// changes enablement. Blindness was economy; the tool gap is the
		// guarantee — and this endpoint is not a tool.
		writeJSONError(w, http.StatusForbidden, "enablement is a human act: an AI-delegated token cannot change config (11 §5.1)")
		return
	}

	var body ApplyEnablementBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}

	tc, err := capability.LoadTenantConfig(b.cfg.CapabilityConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "load tenant config: "+err.Error())
		return
	}
	spec, present := tc.Adapters[adapter]
	if !present {
		writeJSONError(w, http.StatusNotFound,
			fmt.Sprintf("adapter %q is not installed — enablement never installs (11 §6.1)", adapter))
		return
	}
	// A plugin (out-of-process) adapter can only be hot-enabled when the
	// plugin-aware rebuild closure is wired (runtime injects it). Without it,
	// only the fixture class can be spawned in-package — the honest v0 gate.
	if body.Enabled && spec.Class != capability.ClassFixture && b.cfg.CapabilityRebuild == nil {
		writeJSONError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("adapter %q has class %q and no plugin rebuild is wired; enable it via the tenant config + a restart", adapter, spec.Class))
		return
	}

	if err := capability.UpdateAdapterEnablement(b.cfg.CapabilityConfigPath, adapter, body.Enabled, body.Config); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Rebuild from the FILE (the authority) and hot-swap — through the full
	// plugin path when the closure is wired, else the fixture-only in-package
	// build. A rebuild failure after a write is surfaced loudly (the file
	// changed, the surface didn't) so the operator fixes or reverts.
	if err := b.rebuildCapabilityFromFile(); err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"config written but rebuild failed (fix the file or revert): "+err.Error())
		return
	}

	// The audit line: attributed, append-only, beside the file it governs.
	b.appendEnablementAudit(claims.Subject, adapter, body)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "applied",
		"adapter": adapter,
		"enabled": body.Enabled,
	})
}

// rebuildCapabilityFromFile rebuilds + hot-swaps the capability surface from
// the tenant config on disk: the injected plugin-aware closure when wired
// (11 §5.1, the full adapter path), else the fixture-only in-package build (the
// v0 path with no adapter host). Shared by the enablement endpoint and any
// reload trigger.
func (b *Backend) rebuildCapabilityFromFile() error {
	if b.cfg.CapabilityRebuild != nil {
		return b.ReloadCapability()
	}
	tc, err := capability.LoadTenantConfig(b.cfg.CapabilityConfigPath)
	if err != nil {
		return err
	}
	ns := uuid.Nil
	if b.cfg.TenantNamespace != "" {
		ns, _ = uuid.Parse(b.cfg.TenantNamespace)
	}
	resolver, catalog, err := capability.BuildResolver(tc, b.cfg.CapabilityFixtureRoot, ns)
	if err != nil {
		return err
	}
	b.setCapabilitySurface(resolver, catalog)
	return nil
}

// appendEnablementAudit records one config-plane change (11 §5.1: "casual
// changes are the ones that need an audit trail"). Best-effort by design —
// the config write already succeeded; a failed audit line logs, never rolls
// back the change the human confirmed.
func (b *Backend) appendEnablementAudit(principal, adapter string, body ApplyEnablementBody) {
	line, err := json.Marshal(map[string]any{
		"at":        time.Now().UTC().Format(time.RFC3339),
		"principal": principal,
		"adapter":   adapter,
		"enabled":   body.Enabled,
		"config":    body.Config,
	})
	if err != nil {
		return
	}
	path := b.cfg.CapabilityConfigPath + ".audit.jsonl"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func sortEnablement(resp *EnablementResponse) {
	// Deterministic order for stable rendering + tests.
	sort.Slice(resp.Adapters, func(i, j int) bool { return resp.Adapters[i].Name < resp.Adapters[j].Name })
	sort.Slice(resp.Verbs, func(i, j int) bool { return resp.Verbs[i].Verb < resp.Verbs[j].Verb })
}
