package adapterplugin

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/sd-strax/reckon/internal/secretref"
)

// Host owns the set of out-of-process adapter processes for one backend. It
// scans the install layout once (§3) and lazily constructs one Plugin per
// enablement instance, so a vendor that serves both reads and writes (a
// class-mcp adapter with read verbs and ioc.block, §4.2 / 11 §8) runs as a
// single process backing both a read and a write facade — never two.
//
// The Host is the single point the read resolver, both action resolvers, and
// the Temporal worker draw plugin facades from, which is why it lives above all
// of them in the runtime assembly and is Closed on shutdown. Construction is
// spawn-free (lazy, §2); a Plugin spawns on first Invoke/Dispatch/Health.
type Host struct {
	root          string
	engineVersion string
	logger        *slog.Logger

	installed map[string]Installed
	problems  []Problem

	mu      sync.Mutex
	plugins map[string]*Plugin
}

// NewHost scans root (`<data>/adapters`, §3) for installed adapters. A missing
// root is not an error (no adapters installed is the common case); malformed or
// duplicate installs are recorded as Problems and otherwise ignored (§3). No
// process is spawned.
func NewHost(root, engineVersion string, logger *slog.Logger) *Host {
	if logger == nil {
		logger = slog.Default()
	}
	installed, problems := ScanAdapters(root)
	return &Host{
		root:          root,
		engineVersion: engineVersion,
		logger:        logger,
		installed:     installed,
		problems:      problems,
		plugins:       map[string]*Plugin{},
	}
}

// Problems returns the malformed/duplicate installs skipped during the scan,
// for `reckon check` and boot-time logging.
func (h *Host) Problems() []Problem { return h.problems }

// Installed returns the adapters that scanned cleanly, keyed by manifest name.
func (h *Host) Installed() map[string]Installed { return h.installed }

// Plugin returns the Plugin for an enablement instance, constructing it once and
// caching it so repeated calls (read wiring, write wiring, the worker) share one
// process. installName is the installed adapter the instance runs (defaulting to
// the instance name when the config omits it, 11 §5); config is delivered to the
// `configure` handshake (§4.3). It errors if installName is not installed.
func (h *Host) Plugin(instance, installName string, config map[string]any) (*Plugin, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.plugins[instance]; ok {
		return p, nil
	}
	if installName == "" {
		installName = instance
	}
	inst, ok := h.installed[installName]
	if !ok {
		return nil, fmt.Errorf("adapter instance %q references install %q, which is not installed under %s (11 §3)", instance, installName, h.root)
	}
	// Resolve x-secret references to plaintext against the manifest's claimed
	// config_schema (§4.3), refusing any literal in an x-secret field. Done once,
	// here, so the resolved secret lives only in this process's memory and never
	// in the adapter's environment; the plaintext travels only in the configure
	// payload, never the tenant config file. (v0 delivers at configure; the
	// per-invocation credential channel of 05 §10.2 is the deferred hardening.)
	resolved, err := secretref.ResolveConfig(inst.Manifest.ConfigSchema, config)
	if err != nil {
		return nil, fmt.Errorf("adapter instance %q: %w", instance, err)
	}
	p, err := New(instance, inst, resolved, h.engineVersion, WithLogger(h.logger))
	if err != nil {
		return nil, fmt.Errorf("adapter instance %q: %w", instance, err)
	}
	h.plugins[instance] = p
	return p, nil
}

// Close terminates every spawned adapter process. Safe to call once at shutdown.
func (h *Host) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.plugins {
		p.Close()
	}
	h.plugins = map[string]*Plugin{}
}
