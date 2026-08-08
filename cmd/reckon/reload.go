package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/runtime"
)

// supervisorPID reads the running supervisor's pid from the pidfile. Returns
// (0, false) when no supervisor is running (no pidfile) — a normal, non-error
// state the callers report as "not running".
func supervisorPID() (int, bool) {
	cfg, err := config.Load()
	if err != nil {
		return 0, false
	}
	data, err := os.ReadFile(runtime.PIDFilePath(cfg))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return pid, true
}

// signalReload sends SIGHUP to the running supervisor, which rebuilds and
// hot-swaps the capability layer from the tenant config on disk (11 §5.1) —
// no restart, no dropped Postgres/Temporal/Keycloak. Returns false when no
// supervisor is running (nothing to signal — the change applies on next start).
func signalReload() (bool, error) {
	pid, running := supervisorPID()
	if !running {
		return false, nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, fmt.Errorf("find supervisor process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return false, nil // stale pidfile; not running
		}
		return false, fmt.Errorf("send SIGHUP to %d: %w", pid, err)
	}
	return true, nil
}

// runAdapterReload signals a running supervisor to reload the capability layer
// (the CLI face of SIGHUP), for when the tenant config was edited by hand.
func runAdapterReload() error {
	reloaded, err := signalReload()
	if err != nil {
		return err
	}
	if !reloaded {
		fmt.Printf("%s is not running — the config change will apply on next `%s start`.\n", branding.CLI, branding.CLI)
		return nil
	}
	fmt.Printf("✓ signalled the running %s to reload — reads and writes apply immediately (unless the action layer was entirely off at boot).\n", branding.CLI)
	return nil
}
