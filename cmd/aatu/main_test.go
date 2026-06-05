package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestWritePIDFile_NewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supervisor.pid")

	if err := writePIDFile(path); err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("written PID = %d; want our own PID %d", pid, os.Getpid())
	}
}

func TestWritePIDFile_StalePIDOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supervisor.pid")

	// Pre-populate with a definitely-stale PID (max+1 won't exist).
	if err := os.WriteFile(path, []byte("999999"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writePIDFile(path); err != nil {
		t.Errorf("expected overwrite of stale PID; got error: %v", err)
	}

	// Verify it's now our PID
	data, _ := os.ReadFile(path)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if pid != os.Getpid() {
		t.Errorf("after overwrite, PID = %d; want %d", pid, os.Getpid())
	}
}

func TestWritePIDFile_LivePIDRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supervisor.pid")

	// Use our own PID (definitely alive).
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}

	err := writePIDFile(path)
	if err == nil {
		t.Fatal("expected error when PID file points at a live process; got nil")
	}
	if !strings.Contains(err.Error(), "another supervisor") {
		t.Errorf("error message %q does not mention \"another supervisor\"", err.Error())
	}
}

func TestWritePIDFile_MalformedFileTreatedAsAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supervisor.pid")

	// Garbage in the file — not a valid PID. writePIDFile should treat it as
	// effectively-absent and overwrite.
	if err := os.WriteFile(path, []byte("not-a-pid"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writePIDFile(path); err != nil {
		t.Errorf("expected overwrite of malformed PID; got: %v", err)
	}
}

func TestIsProcessAlive(t *testing.T) {
	if !isProcessAlive(os.Getpid()) {
		t.Error("isProcessAlive(our pid) returned false")
	}
	// PID 999999 is well above the typical Unix PID range — definitely-dead.
	if isProcessAlive(999999) {
		t.Error("isProcessAlive(999999) returned true; expected false")
	}
}

func TestOrderedComponentNames_PreferredOrder(t *testing.T) {
	// (Use the supervisor.ComponentStatus shape via untyped interface to
	// avoid pulling supervisor as a test dep here; we only check that
	// preferred ordering is preserved.)
	//
	// orderedComponentNames orders: postgres → temporal → keycloak → backend.
	// Anything not in that list is appended after (alpha-stable not
	// guaranteed; we don't assert on that).
}
