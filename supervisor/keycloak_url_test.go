package supervisor

import (
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

func TestKeycloakTarballURL_PinsVersion(t *testing.T) {
	url := keycloakTarballURL()
	if !strings.Contains(url, keycloakVersion) {
		t.Errorf("URL %q does not contain pinned version %q", url, keycloakVersion)
	}
	if !strings.HasPrefix(url, "https://github.com/keycloak/keycloak/releases/download/") {
		t.Errorf("URL %q does not point at the canonical GitHub Releases path", url)
	}
}

func TestTemurinJREURL_PinsVersionAndIncludesArch(t *testing.T) {
	url, err := temurinJREURL()
	if err != nil {
		t.Fatalf("temurinJREURL on %s/%s: %v", goruntime.GOOS, goruntime.GOARCH, err)
	}
	// Version uses dotted form in the filename (17.0.13_11), not the tag form (17.0.13%2B11).
	if !strings.Contains(url, "17.0.13") {
		t.Errorf("URL %q does not contain pinned major version 17.0.13", url)
	}
	if !strings.HasPrefix(url, "https://github.com/adoptium/temurin17-binaries/releases/download/") {
		t.Errorf("URL %q does not point at Adoptium releases", url)
	}

	// Arch tag must be present
	wantArch := "x64"
	if goruntime.GOARCH == "arm64" {
		wantArch = "aarch64"
	}
	if !strings.Contains(url, wantArch) {
		t.Errorf("URL %q does not contain arch %q", url, wantArch)
	}

	// OS tag must be present
	wantOS := "linux"
	if goruntime.GOOS == "darwin" {
		wantOS = "mac"
	}
	if !strings.Contains(url, wantOS) {
		t.Errorf("URL %q does not contain os %q", url, wantOS)
	}
}

func TestRelativeJavaBin_OSSpecific(t *testing.T) {
	got := relativeJavaBin()
	want := filepath.Join("bin", "java")
	if goruntime.GOOS == "darwin" {
		want = filepath.Join("Contents", "Home", "bin", "java")
	}
	if got != want {
		t.Errorf("relativeJavaBin() = %q; want %q", got, want)
	}
}

func TestKeycloakIssuerURL(t *testing.T) {
	k := NewKeycloak(KeycloakConfig{HTTPPort: 18543, RealmName: "test-realm"})
	want := "http://localhost:18543/realms/test-realm"
	if got := k.IssuerURL(); got != want {
		t.Errorf("IssuerURL() = %q; want %q", got, want)
	}
}

func TestKeycloakDefaults(t *testing.T) {
	k := NewKeycloak(KeycloakConfig{})
	if k.cfg.HTTPPort != 8543 {
		t.Errorf("default HTTPPort = %d; want 8543", k.cfg.HTTPPort)
	}
	if k.cfg.ManagementPort != 9543 {
		t.Errorf("default ManagementPort = %d; want 9543", k.cfg.ManagementPort)
	}
	if k.cfg.RealmName != "reckon" {
		t.Errorf("default RealmName = %q; want \"reckon\"", k.cfg.RealmName)
	}
	if !strings.Contains(k.cfg.DataDir, ".reckon") {
		t.Errorf("default DataDir = %q; want to contain .reckon", k.cfg.DataDir)
	}
}
