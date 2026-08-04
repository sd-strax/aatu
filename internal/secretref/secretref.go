// Package secretref resolves the x-secret reference schemes of the adapter
// plugin config (design/11 §4.3): a field an adapter marks x-secret must carry
// a secret REFERENCE, never a literal, and the engine resolves it out-of-band
// so plaintext never lands in the tenant config file, the adapter's
// environment, the handshake payload on disk, or the conversation.
//
// Three schemes (§4.3):
//
//   - keychain://<service>/<name> — the OS credential store (macOS Keychain,
//     Windows Credential Manager, Linux Secret Service) via zalando/go-keyring.
//     The v0 solo-laptop default: OS access control, encrypted at rest.
//   - env://NAME — the BACKEND's environment at resolve time (the adapter still
//     spawns with a clean env, §2). The CI/server pattern.
//   - vault://… — the uniform 05 §10.2 scheme; the team/SaaS answer, deferred
//     in v0 (parsed and rejected with a clear diagnostic, never silently).
package secretref

import (
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"

	"github.com/sd-strax/reckon/internal/branding"
)

// Scheme prefixes (§4.3).
const (
	SchemeKeychain = "keychain://"
	SchemeEnv      = "env://"
	SchemeVault    = "vault://"
)

// IsRef reports whether s is a secret reference under any known scheme. A
// non-ref string in an x-secret field is a literal, which config load refuses.
func IsRef(s string) bool {
	return strings.HasPrefix(s, SchemeKeychain) ||
		strings.HasPrefix(s, SchemeEnv) ||
		strings.HasPrefix(s, SchemeVault)
}

// Resolve resolves one secret reference to its plaintext value. It errors on an
// unknown scheme, an empty/missing backing value, or an unavailable backend.
// The returned plaintext is meant to live only briefly in engine memory.
func Resolve(ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, SchemeKeychain):
		return resolveKeychain(strings.TrimPrefix(ref, SchemeKeychain))
	case strings.HasPrefix(ref, SchemeEnv):
		return resolveEnv(strings.TrimPrefix(ref, SchemeEnv))
	case strings.HasPrefix(ref, SchemeVault):
		return "", fmt.Errorf("vault:// secret scheme is not configured in v0 (11 §4.3, 05 §10.2); use keychain:// or env://")
	default:
		return "", fmt.Errorf("%q is not a secret reference (want keychain:// / env:// / vault://)", ref)
	}
}

// resolveKeychain reads keychain://<service>/<name>. With no "/" the branding
// service is used, so keychain://okta-client-secret == keychain://reckon/okta-client-secret.
func resolveKeychain(rest string) (string, error) {
	service, name := branding.CLI, rest
	if s, n, ok := strings.Cut(rest, "/"); ok {
		service, name = s, n
	}
	if name == "" {
		return "", fmt.Errorf("keychain reference has no secret name")
	}
	v, err := keyring.Get(service, name)
	if err != nil {
		return "", fmt.Errorf("read keychain secret %s/%s: %w", service, name, err)
	}
	if v == "" {
		return "", fmt.Errorf("keychain secret %s/%s is empty", service, name)
	}
	return v, nil
}

// resolveEnv reads env://NAME from the backend's own environment.
func resolveEnv(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("env reference has no variable name")
	}
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return "", fmt.Errorf("env var %s is empty or unset", name)
	}
	return v, nil
}

// ResolveConfig returns a copy of an adapter instance's config with every
// x-secret field resolved from its reference to plaintext (§4.3). The
// config_schema (the adapter's claimed copy from the manifest, §3) names which
// fields are x-secret. A literal in an x-secret field is refused here — the
// "literal refused at config load" rule — so a plaintext secret never survives
// into the handshake. Non-secret fields pass through untouched. A nil schema
// (an adapter declaring no config) passes the config through as-is.
func ResolveConfig(configSchema map[string]any, config map[string]any) (map[string]any, error) {
	if len(config) == 0 {
		return config, nil
	}
	secretFields := xSecretFields(configSchema)
	out := make(map[string]any, len(config))
	for k, v := range config {
		if !secretFields[k] {
			out[k] = v
			continue
		}
		ref, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("config field %q is x-secret but its value is not a string reference (11 §4.3)", k)
		}
		if !IsRef(ref) {
			return nil, fmt.Errorf("config field %q is x-secret: its value must be a secret reference (keychain:// / env:// / vault://), not a literal (11 §4.3)", k)
		}
		resolved, err := Resolve(ref)
		if err != nil {
			return nil, fmt.Errorf("config field %q: %w", k, err)
		}
		out[k] = resolved
	}
	return out, nil
}

// xSecretFields extracts the set of property names marked `"x-secret": true` in
// a JSON-Schema-shaped config_schema (§4.3).
func xSecretFields(schema map[string]any) map[string]bool {
	out := map[string]bool{}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return out
	}
	for name, raw := range props {
		field, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if secret, ok := field["x-secret"].(bool); ok && secret {
			out[name] = true
		}
	}
	return out
}
