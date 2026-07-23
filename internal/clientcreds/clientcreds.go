// Package clientcreds is the CLIENT-plane credential store: per-user secrets that
// belong to the analyst at the surface, not to the installation. It is the CLI
// analog of the workbench's vscode.SecretStorage, backed by the OS keychain
// (macOS Keychain / Windows Credential Manager / Linux Secret Service) via
// zalando/go-keyring — no cgo, no plaintext file.
//
// This is deliberately SEPARATE from internal/secrets (the install/deployer
// secret store the engine reads): the Anthropic key is BYOK and client-side by
// architectural commitment (design/05 §2.7) — it lives with the surface, never
// crosses to the backend, and is per-user rather than per-install. Keeping the
// two stores distinct keeps that plane boundary honest.
//
// On a headless host with no keyring provider (a server, CI), keychain calls
// fail rather than silently writing a file; callers fall back to the
// ANTHROPIC_API_KEY environment variable there.
package clientcreds

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"

	"github.com/sd-strax/reckon/internal/branding"
)

// keyName is the account under which the Anthropic key is stored, namespaced by
// the branding.CLI service.
const keyName = "anthropic-api-key"

func service() string { return branding.CLI }

// SetAnthropicKey stores the BYOK Anthropic API key in the OS keychain.
func SetAnthropicKey(key string) error {
	if err := keyring.Set(service(), keyName, key); err != nil {
		return fmt.Errorf("store anthropic key in keychain: %w", err)
	}
	return nil
}

// GetAnthropicKey returns the stored key and true, or "" and false when none is
// stored. A backend failure (e.g. no keyring on a headless host) is a real
// error, distinct from "not stored" — so callers can fall back to the env var
// on absence but surface a broken keyring.
func GetAnthropicKey() (string, bool, error) {
	v, err := keyring.Get(service(), keyName)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read anthropic key from keychain: %w", err)
	}
	return v, true, nil
}

// DeleteAnthropicKey removes the stored key. Absent is not an error.
func DeleteAnthropicKey() error {
	err := keyring.Delete(service(), keyName)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete anthropic key from keychain: %w", err)
	}
	return nil
}
