package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/internal/clientcreds"
)

// runSetAnthropicKey stores the BYOK Anthropic key in the OS keychain (client
// side — it never reaches the backend). The key is read without echo from a
// terminal, or from stdin when piped, so it never lands in shell history.
func runSetAnthropicKey() error {
	var key string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Anthropic API key (input hidden): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("read key: %w", err)
		}
		key = strings.TrimSpace(string(b))
	} else {
		b, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return fmt.Errorf("read key from stdin: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if key == "" {
		return fmt.Errorf("no key provided")
	}
	if err := clientcreds.SetAnthropicKey(key); err != nil {
		return fmt.Errorf("%w\n  (no OS keychain here? on a headless host set ANTHROPIC_API_KEY instead)", err)
	}
	fmt.Fprintf(os.Stderr, "%s: Anthropic key stored in the OS keychain — client-side, never sent to the backend.\n", branding.CLI)
	return nil
}

// runUnsetAnthropicKey removes the stored key from the keychain.
func runUnsetAnthropicKey() error {
	if err := clientcreds.DeleteAnthropicKey(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: Anthropic key removed from the OS keychain.\n", branding.CLI)
	return nil
}

// resolveAnthropicKey returns the BYOK key with precedence env > keychain, so
// CI/automation (ANTHROPIC_API_KEY) always wins and interactive use falls back
// to the keychain. A clear error names both paths when neither is set.
func resolveAnthropicKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); k != "" {
		return k, nil
	}
	k, found, err := clientcreds.GetAnthropicKey()
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("no Anthropic API key (the loop is BYOK — the key never reaches the backend): set ANTHROPIC_API_KEY, or run `%s set-anthropic-key`", branding.CLI)
	}
	return k, nil
}
