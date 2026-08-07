package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// promptLine reads one visible line for a non-secret value (e.g. an org URL or
// client id). Callers gate on stdinIsTerminal(). An empty answer returns "".
func promptLine(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	return strings.TrimSpace(line), nil
}

// stdinIsTerminal reports whether we can prompt interactively. When false,
// `reckon init` passes no prompt callback and a no-source secret fails fast
// instead — the non-interactive (CI/IaC) contract.
func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// promptSecretValue reads a secret (e.g. a vendor API key) without echo, no
// retype: unlike an install password, a mistyped key is cheaply detected at
// first use and pasteable input rarely typos. Callers gate on stdinIsTerminal().
func promptSecretValue(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s (input hidden): ", label)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// promptNewPassword reads a new password for label without echo, confirming it
// by retype. It is the interactive source for `reckon init` — the deliberate
// alternative to auto-generation. Callers gate on stdinIsTerminal(); a typo here
// would bake into initdb / the Keycloak bootstrap on first `start`, so the
// retype guard is worth the second prompt.
func promptNewPassword(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "Set the %s (input hidden): ", label)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	pw := strings.TrimSpace(string(first))
	if pw == "" {
		return "", fmt.Errorf("empty password")
	}

	fmt.Fprintf(os.Stderr, "Re-enter the %s: ", label)
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password confirmation: %w", err)
	}
	if pw != strings.TrimSpace(string(second)) {
		return "", fmt.Errorf("passwords did not match")
	}
	return pw, nil
}
