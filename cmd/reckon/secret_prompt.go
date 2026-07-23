package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// stdinIsTerminal reports whether we can prompt interactively. When false,
// `reckon init` passes no prompt callback and a no-source secret fails fast
// instead — the non-interactive (CI/IaC) contract.
func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
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
