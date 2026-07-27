package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/internal/sidecar"
)

// runSidecar is `reckon investigate --stdio`: the workbench-facing agent-loop
// server (implementation/agent-sidecar.md). The extension spawns this process,
// speaks LSP-framed JSON-RPC over stdin/stdout, and supplies tokens via the
// getToken callback — this process runs the canonical Go loop and holds no
// refresh tokens, no passwords, and (when the key arrives at initialize) no
// persistent model credential.
//
// stdout is the protocol channel, so every diagnostic goes to stderr —
// including the standard logger, which components deep in the stack may use.
func runSidecar() error {
	log.SetOutput(os.Stderr)

	return sidecar.Serve(context.Background(), os.Stdin, os.Stdout, sidecar.Options{
		ServerVersion: version,
		NewLLM: func(model, apiKey string) agent.LLM {
			return &agent.Anthropic{
				APIKey: apiKey,
				Model:  model,
				OnRetry: func(attempt int, wait time.Duration, _ error) {
					fmt.Fprintf(os.Stderr, "provider busy (attempt %d), retrying in %s\n", attempt, wait.Round(time.Second))
				},
			}
		},
		// The extension normally passes the BYOK key at initialize (its
		// SecretStorage copy); the fallback covers a host that provisioned the
		// key CLI-side instead (env → OS keychain).
		FallbackAPIKey: resolveAnthropicKey,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "sidecar: "+format+"\n", args...)
		},
	})
}
