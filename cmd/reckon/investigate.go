package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
)

// runInvestigate drives the interactive agent loop (05 §3.4) against a running
// backend: `reckon investigate <investigation-id>`. The loop is client-side by
// architectural commitment — the Anthropic key stays in this process (BYOK) and
// every agent-driven backend call carries the delegate token, so the engine's
// AI write protections hold no matter what the model asks for.
//
// v0 auth is the direct-access grant against the bundled realm's two clients
// (RECKON_USER / RECKON_PASSWORD, defaulting to the bundled first-run admin):
// the same credentials mint the human token (reckon client) and the delegate
// token (reckon-agent client). Token refresh is not handled — a session outlives
// its 1h token only by restarting; fine for v0.
func runInvestigate(invID string) error {
	if invID == "" {
		return fmt.Errorf("usage: %s investigate <investigation-id>", branding.CLI)
	}
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY is not set (the loop is BYOK — the key never reaches the backend)")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	issuer := fmt.Sprintf("http://localhost:%d/realms/%s", cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm)
	backendURL := fmt.Sprintf("http://localhost:%d", cfg.Backend.HTTPPort)

	user := envOr("RECKON_USER", branding.CLI+"-admin")
	pass := envOr("RECKON_PASSWORD", branding.CLI)

	ctx := context.Background()
	humanToken, err := agent.PasswordToken(ctx, issuer, branding.CLI, user, pass)
	if err != nil {
		return fmt.Errorf("login (human client): %w", err)
	}
	agentToken, err := agent.PasswordToken(ctx, issuer, branding.CLI+"-agent", user, pass)
	if err != nil {
		return fmt.Errorf("login (agent client): %w", err)
	}

	client := agent.NewClient(backendURL, agentToken, humanToken)
	llm := &agent.Anthropic{APIKey: apiKey, Model: envOr("RECKON_MODEL", agent.DefaultAnthropicModel)}

	session, err := agent.NewSession(ctx, agent.Config{
		Backend:         client,
		LLM:             llm,
		InvestigationID: invID,
		Hooks: agent.Hooks{
			OnText: func(text string) {
				fmt.Printf("\n%s\n", text)
			},
			OnToolCall: func(name string, input json.RawMessage) {
				fmt.Printf("  → %s %s\n", name, compactJSON(input))
			},
			OnToolResult: func(name, content string, isError bool) {
				mark := "✓"
				if isError {
					mark = "✗"
				}
				fmt.Printf("  %s %s: %s\n", mark, name, clip(content, 200))
			},
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("%s agent loop — investigation %s (%d tools). Type a question; 'exit' to quit.\n",
		branding.CLI, invID, len(session.Tools()))

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	for {
		fmt.Print("\n> ")
		if !in.Scan() {
			return in.Err()
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			return nil
		}

		res, err := session.Turn(ctx, line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "turn error: %v\n", err)
			if res == nil {
				continue
			}
		}

		// Actions the model proposed await the ANALYST — offer approval inline,
		// on the human token. This is the human-in-the-loop seam, not UI sugar.
		for _, a := range res.PendingActions {
			if a.Status != "PENDING_MANUAL" && a.Status != "PENDING_TWO_PARTY" {
				continue
			}
			fmt.Printf("\naction %s [%s, %s] awaits your approval. approve? [y/N/challenge text for T3] ", a.ActionID, a.Tier, a.Status)
			if !in.Scan() {
				return in.Err()
			}
			answer := strings.TrimSpace(in.Text())
			switch {
			case answer == "" || strings.EqualFold(answer, "n"):
				out, err := client.RejectAction(ctx, a.ActionID, "analyst declined at the prompt")
				report("rejected", out, err)
			case strings.EqualFold(answer, "y"):
				out, err := client.ApproveAction(ctx, a.ActionID, "")
				report("approved", out, err)
			default:
				// A T3 approval requires the typed challenge — pass the text through.
				out, err := client.ApproveAction(ctx, a.ActionID, answer)
				report("approved", out, err)
			}
		}
	}
}

func report(verb string, out json.RawMessage, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", verb, err)
		return
	}
	fmt.Printf("%s: %s\n", verb, compactJSON(out))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func compactJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return clip(buf.String(), 200)
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
