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

	fmt.Printf("%s agent loop — investigation %s (%d tools). Type a question; /pending lists actions awaiting you; 'exit' to quit.\n",
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
		if strings.HasPrefix(line, "/") {
			runSlashCommand(ctx, client, in, invID, line)
			continue
		}

		res, err := session.Turn(ctx, line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "turn error: %v\n", err)
			if res == nil {
				continue
			}
		}

		// Actions awaiting the ANALYST — everything pending on the investigation,
		// not just this turn's proposals — offered inline, on the human token.
		// This is the human-in-the-loop seam, not UI sugar.
		offerApprovals(ctx, client, in, res.PendingActions)
	}
}

// runSlashCommand handles the surface-side commands (they never reach the
// model): /pending re-lists actions awaiting approval, /approve and /reject
// act on one by id. These exist so a pending action is never stranded — the
// inline offer after a turn is a convenience, not the only path.
func runSlashCommand(ctx context.Context, client *agent.Client, in *bufio.Scanner, invID, line string) {
	fields := strings.Fields(line)
	switch fields[0] {
	case "/pending":
		acts, err := client.ListActions(ctx, invID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list actions: %v\n", err)
			return
		}
		var pending []agent.ActionStatus
		for _, a := range acts {
			if a.Pending() {
				pending = append(pending, a)
			}
		}
		if len(pending) == 0 {
			fmt.Println("no actions awaiting approval")
			return
		}
		offerApprovals(ctx, client, in, pending)
	case "/approve":
		if len(fields) < 2 {
			fmt.Println("usage: /approve <action-id> [T3 challenge text]")
			return
		}
		out, err := client.ApproveAction(ctx, fields[1], strings.Join(fields[2:], " "))
		report("approved", out, err)
	case "/reject":
		if len(fields) < 2 {
			fmt.Println("usage: /reject <action-id> [reason]")
			return
		}
		reason := strings.Join(fields[2:], " ")
		if reason == "" {
			reason = "analyst rejected via /reject"
		}
		out, err := client.RejectAction(ctx, fields[1], reason)
		report("rejected", out, err)
	default:
		fmt.Println("commands: /pending, /approve <id> [challenge], /reject <id> [reason]")
	}
}

// offerApprovals walks pending actions and prompts for each. Only an explicit
// `y`/`n` acts; Enter (or anything unrecognized) defers — the action stays
// pending and is re-offered after the next turn or via /pending. Deliberately
// strict: free text must never approve a containment action by accident.
func offerApprovals(ctx context.Context, client *agent.Client, in *bufio.Scanner, actions []agent.ActionStatus) {
	for _, a := range actions {
		if !a.Pending() {
			continue
		}
		fmt.Printf("\naction %s %s → %s [%s, %s] awaits your approval.\n",
			a.ActionID, a.ActionType, targetList(a.Targets), a.Tier, a.PendingLabel())
		fmt.Print("  approve? [y = approve, y <challenge> for T3, n [reason] = reject, Enter = decide later] ")
		if !in.Scan() {
			return
		}
		fields := strings.Fields(in.Text())
		switch {
		case len(fields) == 0:
			fmt.Println("  left pending (use /pending to come back to it)")
		case strings.EqualFold(fields[0], "y"):
			out, err := client.ApproveAction(ctx, a.ActionID, strings.Join(fields[1:], " "))
			report("approved", out, err)
		case strings.EqualFold(fields[0], "n"):
			reason := strings.Join(fields[1:], " ")
			if reason == "" {
				reason = "analyst declined at the prompt"
			}
			out, err := client.RejectAction(ctx, a.ActionID, reason)
			report("rejected", out, err)
		default:
			fmt.Println("  unrecognized — left pending (only y/n act; use /pending to come back to it)")
		}
	}
}

// targetList renders an action's targets for the approval prompt.
func targetList(targets []agent.ActionTarget) string {
	if len(targets) == 0 {
		return "(no targets)"
	}
	ids := make([]string, len(targets))
	for i, t := range targets {
		ids[i] = t.ResolvedIdentifier
		if ids[i] == "" {
			ids[i] = t.EntityRef
		}
	}
	return strings.Join(ids, ", ")
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
