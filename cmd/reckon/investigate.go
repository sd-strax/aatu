package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
)

// toolExchange is one tool call + its full result from the most recent turn,
// retained surface-side so /raw can show the untruncated payload the live
// ticker clips. Reset at the start of every agent turn.
type toolExchange struct {
	name    string
	input   string
	content string
	isError bool
}

// repl holds the interactive session's surface-side state: the backend client,
// the input scanner, and the last turn's tool exchanges (for /raw). The agent
// Session owns the reasoning; this owns the analyst's console.
type repl struct {
	client    *agent.Client
	invID     string
	in        *bufio.Scanner
	lastTools []toolExchange
}

// runInvestigate drives the interactive agent loop (05 §3.4) against a running
// backend: `reckon investigate <investigation-id>`. The loop is client-side by
// architectural commitment — the Anthropic key stays in this process (BYOK) and
// every agent-driven backend call carries the delegate token, so the engine's
// AI write protections hold no matter what the model asks for.
//
// v0 auth is the direct-access (ROPC) grant against the two realm clients
// (RECKON_USER / RECKON_PASSWORD, defaulting to the dev-auth principal): the
// same credentials mint the human token (reckon client) and the delegate token
// (reckon-agent client). The shipped realm carries neither the grant nor the
// user — run `reckon dev-auth` once to provision both (implementation/jwt-claims.md).
// Token refresh is not handled — a session outlives its 1h token only by
// restarting; fine for this deferred dev surface.
func runInvestigate(invID string) error {
	if invID == "" {
		return fmt.Errorf("usage: %s investigate <investigation-id>", branding.CLI)
	}
	apiKey, err := resolveAnthropicKey()
	if err != nil {
		return err
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
	humanCred, err := agent.NewCredential(ctx, issuer, branding.CLI, user, pass)
	if err != nil {
		return fmt.Errorf("login (human client): %w\n  hint: the shipped realm has no login user and ROPC is off — run `%s dev-auth` first", err, branding.CLI)
	}
	agentCred, err := agent.NewCredential(ctx, issuer, branding.CLI+"-agent", user, pass)
	if err != nil {
		return fmt.Errorf("login (agent client): %w", err)
	}

	client := agent.NewClient(backendURL, agentCred, humanCred)
	llm := &agent.Anthropic{
		APIKey: apiKey,
		Model:  envOr("RECKON_MODEL", agent.DefaultAnthropicModel),
		OnRetry: func(attempt int, wait time.Duration, _ error) {
			fmt.Fprintf(os.Stderr, "  provider busy (attempt %d), retrying in %s…\n", attempt, wait.Round(time.Second))
		},
	}

	r := &repl{client: client, invID: invID}

	session, err := agent.NewSession(ctx, agent.Config{
		Backend:         client,
		LLM:             llm,
		InvestigationID: invID,
		Hooks: agent.Hooks{
			OnText: func(text string) {
				fmt.Printf("\n%s\n", text)
			},
			OnToolCall: func(name string, input json.RawMessage) {
				fmt.Printf("  → %s %s\n", sanitizeTerminal(name), sanitizeTerminal(compactJSON(input)))
				r.lastTools = append(r.lastTools, toolExchange{name: name, input: string(input)})
			},
			OnToolResult: func(name, content string, isError bool) {
				mark := "✓"
				if isError {
					mark = "✗"
				}
				fmt.Printf("  %s %s: %s\n", mark, sanitizeTerminal(name), sanitizeTerminal(clip(content, 200)))
				// Attach the full result to the call recorded a moment ago
				// (OnToolCall → dispatch → OnToolResult run in sequence per tool).
				if n := len(r.lastTools); n > 0 {
					r.lastTools[n-1].content = content
					r.lastTools[n-1].isError = isError
				}
			},
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("%s agent loop — investigation %s (%d tools). Type a question; /help for commands; 'exit' to quit.\n",
		branding.CLI, invID, len(session.Tools()))

	r.in = bufio.NewScanner(os.Stdin)
	r.in.Buffer(make([]byte, 1<<20), 1<<20)
	for {
		fmt.Print("\n> ")
		if !r.in.Scan() {
			return r.in.Err()
		}
		line := strings.TrimSpace(r.in.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			return nil
		}
		if strings.HasPrefix(line, "/") {
			r.runSlashCommand(ctx, line)
			continue
		}

		// A fresh turn: clear the raw-result buffer so /raw shows THIS turn.
		r.lastTools = nil
		res, err := session.Turn(ctx, line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "turn error: %v\n", err)
			if res == nil {
				continue
			}
		}

		// A compact token readout per turn — tokens are model-agnostic (no dollar
		// estimate here; the eval report owns pricing). cache-read tokens show
		// prompt caching working.
		if u := res.Usage; u != (agent.Usage{}) {
			fmt.Printf("  [%d in / %d out, %d cached]\n", u.Input+u.CacheWrite+u.CacheRead, u.Output, u.CacheRead)
		}

		// Actions awaiting the ANALYST — everything pending on the investigation,
		// not just this turn's proposals — offered inline, on the human token.
		// This is the human-in-the-loop seam, not UI sugar.
		r.offerApprovals(ctx, res.PendingActions)
	}
}

// runSlashCommand handles the surface-side commands (they never reach the
// model): /help lists them, /raw dumps the last turn's untruncated tool
// results, /pending re-lists actions awaiting approval, /approve and /reject
// act on one by id. These exist so a pending action is never stranded and the
// raw telemetry is inspectable without asking the agent to regurgitate it.
func (r *repl) runSlashCommand(ctx context.Context, line string) {
	fields := strings.Fields(line)
	switch fields[0] {
	case "/help":
		printHelp()
	case "/raw":
		r.printRaw(fields[1:])
	case "/pending":
		acts, err := r.client.ListActions(ctx, r.invID)
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
		r.offerApprovals(ctx, pending)
	case "/approve":
		if len(fields) < 2 {
			fmt.Println("usage: /approve <action-id> [T3 challenge text]")
			return
		}
		out, err := r.client.ApproveAction(ctx, fields[1], strings.Join(fields[2:], " "))
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
		out, err := r.client.RejectAction(ctx, fields[1], reason)
		report("rejected", out, err)
	default:
		fmt.Printf("unknown command %q — /help for the list\n", fields[0])
	}
}

// printHelp enumerates the full command surface. This is the discoverable list
// (the inline ticker and approval prompt only hint at parts of it).
func printHelp() {
	fmt.Print(`commands:
  <text>                      ask the agent — runs an investigation turn
  /raw [verb]                 show the last turn's tool results in full (JSON, untruncated);
                              optionally just one verb, e.g. /raw enumerate_logons
  /pending                    list actions awaiting your approval and offer each
  /approve <id> [challenge]   approve an action by id (challenge text required for T3)
  /reject <id> [reason]       reject an action by id
  /help                       this list
  exit | quit                 leave

after a turn that proposes actions, an inline approval prompt appears:
  y               approve
  y <challenge>   approve a T3 action with its challenge text
  n [reason]      reject
  Enter           defer — the action stays pending; revisit with /pending
`)
}

// printRaw prints the most recent turn's tool exchanges with their full,
// untruncated result payloads (the OCSF events + normalized objects a
// capability verb returns) — the raw view the 200-char live ticker clips. An
// optional verb argument filters to that one tool.
func (r *repl) printRaw(args []string) {
	if len(r.lastTools) == 0 {
		fmt.Println("no tool results yet — ask the agent something that queries data first")
		return
	}
	want := ""
	if len(args) > 0 {
		want = args[0]
	}
	shown := 0
	for _, tx := range r.lastTools {
		if want != "" && tx.name != want {
			continue
		}
		shown++
		mark := "✓"
		if tx.isError {
			mark = "✗"
		}
		fmt.Printf("\n%s %s  %s\n%s\n", mark, sanitizeTerminal(tx.name),
			sanitizeTerminalBlock(tx.input), sanitizeTerminalBlock(prettyJSON(tx.content)))
	}
	if shown == 0 {
		fmt.Printf("no tool named %q in the last turn (have: %s)\n", want, sanitizeTerminal(strings.Join(r.toolNames(), ", ")))
	}
}

// toolNames lists the distinct tool names from the last turn (for /raw's hint).
func (r *repl) toolNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, tx := range r.lastTools {
		if !seen[tx.name] {
			seen[tx.name] = true
			names = append(names, tx.name)
		}
	}
	return names
}

// offerApprovals walks pending actions and prompts for each. Only an explicit
// `y`/`n` acts; Enter (or anything unrecognized) defers — the action stays
// pending and is re-offered after the next turn or via /pending. Deliberately
// strict: free text must never approve a containment action by accident.
func (r *repl) offerApprovals(ctx context.Context, actions []agent.ActionStatus) {
	for _, a := range actions {
		if !a.Pending() {
			continue
		}
		// An elapsed approval window means the engine refuses the approve
		// (lazily — status may still read REQUESTED, 04). Don't offer an act
		// that can only fail; say why instead.
		if a.Expired(time.Now()) {
			fmt.Printf("\naction %s %s → %s [%s] EXPIRED at %s — approval window elapsed; re-request if still needed.\n",
				a.ActionID, sanitizeTerminal(a.ActionType), targetList(a.Targets), a.Tier,
				a.ExpiresAt.UTC().Format(time.RFC3339))
			continue
		}
		fmt.Printf("\naction %s %s → %s [%s, %s] awaits your approval.\n",
			a.ActionID, sanitizeTerminal(a.ActionType), targetList(a.Targets), a.Tier, a.PendingLabel())
		fmt.Print("  approve? [y = approve, y <challenge> for T3, n [reason] = reject, Enter = decide later] ")
		if !r.in.Scan() {
			return
		}
		fields := strings.Fields(r.in.Text())
		switch {
		case len(fields) == 0:
			fmt.Println("  left pending (use /pending to come back to it)")
		case strings.EqualFold(fields[0], "y"):
			out, err := r.client.ApproveAction(ctx, a.ActionID, strings.Join(fields[1:], " "))
			report("approved", out, err)
		case strings.EqualFold(fields[0], "n"):
			reason := strings.Join(fields[1:], " ")
			if reason == "" {
				reason = "analyst declined at the prompt"
			}
			out, err := r.client.RejectAction(ctx, a.ActionID, reason)
			report("rejected", out, err)
		default:
			fmt.Println("  unrecognized — left pending (only y/n act; use /pending to come back to it)")
		}
	}
}

// targetList renders an action's targets for the approval prompt. The
// identifiers are model-supplied (via request_action) and echoed at the human
// approval gate, so each is neutralized for terminal display — a crafted
// resolved_identifier must never move the cursor or rewrite the line the analyst
// reads before typing `y`.
func targetList(targets []agent.ActionTarget) string {
	if len(targets) == 0 {
		return "(no targets)"
	}
	ids := make([]string, len(targets))
	for i, t := range targets {
		id := t.ResolvedIdentifier
		if id == "" {
			id = t.EntityRef
		}
		ids[i] = sanitizeTerminal(id)
	}
	return strings.Join(ids, ", ")
}

// sanitizeTerminal renders untrusted text (model- or tool-supplied) safe for a
// SINGLE-LINE terminal display: every control byte — ANSI escape, CR, LF,
// backspace, DEL, C1 — becomes a visible \xNN escape, so a crafted action target
// or tool result cannot move the cursor, rewrite the line, or forge prompt
// framing at the human approval gate. Printable UTF-8 passes through unchanged.
func sanitizeTerminal(s string) string { return sanitize(s, false) }

// sanitizeTerminalBlock is sanitizeTerminal for MULTI-LINE views (/raw): it
// keeps newlines and tabs (legitimate JSON layout) but still neutralizes
// cursor-control bytes so an injected result cannot rewrite the pane.
func sanitizeTerminalBlock(s string) string { return sanitize(s, true) }

func sanitize(s string, keepLayout bool) string {
	if strings.IndexFunc(s, func(r rune) bool { return isTerminalControl(r, keepLayout) }) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isTerminalControl(r, keepLayout) {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isTerminalControl reports whether r is a control byte that must not reach the
// terminal verbatim: C0 (incl. ESC/CR/LF), DEL, and C1. In a multi-line context
// newline and tab are structural layout, not control, so they are kept.
func isTerminalControl(r rune, keepLayout bool) bool {
	if keepLayout && (r == '\n' || r == '\t') {
		return false
	}
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
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

// prettyJSON indents a JSON string for the /raw view. Non-JSON content (e.g. a
// plain error result) is returned unchanged rather than mangled.
func prettyJSON(s string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "", "  "); err != nil {
		return s
	}
	return buf.String()
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
