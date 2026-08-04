package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/internal/adapterplugin"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/internal/mcpclient"
)

// runAdapter dispatches the `adapter` subcommands. Today only `test` (the §7
// conformance verb) exists; `enable`/`list` (11 §5) are config-file sugar that
// can join later.
func runAdapter(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s adapter test <path-to-adapter-dir> [flags]", branding.CLI)
	}
	switch args[0] {
	case "install":
		return runAdapterInstall(args[1:])
	case "setup":
		return runAdapterSetup(args[1:])
	case "test":
		return runAdapterTest(args[1:])
	case "mcp-probe":
		return runMcpProbe(args[1:])
	default:
		return fmt.Errorf("unknown adapter subcommand %q (want: install, setup, test, mcp-probe)", args[0])
	}
}

// runMcpProbe spawns a vendor MCP server, runs the MCP handshake, and prints its
// tools — the live "handshake for truth" check for an MCP-class adapter before
// the reckon bridge is wired. It inherits the shell environment (so vendor
// config like OKTA_ORG_URL/OKTA_CLIENT_ID/OKTA_SCOPES flows through) and streams
// the server's stderr to the terminal, so an interactive device-login URL is
// visible. Optionally calls one tool.
//
//	OKTA_ORG_URL=… OKTA_CLIENT_ID=… OKTA_SCOPES="okta.users.read …" \
//	  reckon adapter mcp-probe -- uvx okta-mcp-server
//	reckon adapter mcp-probe --call list_users -- uvx okta-mcp-server
func runMcpProbe(args []string) error {
	fs := flag.NewFlagSet("adapter mcp-probe", flag.ContinueOnError)
	call := fs.String("call", "", "after listing tools, call this tool and print its result")
	argsJSON := fs.String("args", "{}", "JSON arguments for --call")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return fmt.Errorf("usage: %s adapter mcp-probe [--call tool] -- <server-exec> [args...]", branding.CLI)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // device login is interactive
	defer cancel()

	client, err := mcpclient.Spawn(ctx, argv,
		mcpclient.WithEnv(os.Environ()),
		mcpclient.WithStderr(func(line string) { fmt.Fprintln(os.Stderr, "  [mcp] "+line) }),
	)
	if err != nil {
		return err
	}
	defer client.Close()

	si := client.ServerInfo()
	fmt.Printf("connected to MCP server %q v%s\n", si.Name, si.Version)

	tools, err := client.ListTools(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("tools (%d):\n", len(tools))
	for _, t := range tools {
		fmt.Printf("  - %s — %s\n", t.Name, t.Description)
	}

	if *call != "" {
		var toolArgs map[string]any
		if err := json.Unmarshal([]byte(*argsJSON), &toolArgs); err != nil {
			return fmt.Errorf("--args is not valid JSON: %w", err)
		}
		res, err := client.CallTool(ctx, *call, toolArgs)
		if err != nil {
			return err
		}
		fmt.Printf("\ncall %s (isError=%t):\n%s\n", *call, res.IsError, res.Text())
	}
	return nil
}

// runAdapterTest is the conformance harness (11 §7): it spawns an adapter, runs
// the initialize/describe/configure handshake, validates the described surface
// against the descriptor shapes, and — when asked — exercises one operation so
// an author has a tight authoring loop instead of print-debugging over stdio.
// "Passing conformance is the definition of speaks the protocol."
//
//	reckon adapter test <dir> [--config f.json] [--invoke op --params '{...}']
//	                          [--dispatch op --params '{...}' --idem key]
func runAdapterTest(args []string) error {
	// Accept the directory as a leading positional (`test <dir> --flags`, the
	// natural form) as well as after the flags — Go's flag package stops at the
	// first non-flag arg, so pop a leading positional before parsing.
	var dir string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("adapter test", flag.ContinueOnError)
	configPath := fs.String("config", "", "JSON file with the instance config delivered to `configure` (11 §4.3)")
	invokeOp := fs.String("invoke", "", "after the handshake, invoke this read operation and print the result")
	dispatchOp := fs.String("dispatch", "", "after the handshake, dispatch this write operation and print the WriteResult")
	paramsJSON := fs.String("params", "{}", "JSON params for --invoke/--dispatch")
	idem := fs.String("idem", "conformance-test", "idempotency key for --dispatch")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if dir == "" {
		dir = fs.Arg(0)
	}
	if dir == "" {
		return fmt.Errorf("usage: %s adapter test <path-to-adapter-dir> [flags]", branding.CLI)
	}

	rep := &confReport{}

	installed, err := adapterplugin.Load(dir)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	class, _ := installed.Manifest.AdapterClass()
	fmt.Printf("adapter %q v%s (class %s)\n", installed.Manifest.Name, installed.Manifest.Version, class)
	rep.pass("manifest parses, class known, protocol overlaps")

	config, err := loadConfigJSON(*configPath)
	if err != nil {
		return err
	}

	// New does not spawn; Describe runs the full handshake (initialize →
	// describe → configure). A failure here is a handshake/spawn failure.
	p, err := adapterplugin.New("conformance", installed, config, version)
	if err != nil {
		return err
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	desc, err := p.Describe(ctx)
	if err != nil {
		rep.fail("handshake (initialize/describe/configure): " + err.Error())
		return rep.finish()
	}
	rep.pass("handshake completed (initialize + describe + configure)")
	validateDescribe(desc, rep)
	printDescribe(desc)

	if h := p.Health(); h.Healthy {
		rep.pass("health: " + orDefault(h.Message, "healthy"))
	} else {
		rep.fail("health: " + orDefault(h.Message, "unhealthy"))
	}

	var params map[string]any
	if err := json.Unmarshal([]byte(*paramsJSON), &params); err != nil {
		return fmt.Errorf("--params is not valid JSON: %w", err)
	}

	if *invokeOp != "" {
		resp, err := p.Invoke(ctx, *invokeOp, params)
		if err != nil {
			rep.fail(fmt.Sprintf("invoke %s: %v", *invokeOp, err))
		} else {
			rep.pass(fmt.Sprintf("invoke %s → %d event(s) via %q", *invokeOp, len(resp.Events), resp.SourceTool))
		}
	}
	if *dispatchOp != "" {
		res, err := p.Dispatch(ctx, *dispatchOp, params, *idem)
		if err != nil {
			rep.fail(fmt.Sprintf("dispatch %s: %v", *dispatchOp, err))
		} else {
			rep.pass(fmt.Sprintf("dispatch %s → %s (per-target %v)", *dispatchOp, res.FinalOutcome, res.PerTargetResults))
		}
	}

	return rep.finish()
}

// validateDescribe checks the described surface against the descriptor shapes
// (§4.2). It never trusts the adapter on tier/reversibility — those are
// engine-side risk judgments — so a claimed tier is only surfaced, never graded.
func validateDescribe(desc *adapterplugin.DescribeResult, rep *confReport) {
	if len(desc.Verbs) == 0 && len(desc.ActionTypes) == 0 {
		rep.fail("describe returned no verbs and no action types — nothing to enable")
		return
	}
	ops := map[string]bool{}
	for _, o := range desc.Operations {
		if o.Name == "" {
			rep.fail("describe: an operation has an empty name")
			continue
		}
		ops[o.Name] = true
	}
	for _, v := range desc.Verbs {
		if v.Verb == "" {
			rep.fail("describe: a verb has an empty name")
		}
	}
	for _, a := range desc.ActionTypes {
		if a.ActionType == "" {
			rep.fail("describe: an action type has an empty name")
			continue
		}
		if a.Reversibility == action.ReversibilityReversible && a.ReversibleBy == "" {
			rep.fail(fmt.Sprintf("describe: action %q claims reversible but names no reversible_by op", a.ActionType))
		}
	}
	// Default bindings must reference operations the adapter actually describes
	// (manifest-for-enumeration, handshake-for-truth — a binding to a phantom op
	// would fail at dispatch).
	for _, b := range desc.DefaultReadBindings {
		if b.Operation != "" && !ops[b.Operation] {
			rep.fail(fmt.Sprintf("describe: read binding references undescribed operation %q", b.Operation))
		}
	}
	for _, b := range desc.DefaultWriteBindings {
		if b.Operation != "" && !ops[b.Operation] {
			rep.fail(fmt.Sprintf("describe: write binding references undescribed operation %q", b.Operation))
		}
	}
	rep.pass(fmt.Sprintf("describe well-formed: %d verb(s), %d action type(s), %d operation(s)",
		len(desc.Verbs), len(desc.ActionTypes), len(desc.Operations)))
}

func printDescribe(desc *adapterplugin.DescribeResult) {
	if len(desc.Verbs) > 0 {
		fmt.Println("  read verbs:")
		for _, v := range desc.Verbs {
			fmt.Printf("    - %s — %s\n", v.Verb, v.Intent)
		}
	}
	if len(desc.ActionTypes) > 0 {
		fmt.Println("  action types (tier/reversibility are ENGINE-owned; adapter claims shown for reference):")
		for _, a := range desc.ActionTypes {
			fmt.Printf("    - %s [claims tier=%s reversibility=%s]\n", a.ActionType, orDefault(a.DefaultTier, "?"), orDefault(a.Reversibility, "?"))
		}
	}
}

// confReport accumulates conformance results and prints a report.
type confReport struct {
	failures []string
}

func (r *confReport) pass(msg string) { fmt.Printf("  ✓ %s\n", msg) }

func (r *confReport) fail(msg string) {
	fmt.Printf("  ✗ %s\n", msg)
	r.failures = append(r.failures, msg)
}

func (r *confReport) finish() error {
	fmt.Println()
	if len(r.failures) == 0 {
		fmt.Println("conformance: PASS")
		return nil
	}
	return fmt.Errorf("conformance: FAIL (%d issue(s))", len(r.failures))
}

func loadConfigJSON(path string) (map[string]any, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --config %s: %w", path, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse --config %s: %w", path, err)
	}
	return cfg, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
