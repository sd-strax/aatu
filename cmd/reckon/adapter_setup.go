package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/adapterplugin"
	"github.com/sd-strax/reckon/internal/adapterruntime"
	"github.com/sd-strax/reckon/internal/adopt"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/internal/bundledadapters"
	"github.com/sd-strax/reckon/internal/mcpclient"
	"github.com/sd-strax/reckon/internal/secretref"
)

// runAdapterSetup provisions an installed adapter's ambient runtime so the
// operator installs nothing (design/11 §3): for a Python MCP bridge it downloads
// a managed uv, builds a pinned isolated venv, installs the pinned package, and
// then runs the one-time interactive login (caching the token so the adapter
// runs headless afterward). One command replaces "install Python, install uv,
// fetch the package, dodge the broken version, log in."
//
//	reckon adapter setup okta [--config tenant.yaml] [--no-auth]
func runAdapterSetup(args []string) error {
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("adapter setup", flag.ContinueOnError)
	configPath := fs.String("config", "", "tenant config to read the adapter's instance config from (default: the reckon config's capability.config_path)")
	sets := kvFlags{}
	fs.Var(sets, "set", "instance config field, key=value; repeatable (the adapter's manifest config_schema names the fields)")
	orgFlag := fs.String("org", "", "alias for --set org_url=… (Okta)")
	clientFlag := fs.String("client-id", "", "alias for --set client_id=… (Okta)")
	scopesFlag := fs.String("scopes", "", "alias for --set scopes=… (Okta)")
	enableWrites := fs.Bool("enable-writes", false, "enable the adapter's write action-types too (else prompted; writes are deliberate, 11 §5)")
	noAuth := fs.Bool("no-auth", false, "provision dependencies only; skip enablement + any one-time login")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for k, v := range map[string]string{"org_url": *orgFlag, "client_id": *clientFlag, "scopes": *scopesFlag} {
		if v != "" {
			sets[k] = v
		}
	}
	if name == "" {
		name = fs.Arg(0)
	}
	if name == "" {
		return fmt.Errorf("usage: %s adapter setup <name> [--config tenant.yaml] [--no-auth]", branding.CLI)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	adapterDir := filepath.Join(cfg.Data.Dir, "adapters", name)
	// For a bundled adapter, (re)install it every time so its binary + manifest
	// always match this reckon build — no separate install step, and no stale
	// bridge after an upgrade. External adapters are loaded as-installed.
	if b, ok := bundledadapters.Get(name); ok {
		if _, ierr := installBundled(b, cfg); ierr != nil {
			return ierr
		}
	}
	installed, err := adapterplugin.Load(adapterDir)
	if err != nil {
		return fmt.Errorf("adapter %q is not installed under %s: %w", name, adapterDir, err)
	}
	rt := installed.Manifest.Runtime
	if rt == nil {
		fmt.Printf("%s has no runtime to provision (native adapter) — nothing to set up.\n", name)
		return nil
	}
	// Provisioning fetches a toolchain + the package — no timeout. The kind
	// selects the mechanism (11 §3): managed python/node keep the zero-prereq
	// promise (reckon downloads the toolchain); container is the one-prereq
	// opt-in (reckon pulls the image, the exec is `docker run -i`).
	ctx := context.Background()
	switch rt.Kind {
	case "python":
		uvBin, err := adapterruntime.EnsureUv(ctx, cfg.Data.Dir, os.Stdout)
		if err != nil {
			return err
		}
		if err := adapterruntime.ProvisionPython(ctx, uvBin, adapterDir, rt.Python, rt.Package, rt.Version, os.Stdout); err != nil {
			return err
		}
		fmt.Printf("✓ %s runtime ready (%s, python %s)\n", name, rt.Package, rt.Python)
	case "node":
		binDir, err := adapterruntime.EnsureNode(ctx, cfg.Data.Dir, os.Stdout)
		if err != nil {
			return err
		}
		if err := adapterruntime.ProvisionNode(ctx, binDir, adapterDir, rt.Package, rt.Version, os.Stdout); err != nil {
			return err
		}
		fmt.Printf("✓ %s runtime ready (%s, managed node)\n", name, rt.Package)
	case "container":
		// EXPERIMENTAL (design/11 §3.2 "v0 scope"): pull + attached run only.
		// The lifecycle contract (named containers, labels, reconciliation
		// sweep, force-kill-by-name, runtime auto-detect) is specified in §3.2
		// but not yet implemented — dev use, not production supervision.
		if rt.Image == "" {
			return fmt.Errorf("adapter %q: runtime kind container requires an image", name)
		}
		if err := dockerPull(ctx, rt.Image); err != nil {
			return err
		}
		fmt.Printf("✓ %s image pulled (%s) — the exec runs it via `docker run -i`\n", name, rt.Image)
		fmt.Printf("  note: the container kind is EXPERIMENTAL in v0 (design/11 §3.2) — lifecycle\n" +
			"  supervision (orphan cleanup, force-stop) is not yet container-aware.\n")
	default:
		return fmt.Errorf("unsupported runtime kind %q (python | node | container)", rt.Kind)
	}

	// Resolve the instance config, schema-driven (the manifest's config_schema
	// exists exactly so enablement can collect config without spawning, 11 §3):
	// flags > the tenant config's existing stanza > an interactive prompt per
	// missing REQUIRED field. x-secret fields are captured no-echo and stored in
	// the OS keychain — only the reference lands in YAML (11 §4.3).
	cfgMap, missing := resolveAdapterConfig(name, installed.Manifest.ConfigSchema, cfg, *configPath, sets, !*noAuth)
	if len(missing) > 0 {
		fmt.Printf("\nDependencies are ready. Skipping enablement — required config missing: %s\n(pass --set %s=…, or configure %s in the tenant config, then re-run setup).\n",
			strings.Join(missing, ", "), missing[0], name)
		return nil
	}

	// Enable the adapter in the tenant config (the shared adopt+enable primitive,
	// 11 §5) so the backend serves it — no hand-edited YAML.
	if err := enableAdapter(name, installed, cfg, *configPath, cfgMap, *enableWrites); err != nil {
		return err
	}

	if !*noAuth {
		// Login priming is vendor-specific. Okta's device-authorization grant
		// needs a one-time interactive login (cached token → headless after); an
		// adapter that authenticates by static secret (e.g. an API key) needs
		// none — the backend resolves its secret reference at spawn.
		if name == "okta" {
			if err := primeAuth(name, adapterDir, *rt, cfgMap["org_url"], cfgMap["client_id"], cfgMap["scopes"]); err != nil {
				return err
			}
		} else {
			fmt.Printf("✓ %s needs no interactive login — the backend resolves its credentials at spawn.\n", name)
		}
	}

	// Apply without a restart if the backend is running (11 §5.1). Best-effort:
	// a signal failure is reported, not fatal — the config is already written.
	if reloaded, rerr := signalReload(); rerr != nil {
		fmt.Printf("  (reload signal failed: %v — restart the backend to serve it)\n", rerr)
	} else if reloaded {
		fmt.Printf("✓ reloaded the running %s — reads are live now (a new WRITE adapter still needs a restart).\n", branding.CLI)
	} else {
		fmt.Printf("  restart the backend (or `%s start`) to serve it.\n", branding.CLI)
	}
	return nil
}

// kvFlags is a repeatable key=value flag.
type kvFlags map[string]string

func (k kvFlags) String() string { return "" }
func (k kvFlags) Set(s string) error {
	key, val, ok := strings.Cut(s, "=")
	if !ok || key == "" {
		return fmt.Errorf("want key=value, got %q", s)
	}
	k[key] = val
	return nil
}

// dockerPull fetches a container-kind adapter's image (11 §3). The container is
// itself the adapter process: the manifest exec runs it with `docker run -i`, so
// the plugin protocol flows over the container's stdio unchanged and config +
// secrets arrive over the wire at configure (never on the docker command line).
func dockerPull(ctx context.Context, image string) error {
	fmt.Printf("pulling container image %s\n", image)
	cmd := exec.CommandContext(ctx, "docker", "pull", image) //nolint:gosec // image is from the pinned manifest
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker pull %s (is a container runtime installed and running?): %w", image, err)
	}
	return nil
}

// enableAdapter computes an adoption plan from the adapter's own describe output
// and writes the enablement (adapter stanza + verb/action bindings) into the
// tenant config file. Reads are enabled wholesale; each write action-type is
// per-op explicit (§5), enabled only with --enable-writes or an interactive yes.
// cfgMap is the resolved instance config; x-secret fields carry REFERENCES,
// which are resolved to plaintext only for this describe spawn (mirroring the
// host's own spawn path) — the references, never the values, are what adopt
// writes into YAML.
func enableAdapter(name string, installed adapterplugin.Installed, cfg config.Config, configOverride string, cfgMap map[string]string, enableAllWrites bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resolved, err := secretref.ResolveConfig(installed.Manifest.ConfigSchema, toAnyMap(cfgMap))
	if err != nil {
		return fmt.Errorf("resolve %s secrets for describe: %w", name, err)
	}
	p, err := adapterplugin.New(name, installed, resolved, version)
	if err != nil {
		return err
	}
	defer p.Close()
	desc, err := p.Describe(ctx)
	if err != nil {
		return fmt.Errorf("describe %s: %w", name, err)
	}

	class, err := installed.Manifest.AdapterClass()
	if err != nil {
		return err
	}
	// Unset optional fields stay OUT of the YAML — the adapter's own configure
	// defaults apply (e.g. the okta bridge's default scopes).
	planCfg := map[string]string{}
	for k, v := range cfgMap {
		if v != "" {
			planCfg[k] = v
		}
	}
	plan := adopt.PlanFrom(desc, name, installed.Manifest.Name, string(class), planCfg,
		readOperations(desc), chooseWrites(desc, enableAllWrites))
	if plan.ReadAdapter == nil && plan.WriteAdapter == nil {
		return nil
	}

	target := configOverride
	if target == "" {
		target = cfg.Capability.ConfigPath
	}
	if target == "" {
		target = filepath.Join(cfg.Data.Dir, "tenant.yaml")
	}
	if err := adopt.Apply(target, plan); err != nil {
		return err
	}

	fmt.Printf("✓ enabled in %s\n  verbs: %s\n", target, strings.Join(plan.Summary.Verbs, ", "))
	if len(plan.Summary.ActionTypes) > 0 {
		fmt.Printf("  actions: %s\n", strings.Join(plan.Summary.ActionTypes, ", "))
	}
	if configOverride == "" && cfg.Capability.ConfigPath == "" {
		fmt.Printf("  set  capability.config_path: %s  in your reckon config, then restart the backend.\n", target)
	} else {
		fmt.Printf("  restart the backend to serve it.\n")
	}
	return nil
}

// readOperations returns the distinct read operations the adapter binds.
func readOperations(desc *adapterplugin.DescribeResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, rb := range desc.DefaultReadBindings {
		if rb.Operation != "" && !seen[rb.Operation] {
			seen[rb.Operation] = true
			out = append(out, rb.Operation)
		}
	}
	return out
}

// chooseWrites selects which write action-types to enable — all with
// enableAll, else one interactive confirm each (§5: writes are deliberate).
func chooseWrites(desc *adapterplugin.DescribeResult, enableAll bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, wb := range desc.DefaultWriteBindings {
		at := wb.ActionType
		if at == "" || seen[at] {
			continue
		}
		seen[at] = true
		switch {
		case enableAll:
			out = append(out, at)
		case stdinIsTerminal():
			ans, _ := promptLine(fmt.Sprintf("Enable the WRITE action %q? [y/N]", at))
			if a := strings.ToLower(strings.TrimSpace(ans)); a == "y" || a == "yes" {
				out = append(out, at)
			}
		}
	}
	return out
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// resolveAdapterConfig assembles the instance config for enablement,
// schema-driven: precedence --set flags (and the Okta aliases) > the tenant
// config's existing stanza > an interactive prompt per missing REQUIRED field.
// A missing x-secret field is captured no-echo and stored in the OS keychain,
// and the config carries only the keychain:// reference — plaintext never lands
// in YAML (11 §4.3); when the keychain is unavailable (headless Linux), it
// falls back to writing an env:// reference and telling the operator which
// variable to export. Optional fields are never prompted. Returns the resolved
// map plus the required fields still missing (non-interactive runs) — the
// caller skips enablement with guidance rather than failing.
func resolveAdapterConfig(name string, schema map[string]any, cfg config.Config, configOverride string, flagVals map[string]string, promptOK bool) (map[string]string, []string) {
	out := map[string]string{}
	for k, v := range flagVals {
		out[k] = v
	}

	// Fill gaps from the tenant config's existing stanza, if one is available.
	cfgPath := configOverride
	if cfgPath == "" {
		cfgPath = cfg.Capability.ConfigPath
	}
	if cfgPath != "" {
		if tc, err := capability.LoadTenantConfig(cfgPath); err == nil {
			if spec, ok := tc.Adapters[name]; ok {
				for k, v := range spec.Config {
					if s, ok := v.(string); ok && s != "" && out[k] == "" {
						out[k] = s
					}
				}
			}
		}
	}

	// Prompt for each still-missing required field, when we can.
	secrets := secretref.SchemaSecretFields(schema)
	var missing []string
	for _, field := range secretref.SchemaRequiredFields(schema) {
		if out[field] != "" {
			continue
		}
		if !promptOK || !stdinIsTerminal() {
			missing = append(missing, field)
			continue
		}
		label := field
		if d := secretref.SchemaFieldDescription(schema, field); d != "" {
			label = fmt.Sprintf("%s (%s)", field, d)
		}
		if !secrets[field] {
			v, _ := promptLine(label)
			if v == "" {
				missing = append(missing, field)
			} else {
				out[field] = v
			}
			continue
		}
		// x-secret: capture no-echo, store, and reference — never the value.
		v, err := promptSecretValue(label)
		if err != nil || v == "" {
			missing = append(missing, field)
			continue
		}
		ref, err := secretref.StoreKeychain("", name+"-"+field, v)
		if err != nil {
			envName := envVarNameFor(name, field)
			fmt.Printf("  keychain unavailable (%v)\n  falling back to an env reference: export %s=<the secret> before starting the backend.\n", err, envName)
			ref = secretref.SchemeEnv + envName
		}
		out[field] = ref
	}
	return out, missing
}

// envVarNameFor derives the env:// variable name for an adapter's secret field
// (e.g. greynoise + api_key → GREYNOISE_API_KEY).
func envVarNameFor(adapter, field string) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z':
				return r - 32
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
				return r
			default:
				return '_'
			}
		}, s)
	}
	return clean(adapter) + "_" + clean(field)
}

// primeAuth runs the adapter's one-time interactive login by spawning the
// provisioned MCP server and making one authenticated call, which triggers the
// device-authorization flow; the server prints the verification URL (streamed to
// the terminal) and caches the token on success.
func primeAuth(name, adapterDir string, rt adapterplugin.RuntimeSpec, orgURL, clientID, scopes string) error {
	if scopes == "" {
		// The same default the bridge's configure applies — the login must prime
		// a token with the scopes the adapter will actually use.
		scopes = "okta.users.read okta.groups.read okta.logs.read okta.users.manage"
	}
	entry := filepath.Join(adapterDir, adapterruntime.VenvDir, "bin", rt.EntrypointName())
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"OKTA_ORG_URL=" + orgURL,
		"OKTA_CLIENT_ID=" + clientID,
		"OKTA_SCOPES=" + scopes,
	}

	fmt.Printf("\n─ One-time %s login ─ (this happens once; the adapter runs on its own afterward)\n", name)
	fmt.Println("  1. A sign-in URL appears below — open it, sign in to Okta, and approve.")
	if runtime.GOOS == "darwin" {
		fmt.Println("  2. macOS then asks for your Mac password one or more times. That is macOS")
		fmt.Println("     letting the Okta client store your token in the Keychain — NOT reckon, and")
		fmt.Println("     nothing reckon can see. Click \"Always Allow\" on each and it won't ask again.")
	}
	fmt.Println()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client, err := mcpclient.Spawn(ctx, []string{entry},
		mcpclient.WithEnv(env),
		mcpclient.WithStderr(func(line string) { fmt.Fprintln(os.Stderr, "  "+line) }),
	)
	if err != nil {
		return fmt.Errorf("start %s: %w", rt.EntrypointName(), err)
	}
	defer client.Close()

	// One authenticated call triggers the device flow and verifies access.
	if _, err := client.CallTool(ctx, "list_users", nil); err != nil {
		return fmt.Errorf("login/verify failed: %w", err)
	}
	fmt.Printf("\n✓ %s login complete — token cached; the adapter now runs headless.\n", name)
	return nil
}
