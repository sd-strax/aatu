// The reckon workbench extension entry point.
//
// v0 slice (design/13 §7): backend version handshake, interactive PKCE login,
// BYOK Anthropic key into SecretStorage, and the real investigation list. The
// investigation document (conversation surface) is the next step.
//
// Workbench discipline (design/13 §3): every surface lives in reckon-owned real
// estate, every action is a command first, and nothing here assumes a workspace
// folder is open — investigation state comes from the backend, not the
// filesystem.

import * as vscode from "vscode";
import { BackendClient, InvestigationSummary } from "./backend";
import { Session } from "./auth";
import { SidecarTransport } from "./agentTransport";
import { InvestigationDocuments } from "./investigationDocument";
import { EVIDENCE_SCHEME, EvidenceProvider } from "./evidenceProvider";
import { EvidenceView } from "./evidenceView";

/** Where the BYOK Anthropic key lives — never in settings, never on disk in the clear. */
const ANTHROPIC_KEY_SECRET = "reckon.anthropicApiKey";

export function activate(context: vscode.ExtensionContext): void {
  const log = vscode.window.createOutputChannel("reckon", { log: true });
  log.info(`workbench activated (backend ${backendUrl()})`);

  const session = new Session(
    context.secrets,
    () => new BackendClient(() => backendUrl()).authConfig(),
    log,
  );
  // Authenticated client: its token source is the session, refreshed on demand.
  const client = new BackendClient(() => backendUrl(), () => session.token());

  // Last-seen event sequences — view state behind the tree's unseen-changes
  // cue (ui/02 §2.12). Never investigation state; lives in globalState.
  const seen = new SeenTracker(context.globalState);
  const investigations = new InvestigationsProvider(client, session, seen);
  // The agent loop lives in the Go sidecar (implementation/agent-sidecar.md);
  // this transport spawns it and answers its getToken callbacks from the auth
  // session — the extension stays the sole auth owner.
  const transport = new SidecarTransport({
    backendUrl: () => backendUrl(),
    model: () => vscode.workspace.getConfiguration("reckon").get<string>("model", "claude-opus-4-8"),
    apiKey: () => context.secrets.get(ANTHROPIC_KEY_SECRET),
    getToken: (kind, force) => session.token(kind, force),
  }, log);
  const evidence = new EvidenceView(client);
  const documents = new InvestigationDocuments(client, log, transport, (id, seq) => {
    void seen.set(id, seq).then(() => investigations.refresh());
  });
  context.subscriptions.push(
    log,
    session,
    { dispose: () => transport.dispose() },
    // Citation-open: reckon-evidence:/<ref>.json virtual documents (02 §2.8).
    vscode.workspace.registerTextDocumentContentProvider(EVIDENCE_SCHEME, new EvidenceProvider(client)),
    vscode.commands.registerCommand("reckon.openEvidence", (ref?: string, currentInvestigationId?: string) => {
      if (typeof ref === "string" && ref !== "") {
        void evidence.open(ref, typeof currentInvestigationId === "string" ? currentInvestigationId : undefined);
      }
    }),
    session.onDidChange(() => {
      void vscode.commands.executeCommand("setContext", "reckon.signedIn", session.signedIn);
      investigations.refresh();
      documents.refreshAll();
    }),
    vscode.window.registerTreeDataProvider("reckon.investigations", investigations),

    vscode.commands.registerCommand("reckon.openInvestigation", (id?: string, title?: string) => {
      if (!id) {
        return; // invoked without a target (e.g. from the palette) — nothing to open
      }
      documents.show(id, title);
    }),

    // Seed a new investigation (design/ui/02 §2.7): open the document in its
    // unseeded state and let the analyst root it by typing a host/IP/hash or a
    // question into the composer — the seed surface IS the document, not a
    // wizard. Nothing is persisted until that first line, which keeps "an
    // investigation always begins from something concrete" honest. The server
    // resolves the typed value (minting the STIX id for an entity), so the
    // analyst never handles ids.
    vscode.commands.registerCommand("reckon.newInvestigation", () => {
      if (!session.signedIn) {
        void vscode.window.showWarningMessage("reckon: sign in before seeding an investigation");
        return;
      }
      documents.showDraft();
    }),

    // Seed an investigation FROM a system-of-record case (14-case-seed.md §4.1).
    // The command only LAUNCHES the flow; the search filter and case pick live
    // on the draft document surface (case mode), never the top-of-window quick
    // input — operational input belongs on a panel (workbench discipline, 13 §3).
    // The read fails closed server-side, so a bad case never seeds a half-loaded
    // investigation.
    vscode.commands.registerCommand("reckon.seedFromCase", () => {
      if (!session.signedIn) {
        void vscode.window.showWarningMessage("reckon: sign in before seeding an investigation");
        return;
      }
      documents.showDraft("case");
    }),

    // Rename an investigation from the tree's context menu (human curation — the
    // aggregate bars an AI delegate). Renaming happens ON the document: this
    // reveals the panel and pops its in-document rename card, so the input is
    // never the top-of-window quick input. The header pencil opens the same card
    // directly. Applying the rename + refreshing the tree is handled there.
    vscode.commands.registerCommand("reckon.renameInvestigation", (arg?: unknown) => {
      if (!session.signedIn) {
        void vscode.window.showWarningMessage("reckon: sign in before renaming an investigation");
        return;
      }
      if (arg && typeof arg === "object" && "invId" in arg) {
        const row = arg as { invId: string; invTitle?: string };
        documents.beginRename(row.invId, row.invTitle);
      }
    }),
    // Context reset (agent honesty): rebuild the agent's working conversation
    // from the engine record, discarding its own accumulated narration — the
    // recovery from narrative poisoning. Investigation state is untouched; the
    // reset is recorded on the thread and survives sidecar respawns.
    vscode.commands.registerCommand("reckon.resetAgentContext", async (arg?: unknown) => {
      if (!session.signedIn) {
        void vscode.window.showWarningMessage("reckon: sign in first");
        return;
      }
      if (!arg || typeof arg !== "object" || !("invId" in arg)) {
        return;
      }
      const row = arg as { invId: string; invTitle?: string };
      const ok = await vscode.window.showWarningMessage(
        `reckon: reset the agent's conversation context for "${row.invTitle ?? row.invId}"? ` +
        "The investigation record (evidence, hypotheses, actions, chronicle) is untouched — " +
        "only the agent's working memory is rebuilt from it. Use this when the conversation " +
        "has drifted from the recorded state.",
        { modal: true },
        "Reset context",
      );
      if (ok !== "Reset context") {
        return;
      }
      try {
        await transport.resetSession(row.invId);
        // The reset is a committed act on the thread; refresh an open panel so
        // the chronicle shows the boundary immediately.
        documents.refreshOpen(row.invId);
        void vscode.window.showInformationMessage(
          "reckon: agent context reset — the next turn starts from the engine record.",
        );
      } catch (err) {
        void vscode.window.showErrorMessage(`reckon: context reset failed — ${err instanceof Error ? err.message : String(err)}`);
      }
    }),

    vscode.commands.registerCommand("reckon.signIn", async () => {
      try {
        await session.signIn();
        const me = await client.me();
        void vscode.window.showInformationMessage(
          `reckon: signed in as ${me.username} (${me.roles.join(", ") || "no roles"})`,
        );
      } catch (err) {
        void vscode.window.showErrorMessage(`reckon sign-in failed: ${errText(err)}`);
      }
    }),

    vscode.commands.registerCommand("reckon.signOut", async () => {
      await session.signOut();
      void vscode.window.showInformationMessage("reckon: signed out");
    }),

    vscode.commands.registerCommand("reckon.setAnthropicKey", async () => {
      const key = await vscode.window.showInputBox({
        title: "reckon — Anthropic API key (BYOK)",
        prompt: "Stored in the OS keychain via SecretStorage; never leaves this machine except in calls to Anthropic.",
        password: true,
        ignoreFocusOut: true,
        placeHolder: "sk-ant-...",
      });
      if (key === undefined) {
        return; // cancelled
      }
      if (key.trim() === "") {
        await context.secrets.delete(ANTHROPIC_KEY_SECRET);
        void vscode.window.showInformationMessage("reckon: Anthropic key cleared");
        return;
      }
      await context.secrets.store(ANTHROPIC_KEY_SECRET, key.trim());
      void vscode.window.showInformationMessage("reckon: Anthropic key stored");
    }),

    vscode.commands.registerCommand("reckon.checkBackend", async () => {
      const status = await client.status();
      const reason = client.incompatibilityReason(status);
      log.info(`status ${backendUrl()}: ${status.overall} (api v${status.apiVersion ?? "?"}, ${reason ?? "compatible"})`);
      if (reason) {
        void vscode.window.showWarningMessage(`reckon: ${reason}`);
      } else {
        const detail = Object.entries(status.components)
          .map(([name, c]) => `${name}: ${c.ready ? "ready" : "NOT READY"} (${c.message})`)
          .join("\n");
        void vscode.window.showInformationMessage(
          `reckon backend ${status.overall} at ${backendUrl()} (API v${status.apiVersion})`,
          { modal: false, detail },
        );
      }
      investigations.refresh();
    }),

    vscode.commands.registerCommand("reckon.refreshInvestigations", () => {
      investigations.refresh();
    }),

    // The profile trim (design/13 §6): investigation-first posture, offered
    // never forced, reversible. What settings CAN do; the honest ceiling —
    // hiding other view containers, rebranding the window, product.json
    // behavior — is the fork's payoff, not the extension's.
    vscode.commands.registerCommand("reckon.applyPosture", () => applyPosture(true)),
    vscode.commands.registerCommand("reckon.revertPosture", () => applyPosture(false)),
  );

  // First-run offer (design/13 §6): once, and "Not now" is remembered. An
  // analyst embedding reckon in their developer profile is a supported choice.
  if (!context.globalState.get<boolean>("reckon.postureOffered")) {
    void context.globalState.update("reckon.postureOffered", true);
    void vscode.window
      .showInformationMessage(
        "reckon: apply the investigation-first workbench posture? (no startup editor, quieter chrome — every bit reversible via “reckon: Revert Workbench Posture”)",
        "Apply", "Not now",
      )
      .then((choice) => {
        if (choice === "Apply") {
          void applyPosture(true);
        }
      });
  }

  // Fire-and-forget: restore a prior session, then seed the signed-in context key.
  void session.restore().finally(() => {
    void vscode.commands.executeCommand("setContext", "reckon.signedIn", session.signedIn);
  });
}

export function deactivate(): void {
  // Session and channel are held in context.subscriptions.
}

function backendUrl(): string {
  return vscode.workspace.getConfiguration("reckon").get<string>("backendUrl", "http://localhost:8080");
}

/**
 * The posture's settings (design/13 §6), applied globally: no startup editor,
 * no command center, no tips, menu bar behind Alt (Win/Linux; macOS keeps its
 * native bar per-OS convention). Revert clears our overrides back to defaults
 * rather than guessing what the user had. Keybindings for the core loop ship
 * via contributes.keybindings and need no toggling.
 */
const POSTURE: Record<string, unknown> = {
  "workbench.startupEditor": "none",
  "window.commandCenter": false,
  "workbench.tips.enabled": false,
  "window.menuBarVisibility": "toggle",
};

async function applyPosture(on: boolean): Promise<void> {
  const cfg = vscode.workspace.getConfiguration();
  for (const [key, value] of Object.entries(POSTURE)) {
    try {
      await cfg.update(key, on ? value : undefined, vscode.ConfigurationTarget.Global);
    } catch {
      // A missing/renamed upstream setting must not break the rest.
    }
  }
  void vscode.window.showInformationMessage(
    on ? "reckon: workbench posture applied (revert any time: “reckon: Revert Workbench Posture”)"
      : "reckon: workbench posture reverted — your defaults are back",
  );
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Per-investigation last-seen event sequence, in globalState. The tree's
 * unseen-changes cue compares this against the backend's last_event_sequence:
 * strictly view state (ui/02 §2.12), so it never touches the record.
 */
class SeenTracker {
  private static readonly KEY = "reckon.seenSeq";

  constructor(private readonly memento: vscode.Memento) {}

  get(id: string): number {
    return this.memento.get<Record<string, number>>(SeenTracker.KEY, {})[id] ?? 0;
  }

  async set(id: string, seq: number): Promise<void> {
    const all = { ...this.memento.get<Record<string, number>>(SeenTracker.KEY, {}) };
    if ((all[id] ?? 0) >= seq) {
      return;
    }
    all[id] = seq;
    await this.memento.update(SeenTracker.KEY, all);
  }
}

/** Display order + collapsed defaults for the status groups (ui/06). */
const TREE_GROUPS: { status: string; label: string; collapsed: boolean }[] = [
  { status: "ACTIVE", label: "Active", collapsed: false },
  { status: "PAUSED", label: "Paused", collapsed: false },
  { status: "DRAFT", label: "Draft", collapsed: false },
  { status: "CONCLUDED", label: "Concluded", collapsed: true },
  { status: "ARCHIVED", label: "Archived", collapsed: true },
];

/** Status dot colors (ui/06): themed chart colors, not hardcoded hex. */
const STATUS_COLOR: Record<string, string> = {
  ACTIVE: "charts.blue",
  PAUSED: "charts.yellow",
  DRAFT: "descriptionForeground",
  CONCLUDED: "charts.purple",
  ARCHIVED: "disabledForeground",
};

/**
 * The Investigations view — a triage queue, not a file listing (ui/06). Three
 * top-level states, each a distinct honest surface: backend incompatible or
 * unreachable (fail closed with a diagnostic), signed out (a sign-in
 * affordance), or signed in — status groups whose rows are ordered
 * needs-me-first: soonest-expiring approval, then pending approvals, then
 * unseen changes, then recency.
 */
class InvestigationsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;
  private rows: InvestigationSummary[] = [];

  constructor(
    private readonly client: BackendClient,
    private readonly session: Session,
    private readonly seen: SeenTracker,
  ) {}

  refresh(): void {
    this.emitter.fire();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: vscode.TreeItem): Promise<vscode.TreeItem[]> {
    if (element) {
      const group = (element as GroupItem).groupStatus;
      return group ? this.groupRows(group) : [];
    }

    const status = await this.client.status();
    const reason = this.client.incompatibilityReason(status);
    if (reason) {
      return [this.actionItem(
        status.reachable ? "Backend incompatible" : "Backend not connected",
        reason,
        status.reachable ? "warning" : "debug-disconnect",
        "reckon.checkBackend",
      )];
    }

    if (!this.session.signedIn) {
      return [this.actionItem("Sign in to reckon", "opens Keycloak in your browser", "sign-in", "reckon.signIn")];
    }

    try {
      this.rows = await this.client.investigations();
    } catch (err) {
      // A 401 here means the token went stale under us — surface it, don't hang.
      return [this.actionItem("Could not load investigations", errText(err), "warning", "reckon.refreshInvestigations")];
    }
    if (this.rows.length === 0) {
      const empty = new vscode.TreeItem("No investigations yet");
      empty.description = "seed one to begin";
      empty.iconPath = new vscode.ThemeIcon("search");
      return [empty];
    }

    const items: vscode.TreeItem[] = [];
    for (const g of TREE_GROUPS) {
      const inGroup = this.rows.filter((r) => r.state.toUpperCase() === g.status);
      if (!inGroup.length) {
        continue;
      }
      // Group-level rollups so a collapsed group still signals what's inside.
      const pending = inGroup.reduce((n, r) => n + r.pendingActions, 0);
      const item = new GroupItem(
        `${g.label} (${inGroup.length})`,
        g.status,
        g.collapsed ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.Expanded,
      );
      if (pending > 0) {
        item.description = `${pending} awaiting approval`;
      }
      items.push(item);
    }
    // Anything in a state outside the known groups still shows (honesty over taxonomy).
    const known = new Set(TREE_GROUPS.map((g) => g.status));
    for (const r of this.rows.filter((x) => !known.has(x.state.toUpperCase()))) {
      items.push(this.rowItem(r));
    }
    return items;
  }

  /** The rows of one status group, needs-me-first (ui/06). */
  private groupRows(status: string): vscode.TreeItem[] {
    const rows = this.rows.filter((r) => r.state.toUpperCase() === status);
    rows.sort((a, b) => {
      // 1. Soonest approval expiry first (an open countdown outranks all).
      const ax = a.nearestExpiry ? Date.parse(a.nearestExpiry) : Infinity;
      const bx = b.nearestExpiry ? Date.parse(b.nearestExpiry) : Infinity;
      if (ax !== bx) return ax - bx;
      // 2. More pending approvals first.
      if (a.pendingActions !== b.pendingActions) return b.pendingActions - a.pendingActions;
      // 3. Unseen changes before caught-up.
      const au = this.unseen(a) ? 0 : 1;
      const bu = this.unseen(b) ? 0 : 1;
      if (au !== bu) return au - bu;
      // 4. Recency.
      return (b.updatedAt ? Date.parse(b.updatedAt) : 0) - (a.updatedAt ? Date.parse(a.updatedAt) : 0);
    });
    return rows.map((r) => this.rowItem(r));
  }

  /** Unseen = the thread grew past what this analyst last had open here. */
  private unseen(r: InvestigationSummary): boolean {
    const last = this.seen.get(r.id);
    return last > 0 && r.lastEventSequence > last;
  }

  private rowItem(r: InvestigationSummary): vscode.TreeItem {
    const item = new InvestigationRowItem(r.title);
    item.invId = r.id;
    item.invTitle = r.title;
    item.contextValue = "reckon.investigation";
    const cues: string[] = [];
    if (r.nearestExpiry) {
      const left = Date.parse(r.nearestExpiry) - Date.now();
      cues.push(left <= 0 ? "⏳ expired" : `⏳ ${fmtShort(left)}`);
    }
    if (r.pendingActions > 0) {
      cues.push(`${r.pendingActions} pending`);
    }
    if (this.unseen(r)) {
      cues.push("● new");
    }
    if (r.seedSummary) {
      cues.push(r.seedSummary);
    }
    item.description = cues.join(" · ");
    item.tooltip = `${r.title}\n${r.id}\n${r.state}${r.seedSummary ? "\n" + r.seedSummary : ""}`;
    const color = STATUS_COLOR[r.state.toUpperCase()] ?? "descriptionForeground";
    // An open approval window trumps the status dot — that row needs a human.
    item.iconPath = r.pendingActions > 0
      ? new vscode.ThemeIcon("bell-dot", new vscode.ThemeColor("charts.orange"))
      : new vscode.ThemeIcon("circle-filled", new vscode.ThemeColor(color));
    item.command = {
      command: "reckon.openInvestigation",
      title: "Open Investigation",
      arguments: [r.id, r.title],
    };
    return item;
  }

  private actionItem(label: string, description: string, icon: string, command: string): vscode.TreeItem {
    const item = new vscode.TreeItem(label);
    item.description = description;
    item.tooltip = description;
    item.iconPath = new vscode.ThemeIcon(icon);
    item.command = { command, title: label };
    return item;
  }
}

/** One investigation row; carries its id/title so the context menu (rename)
 *  can act on it without re-deriving from the label. */
class InvestigationRowItem extends vscode.TreeItem {
  invId = "";
  invTitle = "";
}

/** A status group node; groupStatus keys getChildren back into the rows. */
class GroupItem extends vscode.TreeItem {
  constructor(
    label: string,
    readonly groupStatus: string,
    state: vscode.TreeItemCollapsibleState,
  ) {
    super(label, state);
    this.contextValue = "reckon.group";
  }
}

/** Compact remaining-time label for the tree's ⏳ cue. */
function fmtShort(ms: number): string {
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h}h` : `${Math.floor(h / 24)}d`;
}
