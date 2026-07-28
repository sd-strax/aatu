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
import { BackendClient } from "./backend";
import { Session } from "./auth";
import { SidecarTransport } from "./agentTransport";
import { InvestigationDocuments } from "./investigationDocument";
import { EVIDENCE_SCHEME, EvidenceProvider, openEvidence } from "./evidenceProvider";

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

  const investigations = new InvestigationsProvider(client, session);
  // The agent loop lives in the Go sidecar (implementation/agent-sidecar.md);
  // this transport spawns it and answers its getToken callbacks from the auth
  // session — the extension stays the sole auth owner.
  const transport = new SidecarTransport({
    backendUrl: () => backendUrl(),
    model: () => vscode.workspace.getConfiguration("reckon").get<string>("model", "claude-opus-4-8"),
    apiKey: () => context.secrets.get(ANTHROPIC_KEY_SECRET),
    getToken: (kind, force) => session.token(kind, force),
  }, log);
  const documents = new InvestigationDocuments(client, log, transport);
  context.subscriptions.push(
    log,
    session,
    { dispose: () => transport.dispose() },
    // Citation-open: reckon-evidence:/<ref>.json virtual documents (02 §2.8).
    vscode.workspace.registerTextDocumentContentProvider(EVIDENCE_SCHEME, new EvidenceProvider(client)),
    vscode.commands.registerCommand("reckon.openEvidence", (ref?: string) => {
      if (typeof ref === "string" && ref !== "") {
        void openEvidence(ref);
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

    vscode.commands.registerCommand("reckon.newInvestigation", async () => {
      if (!session.signedIn) {
        void vscode.window.showWarningMessage("reckon: sign in before seeding an investigation");
        return;
      }
      const title = await vscode.window.showInputBox({
        title: "reckon — new investigation",
        prompt: "A short title for the investigation (entity or hypothesis rooted).",
        ignoreFocusOut: true,
        placeHolder: "Lateral movement via RDP — host-7",
        validateInput: (v) => (v.trim() === "" ? "a title is required" : undefined),
      });
      if (title === undefined || title.trim() === "") {
        return; // cancelled
      }
      try {
        const created = await client.createInvestigation(title.trim());
        investigations.refresh();
        documents.show(created.id, created.title);
      } catch (err) {
        void vscode.window.showErrorMessage(`reckon: could not seed investigation: ${errText(err)}`);
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
  );

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

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * The Investigations view. Three states, each a distinct honest surface:
 * backend incompatible/unreachable (fail closed with a diagnostic), signed out
 * (a sign-in affordance), or signed in (the real list from /api/investigations).
 */
class InvestigationsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(
    private readonly client: BackendClient,
    private readonly session: Session,
  ) {}

  refresh(): void {
    this.emitter.fire();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: vscode.TreeItem): Promise<vscode.TreeItem[]> {
    if (element) {
      return [];
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
      const rows = await this.client.investigations();
      if (rows.length === 0) {
        const empty = new vscode.TreeItem("No investigations yet");
        empty.description = "seed one to begin";
        empty.iconPath = new vscode.ThemeIcon("search");
        return [empty];
      }
      return rows.map((r) => {
        const item = new vscode.TreeItem(r.title);
        item.description = r.state;
        item.tooltip = `${r.id}\n${r.state}`;
        item.iconPath = new vscode.ThemeIcon("law");
        item.command = {
          command: "reckon.openInvestigation",
          title: "Open Investigation",
          arguments: [r.id, r.title],
        };
        return item;
      });
    } catch (err) {
      // A 401 here means the token went stale under us — surface it, don't hang.
      return [this.actionItem("Could not load investigations", errText(err), "warning", "reckon.refreshInvestigations")];
    }
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
