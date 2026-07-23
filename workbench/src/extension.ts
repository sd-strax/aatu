// The reckon workbench extension entry point.
//
// Scaffold stage: the reckon view container, an Investigations placeholder
// view, and a backend connectivity check. The v0 slice lands in the order of
// design/13 §7; this file grows the session/auth step next.
//
// Workbench discipline (design/13 §3): every surface lives in reckon-owned
// real estate, every action is a command first, and nothing here assumes a
// workspace folder is open — investigation state comes from the backend, not
// the filesystem.

import * as vscode from "vscode";
import { BackendClient } from "./backend";

export function activate(context: vscode.ExtensionContext): void {
  // A named output channel, so "did it activate?" has a positive answer rather
  // than silence — the dev host is a noisy place.
  const log = vscode.window.createOutputChannel("reckon", { log: true });
  log.info(`workbench activated (backend ${backendUrl()})`);

  const client = new BackendClient(() => backendUrl());

  const investigations = new InvestigationsProvider(client);
  context.subscriptions.push(
    log,
    vscode.window.registerTreeDataProvider("reckon.investigations", investigations),

    vscode.commands.registerCommand("reckon.checkBackend", async () => {
      const status = await client.status();
      const reason = client.incompatibilityReason(status);
      log.info(`status ${backendUrl()}: ${status.overall} (api v${status.apiVersion ?? "?"}, ${reason ?? "compatible"})`);
      if (reason) {
        // Fail closed with a diagnostic — never dispatch against an
        // incompatible or absent backend (design/13 §2).
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
}

export function deactivate(): void {
  // Nothing held outside context.subscriptions.
}

function backendUrl(): string {
  return vscode.workspace.getConfiguration("reckon").get<string>("backendUrl", "http://localhost:8080");
}

/**
 * Placeholder tree for the Investigations view: shows backend connectivity
 * until the investigation-list step of the v0 slice (design/13 §7 step 2)
 * replaces it with the real list.
 */
class InvestigationsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly client: BackendClient) {}

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
      const item = new vscode.TreeItem(status.reachable ? "Backend incompatible" : "Backend not connected");
      item.description = reason;
      item.tooltip = reason;
      item.iconPath = new vscode.ThemeIcon(status.reachable ? "warning" : "debug-disconnect");
      item.command = { command: "reckon.checkBackend", title: "Check Backend Connection" };
      return [item];
    }
    const item = new vscode.TreeItem(`Backend ${status.overall}`);
    item.description = "investigation list lands with the v0 slice";
    item.iconPath = new vscode.ThemeIcon(status.overall === "ok" ? "pass" : "warning");
    return [item];
  }
}
