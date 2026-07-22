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
  const client = new BackendClient(() => backendUrl());

  const investigations = new InvestigationsProvider(client);
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("reckon.investigations", investigations),

    vscode.commands.registerCommand("reckon.checkBackend", async () => {
      const status = await client.status();
      if (status.reachable) {
        const detail = Object.entries(status.components)
          .map(([name, c]) => `${name}: ${c.ready ? "ready" : "NOT READY"} (${c.message})`)
          .join("\n");
        void vscode.window.showInformationMessage(
          `reckon backend ${status.overall} at ${backendUrl()}`,
          { modal: false, detail },
        );
      } else {
        void vscode.window.showWarningMessage(
          `reckon backend not reachable at ${backendUrl()} — is the stack running? (\`reckon start\`)`,
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
    if (!status.reachable) {
      const item = new vscode.TreeItem("Backend not connected");
      item.description = "run `reckon start`, then Refresh";
      item.iconPath = new vscode.ThemeIcon("debug-disconnect");
      item.command = { command: "reckon.checkBackend", title: "Check Backend Connection" };
      return [item];
    }
    const item = new vscode.TreeItem(`Backend ${status.overall}`);
    item.description = "investigation list lands with the v0 slice";
    item.iconPath = new vscode.ThemeIcon(status.overall === "ok" ? "pass" : "warning");
    return [item];
  }
}
