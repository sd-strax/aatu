// The investigation document — the analyst's primary workspace (design/13 §4,
// §7 step 2). A reckon-owned webview panel addressed by investigation id, never
// a file the extension decorates (workbench discipline, §3: custom surfaces in
// reckon real estate, no workspace-folder assumption).
//
// v0 renders the read side of the reasoning thread: the investigation header
// plus its hypotheses and nested predictions (D.2 nodes) with status. The
// interactive turn loop (§7 step 3) posts into the same panel next.
//
// The extension host holds the bearer token and does every fetch; the webview
// only renders JSON posted to it. That keeps the token out of the webview and
// lets the CSP forbid all network from the page.

import * as vscode from "vscode";
import { BackendClient, Hypothesis, InvestigationDetail } from "./backend";

/** What the extension host posts to the webview to render. */
type RenderMessage =
  | { type: "loading" }
  | { type: "data"; investigation: InvestigationDetail; hypotheses: Hypothesis[] }
  | { type: "error"; message: string };

/** What the webview posts back to the extension host. */
interface InboundMessage {
  type: "refresh" | "ready";
}

/**
 * Opens and tracks investigation-document panels, one per investigation id.
 * Reopening an already-open investigation reveals its panel rather than
 * stacking a duplicate.
 */
export class InvestigationDocuments {
  private readonly open = new Map<string, vscode.WebviewPanel>();

  constructor(
    private readonly client: BackendClient,
    private readonly log: vscode.LogOutputChannel,
  ) {}

  /** Open (or reveal) the document for one investigation. */
  show(id: string, titleHint?: string): void {
    const existing = this.open.get(id);
    if (existing) {
      existing.reveal();
      void this.load(id, existing);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      "reckon.investigation",
      titleHint ? `⚖ ${titleHint}` : "Investigation",
      vscode.ViewColumn.Active,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    this.open.set(id, panel);
    panel.webview.html = this.html(panel.webview);

    panel.webview.onDidReceiveMessage((msg: InboundMessage) => {
      if (msg.type === "refresh" || msg.type === "ready") {
        void this.load(id, panel);
      }
    });
    panel.onDidDispose(() => this.open.delete(id));
  }

  /** Refresh every open document (e.g. after sign-out flips to sign-in). */
  refreshAll(): void {
    for (const [id, panel] of this.open) {
      void this.load(id, panel);
    }
  }

  private async load(id: string, panel: vscode.WebviewPanel): Promise<void> {
    void this.post(panel, { type: "loading" });
    try {
      const [investigation, hypotheses] = await Promise.all([
        this.client.getInvestigation(id),
        this.client.hypotheses(id),
      ]);
      panel.title = `⚖ ${investigation.title}`;
      void this.post(panel, { type: "data", investigation, hypotheses });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.error(`load investigation ${id}: ${message}`);
      void this.post(panel, { type: "error", message });
    }
  }

  private post(panel: vscode.WebviewPanel, msg: RenderMessage): Thenable<boolean> {
    return panel.webview.postMessage(msg);
  }

  /**
   * The panel shell. All content is rendered from posted JSON by the inline
   * script; the CSP forbids any external load and any network from the page —
   * the webview is a pure renderer, never a second HTTP client.
   */
  private html(webview: vscode.Webview): string {
    const nonce = makeNonce();
    const csp = [
      `default-src 'none'`,
      `style-src ${webview.cspSource} 'unsafe-inline'`,
      `script-src 'nonce-${nonce}'`,
    ].join("; ");

    return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    body {
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      padding: 0 1.25rem 2rem;
      line-height: 1.5;
    }
    header {
      position: sticky;
      top: 0;
      background: var(--vscode-editor-background);
      padding: 1rem 0 0.5rem;
      border-bottom: 1px solid var(--vscode-panel-border);
      display: flex;
      align-items: baseline;
      gap: 0.75rem;
    }
    header h1 { font-size: 1.15rem; margin: 0; flex: 1; }
    .state {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 0.1rem 0.5rem;
      border-radius: 0.6rem;
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
    }
    button {
      font: inherit;
      color: var(--vscode-button-secondaryForeground);
      background: var(--vscode-button-secondaryBackground);
      border: none;
      padding: 0.25rem 0.7rem;
      border-radius: 0.25rem;
      cursor: pointer;
    }
    button:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .meta { font-size: 0.8rem; opacity: 0.7; margin: 0.35rem 0 1rem; }
    h2 { font-size: 0.95rem; margin: 1.25rem 0 0.5rem; }
    .hypothesis {
      border: 1px solid var(--vscode-panel-border);
      border-radius: 0.4rem;
      padding: 0.75rem 0.9rem;
      margin: 0.6rem 0;
    }
    .hypothesis .statement { font-weight: 600; }
    .badge {
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      padding: 0.05rem 0.4rem;
      border-radius: 0.5rem;
      border: 1px solid var(--vscode-panel-border);
      margin-left: 0.5rem;
      vertical-align: middle;
    }
    .labels { margin-top: 0.3rem; }
    .label {
      font-size: 0.7rem;
      opacity: 0.75;
      margin-right: 0.4rem;
    }
    .predictions { list-style: none; padding: 0; margin: 0.5rem 0 0; }
    .predictions li {
      padding: 0.35rem 0 0.35rem 0.9rem;
      border-left: 2px solid var(--vscode-panel-border);
      margin: 0.35rem 0;
    }
    .empty, .error, .loading { opacity: 0.7; font-style: italic; margin: 1.5rem 0; }
    .error { color: var(--vscode-errorForeground); font-style: normal; }
    code { font-family: var(--vscode-editor-font-family); font-size: 0.85em; }
  </style>
</head>
<body>
  <header>
    <h1 id="title">Investigation</h1>
    <span class="state" id="state"></span>
    <button id="refresh" title="Reload from the backend">Refresh</button>
  </header>
  <div class="meta" id="meta"></div>
  <div id="thread"><div class="loading">Loading…</div></div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const $ = (id) => document.getElementById(id);

    document.getElementById("refresh").addEventListener("click", () => {
      vscode.postMessage({ type: "refresh" });
    });

    function esc(s) {
      return String(s ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      }[c]));
    }

    function renderHypotheses(hs) {
      if (!hs.length) {
        return '<div class="empty">No hypotheses yet — the reasoning thread is empty.</div>';
      }
      return hs.map((h) => {
        const labels = (h.labels || []).map((l) => '<span class="label">#' + esc(l) + '</span>').join("");
        const preds = (h.predictions || []).map((p) =>
          '<li><span>' + esc(p.statement) + '</span><span class="badge">' + esc(p.status) + '</span></li>'
        ).join("");
        return '<div class="hypothesis">'
          + '<div><span class="statement">' + esc(h.statement) + '</span>'
          + '<span class="badge">' + esc(h.status) + '</span></div>'
          + (labels ? '<div class="labels">' + labels + '</div>' : '')
          + (preds ? '<ul class="predictions">' + preds + '</ul>' : '')
          + '</div>';
      }).join("");
    }

    window.addEventListener("message", (event) => {
      const msg = event.data;
      if (msg.type === "loading") {
        $("thread").innerHTML = '<div class="loading">Loading…</div>';
        return;
      }
      if (msg.type === "error") {
        $("thread").innerHTML = '<div class="error">Could not load: ' + esc(msg.message) + '</div>';
        return;
      }
      if (msg.type === "data") {
        $("title").textContent = msg.investigation.title;
        $("state").textContent = msg.investigation.state;
        $("meta").innerHTML = '<code>' + esc(msg.investigation.id) + '</code> · '
          + 'seq ' + esc(msg.investigation.lastEventSequence);
        $("thread").innerHTML = '<h2>Reasoning thread</h2>' + renderHypotheses(msg.hypotheses);
      }
    });

    // Tell the host we're ready for the first payload.
    vscode.postMessage({ type: "ready" });
  </script>
</body>
</html>`;
  }
}

function makeNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < 32; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}
