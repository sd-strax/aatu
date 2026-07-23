// The investigation document — the analyst's primary workspace (design/13 §4,
// §7 steps 2–3). A reckon-owned webview panel addressed by investigation id,
// never a file the extension decorates (workbench discipline, §3: custom
// surfaces in reckon real estate, no workspace-folder assumption).
//
// It renders the reasoning thread (hypotheses + predictions, read side) and
// hosts the interactive turn loop: the analyst types, the BYOK agent streams,
// dispatches read tools to the backend, and commits the transcript. The engine
// (Agent, agent.ts) is decoupled — this file is the renderer + message bridge.
//
// The extension host holds the bearer token and the Anthropic key and does
// every call; the webview only renders messages posted to it. The CSP forbids
// all network from the page.

import * as vscode from "vscode";
import { BackendClient, Hypothesis, InvestigationDetail } from "./backend";
import { Agent } from "./agent";

/** What the extension host holds to build an agent when a turn starts. */
export interface AgentDeps {
  apiKey(): Thenable<string | undefined>;
  model(): string;
}

/** What the extension host posts to the webview to render. */
type RenderMessage =
  | { type: "loading" }
  | { type: "data"; investigation: InvestigationDetail; hypotheses: Hypothesis[] }
  | { type: "error"; message: string }
  | { type: "turn.start" }
  | { type: "turn.user"; text: string }
  | { type: "turn.reasoning"; delta: string }
  | { type: "turn.text"; delta: string }
  | { type: "turn.tool"; name: string; input: unknown }
  | { type: "turn.toolResult"; name: string; coverage: string; events: number }
  | { type: "turn.committed"; interpretationId: string }
  | { type: "turn.error"; message: string }
  | { type: "turn.end" };

/** What the webview posts back to the extension host. */
type InboundMessage = { type: "refresh" | "ready" } | { type: "send"; text: string };

export class InvestigationDocuments {
  private readonly open = new Map<string, vscode.WebviewPanel>();
  private readonly agents = new Map<string, Agent>();

  constructor(
    private readonly client: BackendClient,
    private readonly log: vscode.LogOutputChannel,
    private readonly deps: AgentDeps,
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
      } else if (msg.type === "send") {
        void this.runTurn(id, panel, msg.text);
      }
    });
    panel.onDidDispose(() => {
      this.open.delete(id);
      this.agents.delete(id);
    });
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
      const message = errText(err);
      this.log.error(`load investigation ${id}: ${message}`);
      void this.post(panel, { type: "error", message });
    }
  }

  /** Drive one analyst turn through the agent, streaming progress to the webview. */
  private async runTurn(id: string, panel: vscode.WebviewPanel, text: string): Promise<void> {
    void this.post(panel, { type: "turn.user", text });

    const agent = await this.agentFor(id);
    if (!agent) {
      void this.post(panel, {
        type: "turn.error",
        message: "no Anthropic key — run “reckon: Set Anthropic API Key (BYOK)” first",
      });
      void this.post(panel, { type: "turn.end" });
      return;
    }

    void this.post(panel, { type: "turn.start" });
    try {
      await agent.send(text, {
        onReasoning: (delta) => void this.post(panel, { type: "turn.reasoning", delta }),
        onText: (delta) => void this.post(panel, { type: "turn.text", delta }),
        onToolUse: (name, input) => void this.post(panel, { type: "turn.tool", name, input }),
        onToolResult: (name, coverage, events) =>
          void this.post(panel, { type: "turn.toolResult", name, coverage, events }),
        onCommitted: (interpretationId) => void this.post(panel, { type: "turn.committed", interpretationId }),
        onError: (message) => void this.post(panel, { type: "turn.error", message }),
      });
    } catch (err) {
      void this.post(panel, { type: "turn.error", message: errText(err) });
    } finally {
      void this.post(panel, { type: "turn.end" });
      // Reasoning nodes may have changed — refresh the thread panel.
      void this.load(id, panel);
    }
  }

  /** Lazily build (and cache) the agent for one investigation; null if no key. */
  private async agentFor(id: string): Promise<Agent | undefined> {
    const existing = this.agents.get(id);
    if (existing) {
      return existing;
    }
    const key = await this.deps.apiKey();
    if (!key) {
      return undefined;
    }
    const agent = new Agent(key, this.deps.model(), this.client, id);
    this.agents.set(id, agent);
    return agent;
  }

  private post(panel: vscode.WebviewPanel, msg: RenderMessage): Thenable<boolean> {
    return panel.webview.postMessage(msg);
  }

  /**
   * The panel shell. All content is rendered from posted messages by the inline
   * script; the CSP forbids any external load and any network from the page.
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
    html, body { height: 100%; }
    body {
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      margin: 0;
      display: flex;
      flex-direction: column;
      height: 100vh;
    }
    header {
      padding: 0.8rem 1.25rem 0.6rem;
      border-bottom: 1px solid var(--vscode-panel-border);
      display: flex;
      align-items: baseline;
      gap: 0.75rem;
      flex: none;
    }
    header h1 { font-size: 1.1rem; margin: 0; flex: 1; }
    .state {
      font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em;
      padding: 0.1rem 0.5rem; border-radius: 0.6rem;
      background: var(--vscode-badge-background); color: var(--vscode-badge-foreground);
    }
    button {
      font: inherit; color: var(--vscode-button-secondaryForeground);
      background: var(--vscode-button-secondaryBackground); border: none;
      padding: 0.25rem 0.7rem; border-radius: 0.25rem; cursor: pointer;
    }
    button:hover { background: var(--vscode-button-secondaryHoverBackground); }
    button:disabled { opacity: 0.5; cursor: default; }
    #scroll { flex: 1; overflow-y: auto; padding: 0 1.25rem 1rem; }
    .meta { font-size: 0.78rem; opacity: 0.7; margin: 0.6rem 0 0.4rem; }
    details.thread { margin: 0.6rem 0 1rem; }
    details.thread summary { cursor: pointer; font-size: 0.9rem; font-weight: 600; }
    .hypothesis { border: 1px solid var(--vscode-panel-border); border-radius: 0.4rem; padding: 0.6rem 0.8rem; margin: 0.5rem 0; }
    .hypothesis .statement { font-weight: 600; }
    .badge {
      font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.03em;
      padding: 0.05rem 0.4rem; border-radius: 0.5rem; border: 1px solid var(--vscode-panel-border);
      margin-left: 0.5rem; vertical-align: middle;
    }
    .predictions { list-style: none; padding: 0; margin: 0.4rem 0 0; }
    .predictions li { padding: 0.3rem 0 0.3rem 0.8rem; border-left: 2px solid var(--vscode-panel-border); margin: 0.3rem 0; }
    .msg { margin: 0.85rem 0; }
    .msg.user { text-align: right; }
    .msg.user .bubble {
      display: inline-block; text-align: left; max-width: 80%;
      background: var(--vscode-input-background); border: 1px solid var(--vscode-panel-border);
      border-radius: 0.5rem; padding: 0.5rem 0.75rem; white-space: pre-wrap;
    }
    .msg.assistant .text { white-space: pre-wrap; }
    .reasoning {
      font-style: italic; opacity: 0.7; font-size: 0.86rem; white-space: pre-wrap;
      border-left: 2px solid var(--vscode-panel-border); padding-left: 0.6rem; margin: 0.3rem 0;
    }
    .tool {
      font-family: var(--vscode-editor-font-family); font-size: 0.82rem;
      background: var(--vscode-textCodeBlock-background); border-radius: 0.3rem;
      padding: 0.2rem 0.5rem; margin: 0.35rem 0; display: block;
    }
    .tool .verb { font-weight: 600; }
    .tool .result { opacity: 0.85; }
    .committed { font-size: 0.76rem; opacity: 0.55; margin: 0.3rem 0; }
    .error { color: var(--vscode-errorForeground); margin: 0.4rem 0; }
    .empty, .loading { opacity: 0.7; font-style: italic; margin: 1rem 0; }
    code { font-family: var(--vscode-editor-font-family); font-size: 0.85em; }
    #composer {
      flex: none; display: flex; gap: 0.5rem; padding: 0.6rem 1.25rem;
      border-top: 1px solid var(--vscode-panel-border);
    }
    #composer textarea {
      flex: 1; resize: none; font: inherit; color: var(--vscode-input-foreground);
      background: var(--vscode-input-background); border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
      border-radius: 0.3rem; padding: 0.45rem 0.6rem; min-height: 2.4rem; max-height: 8rem;
    }
    #send { align-self: flex-end; }
  </style>
</head>
<body>
  <header>
    <h1 id="title">Investigation</h1>
    <span class="state" id="state"></span>
    <button id="refresh" title="Reload from the backend">Refresh</button>
  </header>

  <div id="scroll">
    <div class="meta" id="meta"></div>
    <details class="thread" id="threadWrap" open>
      <summary>Reasoning thread</summary>
      <div id="thread"><div class="loading">Loading…</div></div>
    </details>
    <div id="conversation"></div>
  </div>

  <div id="composer">
    <textarea id="input" rows="1" placeholder="Ask reckon to investigate… (Enter to send, Shift+Enter for newline)"></textarea>
    <button id="send">Send</button>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const $ = (id) => document.getElementById(id);
    const scroll = $("scroll");
    const conversation = $("conversation");
    const input = $("input");
    const sendBtn = $("send");

    let turn = null; // { textEl, reasoningEl } for the in-flight assistant message

    function esc(s) {
      return String(s ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      }[c]));
    }
    function atBottom() { return scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 40; }
    function stick(was) { if (was) scroll.scrollTop = scroll.scrollHeight; }

    function renderHypotheses(hs) {
      if (!hs.length) return '<div class="empty">No hypotheses yet.</div>';
      return hs.map((h) => {
        const preds = (h.predictions || []).map((p) =>
          '<li>' + esc(p.statement) + '<span class="badge">' + esc(p.status) + '</span></li>'
        ).join("");
        return '<div class="hypothesis"><div><span class="statement">' + esc(h.statement) + '</span>'
          + '<span class="badge">' + esc(h.status) + '</span></div>'
          + (preds ? '<ul class="predictions">' + preds + '</ul>' : '') + '</div>';
      }).join("");
    }

    function el(cls, html) {
      const d = document.createElement("div");
      d.className = cls;
      if (html !== undefined) d.innerHTML = html;
      conversation.appendChild(d);
      return d;
    }

    function setComposerEnabled(on) {
      sendBtn.disabled = !on;
      input.disabled = !on;
      if (on) input.focus();
    }

    sendBtn.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
    });
    function submit() {
      const text = input.value.trim();
      if (!text || sendBtn.disabled) return;
      input.value = "";
      setComposerEnabled(false);
      vscode.postMessage({ type: "send", text });
    }
    $("refresh").addEventListener("click", () => vscode.postMessage({ type: "refresh" }));

    window.addEventListener("message", (event) => {
      const msg = event.data;
      const was = atBottom();
      switch (msg.type) {
        case "loading":
          $("thread").innerHTML = '<div class="loading">Loading…</div>';
          break;
        case "error":
          $("thread").innerHTML = '<div class="error">Could not load: ' + esc(msg.message) + '</div>';
          break;
        case "data":
          $("title").textContent = msg.investigation.title;
          $("state").textContent = msg.investigation.state;
          $("meta").innerHTML = '<code>' + esc(msg.investigation.id) + '</code> · seq ' + esc(msg.investigation.lastEventSequence);
          $("thread").innerHTML = renderHypotheses(msg.hypotheses);
          break;
        case "turn.user":
          el("msg user", '<span class="bubble">' + esc(msg.text) + '</span>');
          break;
        case "turn.start": {
          const wrap = el("msg assistant");
          const reasoningEl = document.createElement("div");
          reasoningEl.className = "reasoning";
          reasoningEl.style.display = "none";
          const textEl = document.createElement("div");
          textEl.className = "text";
          wrap.appendChild(reasoningEl);
          wrap.appendChild(textEl);
          turn = { wrap, reasoningEl, textEl };
          break;
        }
        case "turn.reasoning":
          if (turn) { turn.reasoningEl.style.display = "block"; turn.reasoningEl.textContent += msg.delta; }
          break;
        case "turn.text":
          if (turn) turn.textEl.textContent += msg.delta;
          break;
        case "turn.tool": {
          const args = esc(JSON.stringify(msg.input));
          (turn ? turn.wrap : conversation).appendChild(Object.assign(document.createElement("div"), {
            className: "tool", innerHTML: '<span class="verb">→ ' + esc(msg.name) + '</span> <code>' + args + '</code>',
          }));
          break;
        }
        case "turn.toolResult":
          (turn ? turn.wrap : conversation).appendChild(Object.assign(document.createElement("div"), {
            className: "tool", innerHTML: '<span class="result">✓ ' + esc(msg.name) + ' — ' + esc(msg.coverage)
              + ' · ' + esc(msg.events) + ' event(s)</span>',
          }));
          break;
        case "turn.committed":
          el("committed", "saved to thread · " + esc(msg.interpretationId));
          break;
        case "turn.error":
          el("error", esc(msg.message));
          break;
        case "turn.end":
          turn = null;
          setComposerEnabled(true);
          break;
      }
      stick(was);
    });

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

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
