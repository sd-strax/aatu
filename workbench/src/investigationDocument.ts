// The investigation document — the analyst's primary workspace (design/13 §4,
// §7 steps 2–3). A reckon-owned webview panel addressed by investigation id,
// never a file the extension decorates (workbench discipline, §3: custom
// surfaces in reckon real estate, no workspace-folder assumption).
//
// It renders the reasoning thread (hypotheses + predictions, read side) and
// hosts the interactive turn loop. The loop itself is the canonical Go
// implementation, reached through the AgentTransport seam (the sidecar,
// implementation/agent-sidecar.md) — this file is the renderer + message
// bridge, nothing more.
//
// The extension host holds the tokens and the Anthropic key and does every
// call; the webview only renders messages posted to it. The CSP forbids all
// network from the page.

import * as vscode from "vscode";
import { ActionRow, BackendClient, Capability, Hypothesis, InvestigationDetail, ThreadEntry } from "./backend";
import { AgentTransport } from "./agentTransport";

/** What the extension host posts to the webview to render. */
type RenderMessage =
  | { type: "loading" }
  // capabilities is null when the capability layer is off/unreachable — the
  // rail renders that honestly instead of an empty list. thread is the
  // chronological reasoning history (13 §4); null when its fetch failed.
  | { type: "data"; investigation: InvestigationDetail; hypotheses: Hypothesis[]; capabilities: Capability[] | null; thread: ThreadEntry[] | null }
  | { type: "error"; message: string }
  | { type: "pending"; actions: ActionRow[] }
  | { type: "turn.start" }
  | { type: "turn.user"; text: string }
  | { type: "turn.reasoning"; delta: string }
  | { type: "turn.text"; delta: string }
  | { type: "turn.tool"; name: string; input: unknown }
  | { type: "turn.toolResult"; name: string; isError: boolean; coverage?: string; events?: number }
  | { type: "turn.committed"; interpretationId: string }
  | { type: "turn.error"; message: string }
  | { type: "turn.end"; usage?: { input: number; output: number; cacheRead: number }; rounds?: number };

/** What the webview posts back to the extension host. */
type InboundMessage =
  | { type: "refresh" | "ready" }
  | { type: "send"; text: string }
  | { type: "action.approve"; actionId: string; tier: string; actionType: string }
  | { type: "action.reject"; actionId: string; actionType: string };

export class InvestigationDocuments {
  private readonly open = new Map<string, vscode.WebviewPanel>();

  constructor(
    private readonly client: BackendClient,
    private readonly log: vscode.LogOutputChannel,
    private readonly transport: AgentTransport,
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
      } else if (msg.type === "action.approve") {
        void this.approve(id, panel, msg);
      } else if (msg.type === "action.reject") {
        void this.reject(id, panel, msg);
      }
    });
    panel.onDidDispose(() => {
      this.open.delete(id);
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
      const [investigation, hypotheses, capabilities, thread] = await Promise.all([
        this.client.getInvestigation(id),
        this.client.hypotheses(id),
        // Capability health is a v0 rail surface (13 §4); a 503 just means the
        // layer is off — null renders as "unavailable", never a broken panel.
        this.client.capabilities().catch(() => null),
        // The reasoning history — how the investigation got to its current
        // state. Failure degrades to "history unavailable", not a broken panel.
        this.client.thread(id).catch(() => null),
      ]);
      panel.title = `⚖ ${investigation.title}`;
      void this.post(panel, { type: "data", investigation, hypotheses, capabilities, thread });
    } catch (err) {
      const message = errText(err);
      this.log.error(`load investigation ${id}: ${message}`);
      void this.post(panel, { type: "error", message });
    }
    // The durable action queue rides every load (open, refresh, post-turn,
    // post-decision) — the panel always shows what actually awaits the
    // analyst, not just what the last turn proposed.
    await this.postPending(id, panel);
  }

  /** Fetch + render the action queue. Failure logs and leaves the panel as-is. */
  private async postPending(id: string, panel: vscode.WebviewPanel): Promise<void> {
    try {
      const actions = await this.client.actions(id);
      void this.post(panel, { type: "pending", actions });
    } catch (err) {
      // A 503 here just means the action layer is off — not a broken panel.
      this.log.debug(`list actions ${id}: ${errText(err)}`);
    }
  }

  /**
   * Approve one action — the analyst's own act, extension→backend on the
   * HUMAN token, never through the sidecar (implementation/agent-sidecar.md
   * §5). A T3 approval demands the typed challenge (04 §5.5) via input box.
   */
  private async approve(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { actionId: string; tier: string; actionType: string },
  ): Promise<void> {
    let challenge: string | undefined;
    if (msg.tier === "T3") {
      challenge = await vscode.window.showInputBox({
        title: `reckon — approve ${msg.actionType} (T3)`,
        prompt: "Tier-3 approval requires the typed challenge. This action has high blast radius.",
        ignoreFocusOut: true,
        validateInput: (v) => (v.trim() === "" ? "the challenge text is required for T3" : undefined),
      });
      if (challenge === undefined || challenge.trim() === "") {
        await this.postPending(id, panel); // cancelled — re-enable the buttons
        return;
      }
    }
    try {
      const decision = await this.client.approveAction(msg.actionId, challenge);
      void vscode.window.showInformationMessage(
        `reckon: ${msg.actionType} → ${decision.status}${decision.stage ? ` (${decision.stage})` : ""}`,
      );
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: approve failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /** Reject one action — ditto, human token only. */
  private async reject(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { actionId: string; actionType: string },
  ): Promise<void> {
    const reason = await vscode.window.showInputBox({
      title: `reckon — reject ${msg.actionType}`,
      prompt: "Why is this action rejected? (recorded on the audit trail)",
      ignoreFocusOut: true,
      placeHolder: "rejected from the workbench",
    });
    if (reason === undefined) {
      await this.postPending(id, panel); // cancelled — re-enable the buttons
      return;
    }
    try {
      const decision = await this.client.rejectAction(
        msg.actionId,
        reason.trim() === "" ? "rejected from the workbench" : reason.trim(),
      );
      void vscode.window.showInformationMessage(`reckon: ${msg.actionType} → ${decision.status}`);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: reject failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /** Drive one analyst turn through the transport, streaming progress to the webview. */
  private async runTurn(id: string, panel: vscode.WebviewPanel, text: string): Promise<void> {
    void this.post(panel, { type: "turn.user", text });
    void this.post(panel, { type: "turn.start" });
    try {
      const outcome = await this.transport.turn(id, text, {
        // Both text paths land on the same appendable turn.text case: deltas
        // stream token-by-token (E.4); round-complete text arrives only from a
        // non-streaming provider (mutually exclusive per completion, enforced
        // sidecar-side — never both for the same text).
        onText: (chunk) => void this.post(panel, { type: "turn.text", delta: chunk }),
        onTextDelta: (chunk) => void this.post(panel, { type: "turn.text", delta: chunk }),
        onToolCall: (name, input) => void this.post(panel, { type: "turn.tool", name, input }),
        // coverage/events come distilled from the sidecar (from the full,
        // unclipped payload) — absent for non-envelope results, and the
        // webview renders that honestly instead of a bogus "? · 0".
        onToolResult: (name, _content, isError, coverage, events) =>
          void this.post(panel, { type: "turn.toolResult", name, isError, coverage, events }),
      });
      if (outcome.interpretationId) {
        void this.post(panel, { type: "turn.committed", interpretationId: outcome.interpretationId });
      }
      // Pending actions are NOT posted from the outcome: the finally-load
      // re-fetches the durable queue, so the panel renders the backend's
      // truth (including actions from earlier turns/sessions) with the
      // approve/reject affordances attached.
      if (outcome.error) {
        void this.post(panel, { type: "turn.error", message: outcome.error });
      }
      void this.post(panel, {
        type: "turn.end",
        rounds: outcome.toolRounds,
        usage: {
          input: outcome.usage.input + outcome.usage.cacheRead + outcome.usage.cacheWrite,
          output: outcome.usage.output,
          cacheRead: outcome.usage.cacheRead,
        },
      });
    } catch (err) {
      void this.post(panel, { type: "turn.error", message: errText(err) });
      void this.post(panel, { type: "turn.end" });
    } finally {
      // Reasoning nodes may have changed — refresh the thread panel.
      void this.load(id, panel);
    }
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
      font-size: 13px;
      line-height: 1.55;
      color: var(--vscode-foreground);
      margin: 0;
      display: flex;
      height: 100vh;
      overflow: hidden;
    }

    /* ---- two-region layout: conversation + state rail ---- */
    #main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
    #rail {
      flex: none; width: 272px; min-width: 200px;
      border-left: 1px solid var(--vscode-panel-border);
      overflow-y: auto; padding: 0.75rem 0.9rem 1rem;
      background: var(--vscode-sideBar-background, transparent);
    }
    @media (max-width: 640px) { #rail { display: none; } }

    header {
      padding: 0.7rem 1.25rem 0.55rem;
      border-bottom: 1px solid var(--vscode-panel-border);
      flex: none;
    }
    .titlerow { display: flex; align-items: baseline; gap: 0.7rem; }
    header h1 { font-size: 1.05rem; margin: 0; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .state {
      font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em;
      padding: 0.12rem 0.55rem; border-radius: 0.65rem;
      background: var(--vscode-badge-background); color: var(--vscode-badge-foreground);
    }
    #meta { font-size: 0.74rem; opacity: 0.55; margin-top: 0.15rem; }

    button {
      font: inherit; color: var(--vscode-button-secondaryForeground);
      background: var(--vscode-button-secondaryBackground); border: none;
      padding: 0.25rem 0.7rem; border-radius: 0.25rem; cursor: pointer;
    }
    button:hover { background: var(--vscode-button-secondaryHoverBackground); }
    button:disabled { opacity: 0.5; cursor: default; }

    #scroll { flex: 1; overflow-y: auto; padding: 0.4rem 1.25rem 1rem; }
    #banner { color: var(--vscode-errorForeground); margin: 0.5rem 0; }
    #banner:empty { display: none; }
    #conversation:empty::before {
      content: "Ask reckon to investigate — it reasons over the evidence, cites what it saw, and proposes actions for your approval.";
      display: block; opacity: 0.55; font-style: italic; margin: 1.4rem 0; max-width: 46ch;
    }

    /* ---- conversation ---- */
    .msg { margin: 1rem 0; max-width: 78ch; }
    .msg.user { display: flex; justify-content: flex-end; max-width: none; }
    .msg.user .bubble {
      max-width: 60ch; white-space: pre-wrap;
      background: var(--vscode-input-background); border: 1px solid var(--vscode-panel-border);
      border-radius: 0.6rem; padding: 0.45rem 0.8rem;
    }
    .reasoning {
      font-style: italic; opacity: 0.7; font-size: 0.86rem; white-space: pre-wrap;
      border-left: 2px solid var(--vscode-panel-border); padding-left: 0.6rem; margin: 0.3rem 0;
    }

    /* markdown-rendered assistant text */
    .md p { margin: 0.45rem 0; }
    .md ul, .md ol { margin: 0.35rem 0; padding-left: 1.4rem; }
    .md li { margin: 0.15rem 0; }
    .md .mdh { font-weight: 600; margin: 0.7rem 0 0.3rem; }
    .md code, code {
      font-family: var(--vscode-editor-font-family); font-size: 0.86em;
      background: var(--vscode-textCodeBlock-background);
      padding: 0.05em 0.3em; border-radius: 0.25em;
    }
    .md pre.codeblock {
      font-family: var(--vscode-editor-font-family); font-size: 0.84rem; line-height: 1.45;
      background: var(--vscode-textCodeBlock-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 0.4rem; padding: 0.6rem 0.8rem; margin: 0.5rem 0;
      overflow-x: auto; white-space: pre;
    }
    .md pre.codeblock code { background: none; padding: 0; }

    /* tool rows: one-line summary, args behind the disclosure */
    details.tool {
      font-family: var(--vscode-editor-font-family); font-size: 0.8rem;
      border: 1px solid var(--vscode-panel-border);
      border-radius: 0.35rem; margin: 0.4rem 0; max-width: 78ch;
      background: var(--vscode-textCodeBlock-background);
    }
    details.tool summary {
      cursor: pointer; padding: 0.28rem 0.6rem; list-style: none;
      display: flex; align-items: baseline; gap: 0.5rem; overflow: hidden;
    }
    details.tool summary::-webkit-details-marker { display: none; }
    .tool .mark { flex: none; }
    .tool .mark.ok { color: var(--vscode-charts-green, #89d185); }
    .tool .mark.err { color: var(--vscode-errorForeground); }
    .tool .verb { font-weight: 600; flex: none; }
    .tool .hint {
      opacity: 0.55; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; min-width: 0;
    }
    .tool .status { flex: none; opacity: 0.8; }
    .tool pre {
      margin: 0; padding: 0.5rem 0.6rem 0.6rem;
      border-top: 1px solid var(--vscode-panel-border);
      overflow-x: auto; white-space: pre;
    }

    .committed, .usage { font-size: 0.74rem; opacity: 0.5; margin: 0.35rem 0; }
    .error { color: var(--vscode-errorForeground); margin: 0.4rem 0; max-width: 78ch; }

    /* ---- reasoning history (the thread, 13 §4) ---- */
    #historyWrap { margin: 0.6rem 0 1rem; max-width: 78ch; }
    #historyWrap > summary {
      cursor: pointer; font-size: 0.78rem; text-transform: uppercase;
      letter-spacing: 0.06em; opacity: 0.6; font-weight: 600; margin-bottom: 0.3rem;
    }
    .step {
      border-left: 2px solid var(--vscode-panel-border);
      padding: 0.15rem 0 0.3rem 0.8rem; margin: 0.55rem 0;
    }
    .step.ai { border-left-color: var(--vscode-charts-blue, #4e94ce); }
    .step .stephead {
      font-size: 0.72rem; opacity: 0.65;
      display: flex; align-items: baseline; gap: 0.55rem; flex-wrap: wrap;
    }
    .step .stephead .who { font-weight: 600; }
    .step .stepbody { font-size: 0.86rem; margin-top: 0.1rem; }
    .step .stepbody p { margin: 0.2rem 0; }

    /* ---- rail ---- */
    #rail section { margin-bottom: 1.1rem; }
    #rail h2 {
      font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em;
      opacity: 0.6; margin: 0 0 0.45rem; font-weight: 600;
    }
    .card {
      border: 1px solid var(--vscode-panel-border); border-radius: 0.4rem;
      padding: 0.5rem 0.65rem; margin: 0.4rem 0; font-size: 0.84rem;
    }
    .card .statement { font-weight: 600; }
    .badge {
      font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.03em;
      padding: 0.05rem 0.4rem; border-radius: 0.5rem; border: 1px solid var(--vscode-panel-border);
      margin-left: 0.4rem; vertical-align: middle; white-space: nowrap;
    }
    .predictions { list-style: none; padding: 0; margin: 0.35rem 0 0; }
    .predictions li {
      padding: 0.2rem 0 0.2rem 0.6rem; border-left: 2px solid var(--vscode-panel-border);
      margin: 0.25rem 0; font-size: 0.8rem;
    }
    .cardmeta { font-size: 0.74rem; opacity: 0.65; margin-top: 0.25rem; word-break: break-word; }
    .decide { margin-top: 0.45rem; display: flex; gap: 0.4rem; flex-wrap: wrap; }
    .decide button { font-size: 0.8rem; padding: 0.2rem 0.6rem; }
    .decide .primary { color: var(--vscode-button-foreground); background: var(--vscode-button-background); }
    .decide .primary:hover { background: var(--vscode-button-hoverBackground); }
    .empty { opacity: 0.55; font-style: italic; font-size: 0.8rem; }
    .caprow { display: flex; align-items: baseline; gap: 0.45rem; font-size: 0.8rem; margin: 0.15rem 0; }
    .dot { flex: none; width: 0.5em; height: 0.5em; border-radius: 50%; background: var(--vscode-charts-green, #89d185); }
    .dot.degraded { background: var(--vscode-charts-yellow, #cca700); }
    .dot.unavailable { background: var(--vscode-charts-red, #f14c4c); opacity: 0.7; }
    .caprow .verb { font-family: var(--vscode-editor-font-family); }
    .caprow.unavailable .verb { opacity: 0.5; }
    body.loading #rail { opacity: 0.6; }

    /* ---- composer ---- */
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
<body class="loading">
  <div id="main">
    <header>
      <div class="titlerow">
        <h1 id="title">Investigation</h1>
        <span class="state" id="state"></span>
        <button id="refresh" title="Reload from the backend">Refresh</button>
      </div>
      <div id="meta"></div>
    </header>

    <div id="scroll">
      <div id="banner"></div>
      <details id="historyWrap" open style="display:none">
        <summary id="historySummary">How this investigation got here</summary>
        <div id="history"></div>
      </details>
      <div id="conversation"></div>
    </div>

    <div id="composer">
      <textarea id="input" rows="1" placeholder="Ask reckon to investigate… (Enter to send, Shift+Enter for newline)"></textarea>
      <button id="send">Send</button>
    </div>
  </div>

  <aside id="rail">
    <section>
      <h2>Needs your approval</h2>
      <div id="pending"><div class="empty">Nothing waiting</div></div>
    </section>
    <section>
      <h2>Hypotheses</h2>
      <div id="hyps"><div class="empty">None yet</div></div>
    </section>
    <section>
      <h2>Capabilities</h2>
      <div id="caps"><div class="empty">…</div></div>
    </section>
  </aside>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const $ = (id) => document.getElementById(id);
    const scroll = $("scroll");
    const conversation = $("conversation");
    const input = $("input");
    const sendBtn = $("send");

    // The in-flight assistant message: wrap is the container; seg/buf are the
    // current markdown text segment (closed by a tool row, so text after a
    // tool round lands AFTER it, in reading order); tools is the FIFO of tool
    // rows awaiting their result.
    let turn = null;

    function esc(s) {
      return String(s ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      }[c]));
    }
    function atBottom() { return scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 40; }
    function stick(was) { if (was) scroll.scrollTop = scroll.scrollHeight; }

    // ---- minimal markdown, escape-first ------------------------------------
    // Model text is untrusted: every path escapes BEFORE formatting, and only
    // these known-safe elements are ever produced. Covers what the agent
    // actually emits (inline code, bold, bullets, numbered lists, fenced
    // blocks, light headings); everything else renders as written.
    function inlineMd(s) {
      let out = esc(s);
      out = out.replace(/\`([^\`]+)\`/g, "<code>$1</code>");
      out = out.replace(/\\*\\*([^*]+)\\*\\*/g, "<strong>$1</strong>");
      return out;
    }
    function md(src) {
      const lines = String(src ?? "").split("\\n");
      const out = [];
      let para = [];
      let list = null;
      const flushPara = () => {
        if (para.length) { out.push("<p>" + para.map(inlineMd).join("<br>") + "</p>"); para = []; }
      };
      const flushList = () => {
        if (list) {
          out.push("<" + list.tag + ">" + list.items.map((it) => "<li>" + inlineMd(it) + "</li>").join("") + "</" + list.tag + ">");
          list = null;
        }
      };
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\\s*\`\`\`/.test(line)) {
          flushPara(); flushList();
          const buf = [];
          for (i++; i < lines.length && !/^\\s*\`\`\`/.test(lines[i]); i++) buf.push(lines[i]);
          // An unclosed fence (mid-stream) still renders as a block — the
          // re-render on the next delta keeps it live.
          out.push('<pre class="codeblock"><code>' + esc(buf.join("\\n")) + "</code></pre>");
          continue;
        }
        const ul = line.match(/^\\s*[-*•]\\s+(.*)$/);
        const ol = line.match(/^\\s*\\d+[.)]\\s+(.*)$/);
        const h = line.match(/^\\s*#{1,4}\\s+(.*)$/);
        if (ul || ol) {
          flushPara();
          const tag = ul ? "ul" : "ol";
          if (!list || list.tag !== tag) { flushList(); list = { tag, items: [] }; }
          list.items.push((ul || ol)[1]);
        } else if (h) {
          flushPara(); flushList();
          out.push('<div class="mdh">' + inlineMd(h[1]) + "</div>");
        } else if (line.trim() === "") {
          flushPara(); flushList();
        } else {
          flushList();
          para.push(line);
        }
      }
      flushPara(); flushList();
      return out.join("");
    }

    function el(cls, html) {
      const d = document.createElement("div");
      d.className = cls;
      if (html !== undefined) d.innerHTML = html;
      conversation.appendChild(d);
      return d;
    }

    // Append streamed/completed text into the current segment, re-rendering
    // its markdown from the accumulated raw buffer (cheap at chat sizes).
    function appendText(delta) {
      if (!turn) return;
      if (!turn.seg) {
        turn.seg = document.createElement("div");
        turn.seg.className = "md";
        turn.buf = "";
        turn.wrap.appendChild(turn.seg);
      }
      turn.buf += delta;
      turn.seg.innerHTML = md(turn.buf);
    }

    function addToolRow(name, inputArgs) {
      const row = document.createElement("details");
      row.className = "tool";
      const sum = document.createElement("summary");
      const mark = document.createElement("span");
      mark.className = "mark";
      mark.textContent = "→";
      const verb = document.createElement("span");
      verb.className = "verb";
      verb.textContent = name;
      const hint = document.createElement("span");
      hint.className = "hint";
      hint.textContent = JSON.stringify(inputArgs ?? {});
      sum.append(mark, verb, hint);
      const body = document.createElement("pre");
      body.textContent = JSON.stringify(inputArgs ?? {}, null, 2);
      row.append(sum, body);
      (turn ? turn.wrap : conversation).appendChild(row);
      if (turn) { turn.seg = null; turn.tools.push(row); }
      return row;
    }

    function settleToolRow(msg) {
      const row = turn && turn.tools.length ? turn.tools.shift() : null;
      const detail = msg.isError ? "error"
        : msg.coverage !== undefined ? msg.coverage + " · " + msg.events + " event(s)"
        : "done";
      if (!row) {
        el("committed", (msg.isError ? "✗ " : "✓ ") + esc(msg.name) + " — " + esc(detail));
        return;
      }
      const mark = row.querySelector(".mark");
      mark.textContent = msg.isError ? "✗" : "✓";
      mark.classList.add(msg.isError ? "err" : "ok");
      const st = document.createElement("span");
      st.className = "hint status";
      st.textContent = detail;
      row.querySelector("summary").appendChild(st);
    }

    // ---- reasoning history -------------------------------------------------
    // Frozen at the sequence seen on FIRST load: acts recorded later arrive
    // through the live conversation (or the rail), so re-fetches never
    // duplicate what a live turn already rendered below.
    let historyCutoff = null;

    function renderHistory(entries) {
      const wrap = $("historyWrap");
      const box = $("history");
      if (!entries || !entries.length) {
        wrap.style.display = "none";
        return;
      }
      if (historyCutoff === null) {
        historyCutoff = entries[entries.length - 1].sequenceNo;
      }
      const shown = entries.filter((e) => e.sequenceNo <= historyCutoff);
      if (!shown.length) {
        wrap.style.display = "none";
        return;
      }
      wrap.style.display = "";
      $("historySummary").textContent =
        "How this investigation got here · " + shown.length + " step" + (shown.length === 1 ? "" : "s");
      box.textContent = "";
      for (const e of shown) {
        const step = document.createElement("div");
        step.className = "step" + (e.actor.kind === "AI_DELEGATED" ? " ai" : "");

        const head = document.createElement("div");
        head.className = "stephead";
        const who = document.createElement("span");
        who.className = "who";
        who.textContent = e.actor.kind === "AI_DELEGATED" ? "AI" + (e.actor.model ? " · " + e.actor.model : "")
          : e.actor.kind === "SYSTEM" ? "system" : "analyst";
        who.title = e.actor.principal;
        const typ = document.createElement("span");
        typ.textContent = e.interpretationType;
        const when = document.createElement("span");
        when.textContent = e.occurredAt ? new Date(e.occurredAt).toLocaleString() : "";
        head.append(who, typ, when);
        const extras = [];
        if (e.confidence) extras.push(e.confidence.toLowerCase() + " confidence");
        if (e.toolCalls) extras.push(e.toolCalls + " tool call" + (e.toolCalls === 1 ? "" : "s"));
        const refs = (e.inputRefs?.length ?? 0) + (e.outputRefs?.length ?? 0);
        if (refs) extras.push(refs + " evidence ref" + (refs === 1 ? "" : "s"));
        if (extras.length) {
          const ex = document.createElement("span");
          ex.textContent = extras.join(" · ");
          head.append(ex);
        }

        const body = document.createElement("div");
        body.className = "stepbody md";
        body.innerHTML = md(e.summary);

        step.append(head, body);
        box.appendChild(step);
      }
    }

    // ---- rail --------------------------------------------------------------
    function renderHypotheses(hs) {
      const box = $("hyps");
      if (!hs || !hs.length) {
        box.innerHTML = '<div class="empty">None yet</div>';
        return;
      }
      box.innerHTML = hs.map((h) => {
        const preds = (h.predictions || []).map((p) =>
          '<li>' + esc(p.statement) + '<span class="badge">' + esc(p.status) + '</span></li>'
        ).join("");
        return '<div class="card"><div><span class="statement">' + esc(h.statement) + '</span>'
          + '<span class="badge">' + esc(h.status) + '</span></div>'
          + (preds ? '<ul class="predictions">' + preds + '</ul>' : '') + '</div>';
      }).join("");
    }

    function renderCapabilities(caps) {
      const box = $("caps");
      if (caps === null) {
        box.innerHTML = '<div class="empty">capability layer off</div>';
        return;
      }
      if (!caps.length) {
        box.innerHTML = '<div class="empty">none configured</div>';
        return;
      }
      const order = { available: 0, degraded: 1, unavailable: 2 };
      const sorted = caps.slice().sort((a, b) =>
        (order[a.status] ?? 3) - (order[b.status] ?? 3) || a.verb.localeCompare(b.verb));
      box.textContent = "";
      for (const c of sorted) {
        const row = document.createElement("div");
        row.className = "caprow " + c.status;
        const dot = document.createElement("span");
        dot.className = "dot " + c.status;
        dot.title = c.status;
        const verb = document.createElement("span");
        verb.className = "verb";
        verb.textContent = c.verb;
        row.append(dot, verb);
        box.appendChild(row);
      }
    }

    // The action queue: rows are DOM-built (action_type/targets are
    // model-influenced — no innerHTML for them), each with Approve/Reject
    // posting to the host, which does the real call on the human token.
    function renderPending(actions) {
      const box = $("pending");
      const pend = (actions || []).filter((a) => a.pending);
      box.textContent = "";
      if (!pend.length) {
        box.innerHTML = '<div class="empty">Nothing waiting</div>';
        return;
      }
      for (const a of pend) {
        const row = document.createElement("div");
        row.className = "card";

        const head = document.createElement("div");
        const name = document.createElement("span");
        name.className = "statement";
        name.textContent = a.actionType;
        const tier = document.createElement("span");
        tier.className = "badge";
        tier.textContent = a.tier;
        const state = document.createElement("span");
        state.className = "badge";
        state.textContent = a.expired ? "EXPIRED" : a.pendingLabel;
        head.append(name, tier, state);

        const targets = document.createElement("div");
        targets.className = "cardmeta";
        targets.textContent = "→ " + (a.targets || []).join(", ");

        row.append(head, targets);

        if (a.expired) {
          // The approval deadline passed — the engine refuses an approve, so
          // no buttons: an affordance that can only fail is a lie.
          row.style.opacity = "0.55";
          const note = document.createElement("div");
          note.className = "cardmeta";
          note.textContent = "approval window elapsed — re-request the action if it is still needed";
          row.append(note);
        } else {
          const decide = document.createElement("div");
          decide.className = "decide";
          const ok = document.createElement("button");
          ok.className = "primary";
          ok.textContent = a.tier === "T3" ? "Approve (challenge)…" : "Approve";
          ok.addEventListener("click", () => {
            setDecideEnabled(false);
            vscode.postMessage({ type: "action.approve", actionId: a.actionId, tier: a.tier, actionType: a.actionType });
          });
          const no = document.createElement("button");
          no.textContent = "Reject…";
          no.addEventListener("click", () => {
            setDecideEnabled(false);
            vscode.postMessage({ type: "action.reject", actionId: a.actionId, actionType: a.actionType });
          });
          decide.append(ok, no);
          row.append(decide);
        }
        box.appendChild(row);
      }
    }

    // One decision in flight at a time; the host re-posts the queue after
    // every outcome (including cancel), which re-enables via re-render.
    function setDecideEnabled(on) {
      for (const b of document.querySelectorAll("#pending button")) b.disabled = !on;
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
          document.body.classList.add("loading");
          break;
        case "error":
          document.body.classList.remove("loading");
          $("banner").textContent = "Could not load: " + msg.message;
          break;
        case "data":
          document.body.classList.remove("loading");
          $("banner").textContent = "";
          $("title").textContent = msg.investigation.title;
          $("state").textContent = msg.investigation.state;
          $("meta").innerHTML = '<code>' + esc(msg.investigation.id) + '</code> · seq ' + esc(msg.investigation.lastEventSequence);
          renderHypotheses(msg.hypotheses);
          renderCapabilities(msg.capabilities);
          renderHistory(msg.thread);
          break;
        case "turn.user":
          el("msg user", '<span class="bubble">' + esc(msg.text) + '</span>');
          break;
        case "turn.start":
          turn = { wrap: el("msg assistant"), seg: null, buf: "", tools: [], reasoningEl: null };
          break;
        case "turn.reasoning":
          if (turn) {
            if (!turn.reasoningEl) {
              turn.reasoningEl = document.createElement("div");
              turn.reasoningEl.className = "reasoning";
              turn.wrap.prepend(turn.reasoningEl);
            }
            turn.reasoningEl.textContent += msg.delta;
          }
          break;
        case "turn.text":
          appendText(msg.delta);
          break;
        case "turn.tool":
          addToolRow(msg.name, msg.input);
          break;
        case "turn.toolResult":
          settleToolRow(msg);
          break;
        case "turn.committed":
          el("committed", "saved to thread · " + esc(String(msg.interpretationId).slice(0, 8)) + "…");
          break;
        case "pending":
          renderPending(msg.actions);
          break;
        case "turn.error":
          el("error", esc(msg.message));
          break;
        case "turn.end": {
          if (msg.usage && turn) {
            const u = msg.usage;
            const parts = [];
            if (msg.rounds) parts.push(msg.rounds + " tool round" + (msg.rounds === 1 ? "" : "s"));
            parts.push(u.input.toLocaleString() + " in / " + u.output.toLocaleString() + " out");
            if (u.cacheRead) parts.push(u.cacheRead.toLocaleString() + " cached");
            const line = document.createElement("div");
            line.className = "usage";
            line.textContent = parts.join(" · ");
            turn.wrap.appendChild(line);
          }
          turn = null;
          setComposerEnabled(true);
          break;
        }
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
