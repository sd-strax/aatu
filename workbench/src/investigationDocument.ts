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
import { ActionRow, BackendClient, Hypothesis, InvestigationDetail } from "./backend";
import { AgentTransport } from "./agentTransport";

/** What the extension host posts to the webview to render. */
type RenderMessage =
  | { type: "loading" }
  | { type: "data"; investigation: InvestigationDetail; hypotheses: Hypothesis[] }
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
  | { type: "turn.end" };

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
    } catch (err) {
      void this.post(panel, { type: "turn.error", message: errText(err) });
    } finally {
      void this.post(panel, { type: "turn.end" });
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
    .decide { margin-top: 0.45rem; display: flex; gap: 0.5rem; }
    .decide .primary {
      color: var(--vscode-button-foreground);
      background: var(--vscode-button-background);
    }
    .decide .primary:hover { background: var(--vscode-button-hoverBackground); }
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
    <details class="thread" id="pendingWrap" open style="display:none">
      <summary>Pending actions — your approval</summary>
      <div id="pending"></div>
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

    // The action queue: rows are DOM-built (action_type/targets are
    // model-influenced — no innerHTML for them), each with Approve/Reject
    // posting to the host, which does the real call on the human token.
    function renderPending(actions) {
      const wrap = $("pendingWrap");
      const box = $("pending");
      const pend = (actions || []).filter((a) => a.pending);
      box.textContent = "";
      wrap.style.display = pend.length ? "" : "none";
      for (const a of pend) {
        const row = document.createElement("div");
        row.className = "hypothesis";

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
        targets.className = "meta";
        targets.textContent = "→ " + (a.targets || []).join(", ");

        row.append(head, targets);

        if (a.expired) {
          // The approval deadline passed — the engine refuses an approve, so
          // no buttons: an affordance that can only fail is a lie.
          row.style.opacity = "0.55";
          const note = document.createElement("div");
          note.className = "meta";
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
        case "turn.toolResult": {
          // Envelope results show coverage + count (distilled from the full
          // payload); non-envelope results just complete; errors say so.
          const mark = msg.isError ? "✗" : "✓";
          const detail = msg.isError ? " — error"
            : msg.coverage !== undefined ? " — " + esc(msg.coverage) + " · " + esc(msg.events) + " event(s)"
            : "";
          (turn ? turn.wrap : conversation).appendChild(Object.assign(document.createElement("div"), {
            className: "tool", innerHTML: '<span class="result">' + mark + ' ' + esc(msg.name) + detail + '</span>',
          }));
          break;
        }
        case "turn.committed":
          el("committed", "saved to thread · " + esc(msg.interpretationId));
          break;
        case "pending":
          renderPending(msg.actions);
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
