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
import { ActionRow, BackendClient, Capability, EvidenceDoc, Hypothesis, InvestigationDetail, PinRow, ThreadEntry } from "./backend";
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
  | { type: "pins"; pins: PinRow[] }
  // The committed conversation, reconstructed: one entry per transcript-
  // bearing thread act, in sequence order. The webview parses the line-framed
  // transcript bodies back into the conversation rendering (cold restore).
  | { type: "history.turns"; turns: { sequenceNo: number; occurredAt: string; body: string }[] }
  // A resolved human label for an evidence ref (e.g. "host · WIN-FILE01"),
  // so the chips read as evidence instead of opaque STIX ids.
  | { type: "evidence.label"; ref: string; label: string }
  | { type: "turn.start" }
  | { type: "turn.user"; text: string }
  | { type: "turn.reasoning"; delta: string }
  | { type: "turn.text"; delta: string }
  | { type: "turn.step"; round: number }
  | { type: "turn.tool"; name: string; input: unknown }
  | { type: "turn.toolResult"; name: string; isError: boolean; coverage?: string; events?: number; refs?: string[] }
  | { type: "turn.committed"; interpretationId: string }
  | { type: "turn.error"; message: string }
  | { type: "turn.end"; usage?: { input: number; output: number; cacheRead: number }; rounds?: number };

/** What the webview posts back to the extension host. */
type InboundMessage =
  | { type: "refresh" | "ready" }
  | { type: "send"; text: string }
  | { type: "action.approve"; actionId: string; tier: string; actionType: string }
  | { type: "action.reject"; actionId: string; actionType: string }
  | { type: "pin.add"; refs: string[]; finding: string }
  | { type: "pin.unpin"; interpretationId: string }
  | { type: "verdict.submit"; disposition: string; rationale: string; refs: string[] }
  | { type: "evidence.open"; ref: string }
  | { type: "evidence.resolve"; ref: string }
  | { type: "transcript.open"; interpretationId: string };

export class InvestigationDocuments {
  private readonly open = new Map<string, vscode.WebviewPanel>();
  // Resolved evidence-ref labels, shared across panels — deterministic ids
  // mean a ref resolves to the same thing everywhere, so cache once.
  private readonly labelCache = new Map<string, string>();

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
      } else if (msg.type === "pin.add") {
        void this.pinCommit(id, panel, msg.refs, msg.finding);
      } else if (msg.type === "pin.unpin") {
        void this.unpin(id, panel, msg.interpretationId);
      } else if (msg.type === "verdict.submit") {
        void this.submitVerdict(id, panel, msg);
      } else if (msg.type === "evidence.open") {
        void vscode.commands.executeCommand("reckon.openEvidence", msg.ref);
      } else if (msg.type === "evidence.resolve") {
        void this.resolveLabel(panel, msg.ref);
      } else if (msg.type === "transcript.open") {
        void this.openTranscript(msg.interpretationId);
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

      // Cold restore (07 cross-cutting acceptance): fetch the committed
      // transcripts and let the webview reconstruct the conversation. Bounded
      // to the most recent turns; failures skip silently (the compact thread
      // remains the fallback lens).
      const withTranscript = (thread ?? []).filter((e) => e.hasTranscript).slice(-30);
      if (withTranscript.length) {
        const turns = (await Promise.all(withTranscript.map(async (e) => {
          try {
            const t = await this.client.transcript(e.interpretationId);
            return { sequenceNo: e.sequenceNo, occurredAt: e.occurredAt, body: t.body };
          } catch {
            return null;
          }
        }))).filter((t): t is { sequenceNo: number; occurredAt: string; body: string } => t !== null);
        void this.post(panel, { type: "history.turns", turns });
      }
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

  /** Fetch + render the action queue and pin fold. Failure logs, never breaks. */
  private async postPending(id: string, panel: vscode.WebviewPanel): Promise<void> {
    try {
      const actions = await this.client.actions(id);
      void this.post(panel, { type: "pending", actions });
    } catch (err) {
      // A 503 here just means the action layer is off — not a broken panel.
      this.log.debug(`list actions ${id}: ${errText(err)}`);
    }
    try {
      const pins = await this.client.pins(id);
      void this.post(panel, { type: "pins", pins });
    } catch (err) {
      this.log.debug(`list pins ${id}: ${errText(err)}`);
    }
  }

  /**
   * Pin evidence — the analyst's curation act, on the human token. The finding
   * note is collected in-webview (the pin card), so this just records it.
   */
  private async pinCommit(id: string, panel: vscode.WebviewPanel, refs: string[], finding: string): Promise<void> {
    if (!refs.length || finding.trim() === "") {
      return;
    }
    try {
      await this.client.pinEvidence(id, finding.trim(), refs);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: pin failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /**
   * Resolve a human label for an evidence ref (host · WIN-FILE01, account ·
   * svc_backup) from the evidence endpoint, cached. Posts back only on a hit;
   * a ref that can't be opened keeps its type-only label in the webview.
   */
  private async resolveLabel(panel: vscode.WebviewPanel, ref: string): Promise<void> {
    let label = this.labelCache.get(ref);
    if (label === undefined) {
      try {
        label = deriveEvidenceLabel(await this.client.evidence(ref));
      } catch {
        label = "";
      }
      this.labelCache.set(ref, label);
    }
    if (label) {
      void this.post(panel, { type: "evidence.label", ref, label });
    }
  }

  /** Un-pin = supersession with a reason; the pin stays visible, struck. */
  private async unpin(id: string, panel: vscode.WebviewPanel, interpretationId: string): Promise<void> {
    const reason = await vscode.window.showInputBox({
      title: "reckon — un-pin evidence",
      prompt: "Why remove this from the evidence? (recorded; the pin stays visible, struck)",
      ignoreFocusOut: true,
      validateInput: (v) => (v.trim() === "" ? "a reason is required" : undefined),
    });
    if (reason === undefined || reason.trim() === "") {
      return;
    }
    try {
      await this.client.supersedeInterpretation(interpretationId, id, reason.trim());
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: un-pin failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /** Record the verdict of record — always the analyst's act here (human token). */
  private async submitVerdict(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { disposition: string; rationale: string; refs: string[] },
  ): Promise<void> {
    try {
      await this.client.recordVerdict(id, msg.disposition, msg.rationale, msg.refs);
      void vscode.window.showInformationMessage(`reckon: verdict recorded — ${msg.disposition}`);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: verdict failed — ${errText(err)}`);
    }
    await this.load(id, panel);
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

  /** Open a thread step's full committed transcript in a read-only tab. */
  private async openTranscript(interpretationId: string): Promise<void> {
    try {
      const t = await this.client.transcript(interpretationId);
      const doc = await vscode.workspace.openTextDocument({
        content: t.body,
        language: "plaintext",
      });
      await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: transcript unavailable — ${errText(err)}`);
    }
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
        onStep: (round) => void this.post(panel, { type: "turn.step", round }),
        onToolCall: (name, input) => void this.post(panel, { type: "turn.tool", name, input }),
        // coverage/events come distilled from the sidecar (from the full,
        // unclipped payload) — absent for non-envelope results, and the
        // webview renders that honestly instead of a bogus "? · 0".
        onToolResult: (name, _content, isError, coverage, events, refs) =>
          void this.post(panel, { type: "turn.toolResult", name, isError, coverage, events, refs }),
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
    .stepmark { font-size: 0.7rem; opacity: 0.4; margin: 0.5rem 0 0.1rem; letter-spacing: 0.08em; }
    .sopchip {
      display: inline-block; font-size: 0.7rem; padding: 0.02rem 0.4rem;
      margin: 0.1rem 0.2rem 0 0; border: 1px solid var(--vscode-charts-blue, #4e94ce);
      border-radius: 0.5rem; opacity: 0.85;
    }
    .sopchip.consulted { border-style: dashed; opacity: 0.55; }
    .translink { cursor: pointer; text-decoration: underline; opacity: 0.7; font-size: 0.72rem; }
    .translink:hover { opacity: 1; }
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
    .railfold { margin-bottom: 1.1rem; }
    .railfold > summary {
      font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em;
      opacity: 0.6; font-weight: 600; cursor: pointer; margin-bottom: 0.45rem;
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

    /* ---- verdict + pins + citations ---- */
    .verdictbadge.BENIGN { background: rgba(78,199,123,.2); color: var(--vscode-charts-green, #4ec77b); }
    .verdictbadge.SUSPICIOUS { background: rgba(245,181,61,.2); color: var(--vscode-charts-yellow, #f5b53d); }
    .verdictbadge.MALICIOUS { background: rgba(255,95,110,.2); color: var(--vscode-charts-red, #ff5f6e); }
    .refchip {
      display: inline-block; font-family: var(--vscode-editor-font-family);
      font-size: 0.72rem; padding: 0.02rem 0.35rem; margin: 0.1rem 0.15rem 0.1rem 0;
      border: 1px solid var(--vscode-panel-border); border-radius: 0.3rem;
      cursor: pointer; opacity: 0.85; max-width: 100%; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom;
    }
    .refchip:hover { border-color: var(--vscode-focusBorder, currentColor); opacity: 1; }
    .pinrow .finding { font-size: 0.84rem; }
    .pinrow.superseded .finding { text-decoration: line-through; opacity: 0.55; }
    .pinrow .unpin { float: right; font-size: 0.72rem; padding: 0 0.35rem; }
    .countdown.warn { color: var(--vscode-charts-yellow, #f5b53d); font-weight: 600; }
    .countdown.due { color: var(--vscode-errorForeground); font-weight: 600; }
    .toolrefs { padding: 0.35rem 0.6rem 0.5rem; border-top: 1px solid var(--vscode-panel-border); font-family: var(--vscode-font-family); }
    .toolactions { margin-top: 0.4rem; }
    .pincta {
      font-size: 0.76rem; padding: 0.15rem 0.6rem;
      color: var(--vscode-button-foreground);
      background: var(--vscode-button-background);
      border-radius: 0.3rem;
    }
    .pincta:hover { background: var(--vscode-button-hoverBackground); }
    .stepPin { font-size: 0.7rem; padding: 0.05rem 0.45rem; margin-left: 0.35rem; }
    /* The pin sits at the right end of the always-visible tool summary. */
    .summaryPin { flex: none; margin-left: auto; font-size: 0.72rem; padding: 0.02rem 0.5rem; }
    details.tool[open] .summaryPin { opacity: 0.9; }

    #verdictDialog, #pinDialog {
      position: fixed; inset: 0; background: rgba(0,0,0,.45);
      display: flex; align-items: center; justify-content: center; z-index: 10;
    }
    #pinDialog textarea {
      width: 100%; box-sizing: border-box; font: inherit; resize: vertical;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 0.3rem; padding: 0.4rem 0.5rem;
    }
    .pinrefs { margin: 0.5rem 0 0.3rem; }
    .pinhelp { font-size: 0.76rem; opacity: 0.6; margin-bottom: 0.2rem; }
    #verdictDialog .dlg, #pinDialog .dlg {
      width: min(480px, 90vw); background: var(--vscode-editorWidget-background, var(--vscode-editor-background));
      border: 1px solid var(--vscode-widget-border, var(--vscode-panel-border));
      border-radius: 0.5rem; padding: 0.9rem 1.1rem 1rem;
      box-shadow: 0 8px 28px rgba(0,0,0,.45);
    }
    #verdictDialog h3 { margin: 0 0 0.6rem; font-size: 1rem; }
    .checklist { margin: 0.3rem 0 0.6rem; font-size: 0.84rem; }
    .checklist .item { margin: 0.2rem 0; }
    .checklist .ok { color: var(--vscode-charts-green, #4ec77b); }
    .checklist .unmet { color: var(--vscode-charts-yellow, #f5b53d); }
    .dlglabel { font-size: 0.72rem; text-transform: uppercase; letter-spacing: .05em; opacity: 0.6; margin: 0.55rem 0 0.25rem; }
    .dispositions label { margin-right: 0.9rem; font-size: 0.86rem; cursor: pointer; }
    #verdictRationale {
      width: 100%; box-sizing: border-box; font: inherit; resize: vertical;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 0.3rem; padding: 0.4rem 0.5rem;
    }
    .residual { font-size: 0.78rem; opacity: 0.75; margin-top: 0.55rem; border-left: 2px solid var(--vscode-panel-border); padding-left: 0.6rem; }
    .residual .rtitle { text-transform: uppercase; letter-spacing: .05em; font-size: 0.7rem; opacity: 0.8; margin-bottom: 0.2rem; }

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
        <span class="state verdictbadge" id="verdictBadge" style="display:none"></span>
        <button id="verdictBtn" title="Record the disposition of record">Verdict…</button>
        <button id="refresh" title="Reload from the backend">Refresh</button>
      </div>
      <div id="meta"></div>
    </header>

    <div id="scroll">
      <div id="banner"></div>
      <details id="historyWrap" style="display:none">
        <summary id="historySummary">How this investigation got here</summary>
        <div id="history"></div>
      </details>
      <div id="restored"></div>
      <div id="conversation"></div>
    </div>

    <div id="composer">
      <textarea id="input" rows="1" placeholder="Ask reckon to investigate… (Enter to send, Shift+Enter for newline)"></textarea>
      <button id="send">Send</button>
    </div>
  </div>

  <aside id="rail">
    <!-- The rail mirrors the epistemic workflow: what we believe (hypotheses,
         the scoreboard) → what grounds it (pinned evidence). Approvals are an
         INTERRUPT, not a section: hidden when empty, pinned above everything
         when something actually needs the analyst (a countdown outranks all).
         Capability health is operator info (13 §4 puts it in the container) —
         collapsed to a count here; coverage already surfaces where it bites
         (tool-result rows, the verdict residual). -->
    <section id="pendingSection" style="display:none">
      <h2>Needs your approval</h2>
      <div id="pending"></div>
    </section>
    <section>
      <h2>Hypotheses</h2>
      <div id="hyps"><div class="empty">None yet</div></div>
    </section>
    <section>
      <h2 id="pinsHead">Pinned evidence</h2>
      <div id="pinsBox"><div class="empty">Nothing pinned yet</div></div>
    </section>
    <details id="capsFold" class="railfold">
      <summary id="capsHead">Capabilities</summary>
      <div id="caps"><div class="empty">…</div></div>
    </details>
  </aside>

  <div id="pinDialog" style="display:none">
    <div class="dlg">
      <h3>Pin as evidence</h3>
      <div class="dlglabel">What does this evidence show?</div>
      <textarea id="pinFinding" rows="3" placeholder="e.g. First external egress from the svc_backup source host, 15s after the encoded PowerShell"></textarea>
      <div id="pinRefs" class="pinrefs"></div>
      <div class="pinhelp">Recorded on the investigation thread and cited by your verdict.</div>
      <div class="decide">
        <button class="primary" id="pinConfirm" disabled>📌 Pin evidence</button>
        <button id="pinCancel">Cancel</button>
      </div>
    </div>
  </div>

  <div id="verdictDialog" style="display:none">
    <div class="dlg">
      <h3>Record verdict</h3>
      <div class="checklist" id="verdictChecklist"></div>
      <div class="dlglabel">Disposition</div>
      <div class="dispositions" id="dispositions">
        <label><input type="radio" name="disp" value="BENIGN"> BENIGN</label>
        <label><input type="radio" name="disp" value="SUSPICIOUS"> SUSPICIOUS</label>
        <label><input type="radio" name="disp" value="MALICIOUS"> MALICIOUS</label>
      </div>
      <div class="dlglabel">Rationale (required — this is the record)</div>
      <textarea id="verdictRationale" rows="3"></textarea>
      <div class="residual" id="verdictResidual"></div>
      <div class="decide">
        <button class="primary" id="verdictSubmit" disabled>Record verdict</button>
        <button id="verdictCancel">Cancel</button>
      </div>
    </div>
  </div>

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

    // Rail state the verdict dialog + header badges derive from.
    let lastPins = [], lastHyps = [], lastCaps = null, lastVerdict = null, lastPending = [];

    // A clickable citation (02 §2.8): every ref opens. The chip reads as
    // evidence — a type label immediately (from the id prefix), enriched with
    // the actual value ("host · WIN-FILE01") once the host resolves it. The
    // full id is always in the tooltip.
    const REF_TYPE_LABELS = {
      "observed-data": "observed data", "x-host": "host", "ipv4-addr": "IP",
      "ipv6-addr": "IP", "user-account": "account", "process": "process",
      "file": "file", "domain-name": "domain", "email-addr": "email",
      "url": "URL", "windows-registry-key": "registry", "indicator": "indicator",
      "x-hypothesis": "hypothesis", "x-prediction": "prediction",
      "identity": "vendor", "sighting": "sighting",
    };
    const resolvedLabels = {}; // ref → resolved value, webview-side cache
    function refTypeLabel(ref) {
      const t = ref.includes("--") ? ref.slice(0, ref.indexOf("--")) : "event";
      return REF_TYPE_LABELS[t] || t;
    }
    function chipText(ref) {
      const type = refTypeLabel(ref);
      const val = resolvedLabels[ref];
      return val ? type + " · " + val : type;
    }
    function refChip(ref) {
      const c = document.createElement("span");
      c.className = "refchip";
      c.dataset.ref = ref;
      c.textContent = chipText(ref);
      c.title = "Open evidence: " + ref;
      c.addEventListener("click", (e) => {
        e.stopPropagation();
        vscode.postMessage({ type: "evidence.open", ref });
      });
      if (resolvedLabels[ref] === undefined) {
        vscode.postMessage({ type: "evidence.resolve", ref });
      }
      return c;
    }

    // Live approval-window countdown (03 §3.3): the analyst's only warning
    // for lazy expiry. Elements carry data-expires (epoch ms).
    function fmtRemaining(ms) {
      if (ms <= 0) return "expired";
      const m = Math.floor(ms / 60000), s = Math.floor((ms % 60000) / 1000);
      return m > 0 ? m + "m " + s + "s" : s + "s";
    }
    setInterval(() => {
      for (const el of document.querySelectorAll("[data-expires]")) {
        const left = Number(el.dataset.expires) - Date.now();
        el.textContent = left <= 0 ? "window expired — refresh" : "expires in " + fmtRemaining(left);
        el.classList.toggle("due", left <= 0);
        el.classList.toggle("warn", left > 0 && left < 5 * 60000);
      }
    }, 1000);

    // Header badges: engine status + verdict + the derived presentation label
    // (binding §2.4 — ACTIVE reads as remediating / verdict-reached; derived,
    // never stored).
    function renderHeaderState(status) {
      if (status) $("state").dataset.engine = status;
      const engine = $("state").dataset.engine || "";
      let label = engine;
      if (engine === "ACTIVE") {
        const open = lastPending.some((a) => a.pending && !a.expired) ||
          lastPending.some((a) => a.status === "APPROVED" || a.status === "EXECUTING");
        if (open) label = "ACTIVE · REMEDIATING";
        else if (lastVerdict) label = "ACTIVE · VERDICT REACHED";
      }
      $("state").textContent = label;
      const vb = $("verdictBadge");
      if (lastVerdict) {
        vb.style.display = "";
        vb.textContent = lastVerdict.disposition;
        vb.className = "state verdictbadge " + lastVerdict.disposition;
        vb.title = lastVerdict.rationale || "";
      } else {
        vb.style.display = "none";
      }
    }

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

      // Pin-from-result (02 §2.8, 01 §Pinned evidence): the pin lives on the
      // always-visible SUMMARY line — pinning is the point of a result, not a
      // detail to hunt for behind the disclosure. The ref chips (inspectable
      // citations) stay in the expanded body.
      attachResultRefs(row, msg.refs);
    }

    // attachResultRefs puts a pin button on the row's summary (always visible)
    // and the citation chips in the expanded body. Shared by the live and the
    // reconstructed tool rows.
    function attachResultRefs(row, refs) {
      if (!refs || !refs.length) return;
      const pin = document.createElement("button");
      pin.className = "pincta summaryPin";
      pin.textContent = "📌 Pin";
      pin.title = "Pin this result as evidence (cites all " + refs.length + " refs)";
      pin.addEventListener("click", (e) => {
        e.stopPropagation();       // don't toggle the disclosure
        e.preventDefault();
        openPinDialog(refs);
      });
      row.querySelector("summary").appendChild(pin);

      const box = document.createElement("div");
      box.className = "toolrefs";
      for (const r of refs.slice(0, 12)) box.appendChild(refChip(r));
      row.appendChild(box);
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
        if (extras.length) {
          const ex = document.createElement("span");
          ex.textContent = extras.join(" · ");
          head.append(ex);
        }

        const body = document.createElement("div");
        body.className = "stepbody md";
        body.innerHTML = md(e.summary);

        step.append(head, body);

        // The step's citations, as CHIPS (02 §2.8 — every citation opens),
        // not a count: after a reload, the thread is the only lens on the
        // conversation, so its refs must stay clickable and pinnable.
        const allRefs = [];
        for (const r of (e.inputRefs || []).concat(e.outputRefs || [])) {
          if (r && !allRefs.includes(r)) allRefs.push(r);
        }
        if (allRefs.length) {
          const refsRow = document.createElement("div");
          const shown = allRefs.slice(0, 8);
          for (const r of shown) refsRow.appendChild(refChip(r));
          if (allRefs.length > shown.length) {
            const more = document.createElement("span");
            more.className = "cardmeta";
            more.textContent = "+" + (allRefs.length - shown.length) + " more";
            refsRow.appendChild(more);
          }
          const pin = document.createElement("button");
          pin.className = "pincta stepPin";
          pin.textContent = "📌 Pin…";
          pin.title = "Pin this step's cited evidence (" + allRefs.length + " refs)";
          pin.addEventListener("click", () => openPinDialog(allRefs));
          refsRow.appendChild(pin);
          step.appendChild(refsRow);
        }

        // Knowledge provenance chips (02 §2.11): followed vs consulted.
        if (e.consultedSops && e.consultedSops.length) {
          const sops = document.createElement("div");
          for (const c of e.consultedSops) {
            const chip = document.createElement("span");
            chip.className = "sopchip" + (c.used ? "" : " consulted");
            chip.textContent = (c.used ? "followed SOP: " : "consulted: ") + (c.title || c.sopId);
            chip.title = c.used ? "the turn's text references this SOP" : "retrieved, not applied";
            sops.appendChild(chip);
          }
          step.appendChild(sops);
        }
        // The full committed turn record, one click away (02 §2.9's data).
        if (e.hasTranscript) {
          const tl = document.createElement("span");
          tl.className = "translink";
          tl.textContent = "open transcript";
          tl.addEventListener("click", () =>
            vscode.postMessage({ type: "transcript.open", interpretationId: e.interpretationId }));
          step.appendChild(tl);
        }
        box.appendChild(step);
      }
    }

    // ---- cold restore: the committed conversation --------------------------
    // Transcripts are line-framed ([user]/[assistant]/[tool_use]/[tool_result]
    // records, one per line, content newlines escaped) and results carry the
    // FULL payloads — so reconstruction renders real coverage, refs, and
    // pinnable chips, not a summary. Rebuilt idempotently on every load;
    // entries past the first-load cutoff arrive as live turns instead.
    function unescapeT(s) {
      return String(s ?? "").replace(/\\\\n/g, "\\n").replace(/\\\\r/g, "\\r");
    }

    function renderRestored(turns) {
      if (historyCutoff === null) return;
      const box = $("restored");
      box.textContent = "";
      const shown = (turns || [])
        .filter((t) => t.sequenceNo <= historyCutoff)
        .sort((a, b) => a.sequenceNo - b.sequenceNo);
      for (const t of shown) box.appendChild(restoredTurn(t));
    }

    function restoredTurn(t) {
      const wrap = document.createElement("div");
      const hdr = document.createElement("div");
      hdr.className = "usage";
      hdr.textContent = (t.occurredAt ? new Date(t.occurredAt).toLocaleString() + " · " : "") + "committed turn";
      wrap.appendChild(hdr);

      const rows = new Map(); // tool call id → row, for result matching
      for (const line of String(t.body).split("\\n")) {
        let m;
        if ((m = line.match(/^\\[user\\] ([^]*)$/))) {
          const u = document.createElement("div");
          u.className = "msg user";
          const b = document.createElement("span");
          b.className = "bubble";
          b.textContent = unescapeT(m[1]);
          u.appendChild(b);
          wrap.appendChild(u);
        } else if ((m = line.match(/^\\[assistant\\] ([^]*)$/))) {
          const seg = document.createElement("div");
          seg.className = "msg assistant md";
          seg.innerHTML = md(unescapeT(m[1]));
          wrap.appendChild(seg);
        } else if ((m = line.match(/^\\[tool_use ([^ \\]]+) id=([^\\]]+)\\] ([^]*)$/))) {
          const row = staticToolRow(m[1], m[3]);
          rows.set(m[2], row);
          wrap.appendChild(row);
        } else if ((m = line.match(/^\\[tool_result ([^ \\]]+) id=([^ \\]]+) error=(true|false)\\] ([^]*)$/))) {
          settleStaticRow(rows.get(m[2]), m[3] === "true", unescapeT(m[4]));
        } else if ((m = line.match(/^\\[loop\\] ([^]*)$/))) {
          const d = document.createElement("div");
          d.className = "committed";
          d.textContent = m[1];
          wrap.appendChild(d);
        }
      }
      return wrap;
    }

    function staticToolRow(name, argsRaw) {
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
      hint.textContent = argsRaw;
      sum.append(mark, verb, hint);
      const body = document.createElement("pre");
      try {
        body.textContent = JSON.stringify(JSON.parse(unescapeT(argsRaw)), null, 2);
      } catch {
        body.textContent = unescapeT(argsRaw);
      }
      row.append(sum, body);
      return row;
    }

    function settleStaticRow(row, isErr, content) {
      if (!row) return;
      const mark = row.querySelector(".mark");
      mark.textContent = isErr ? "✗" : "✓";
      mark.classList.add(isErr ? "err" : "ok");

      // Distill the envelope exactly as the sidecar does live — the FULL
      // payload is in the committed record here, so nothing is guessed.
      let detail = isErr ? "error" : "done";
      const refs = [];
      try {
        const env2 = JSON.parse(content);
        if (env2 && env2.coverage) {
          detail = env2.coverage + " · " + (Array.isArray(env2.events) ? env2.events.length : 0) + " event(s)";
          for (const k of ["observed_data_refs", "entity_refs", "ocsf_event_refs"]) {
            for (const r of env2[k] || []) if (!refs.includes(r)) refs.push(r);
          }
        }
      } catch { /* not an envelope — plain result */ }
      const st = document.createElement("span");
      st.className = "hint status";
      st.textContent = detail;
      row.querySelector("summary").appendChild(st);

      // The result detail: for a capability envelope, coverage + refs are
      // distilled into the summary + chips, so the raw envelope is noise —
      // show the normalized objects (or nothing) instead of the JSON dump.
      // For a non-envelope result, pretty-print what there is.
      let detailBody = "";
      try {
        const env2 = JSON.parse(content);
        if (!(env2 && env2.coverage)) {
          detailBody = JSON.stringify(env2, null, 2);
        }
      } catch {
        detailBody = content;
      }
      if (detailBody) {
        const res = document.createElement("pre");
        res.textContent = detailBody.length > 4000 ? detailBody.slice(0, 4000) + "…" : detailBody;
        row.appendChild(res);
      }

      attachResultRefs(row, refs);
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
        $("capsHead").textContent = "Capabilities · off";
        box.innerHTML = '<div class="empty">capability layer off</div>';
        return;
      }
      if (!caps.length) {
        $("capsHead").textContent = "Capabilities";
        box.innerHTML = '<div class="empty">none configured</div>';
        return;
      }
      const avail = caps.filter((c) => c.status === "available").length;
      $("capsHead").textContent = "Capabilities · " + avail + "/" + caps.length + " available";
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

    // Pinned evidence (01 §Pinned evidence): the curation fold. Superseded
    // pins render struck, never absent. DOM-built (findings are free text).
    function renderPins(pins) {
      lastPins = pins || [];
      const box = $("pinsBox");
      const active = lastPins.filter((p) => !p.superseded).length;
      $("pinsHead").textContent = "Pinned evidence" + (lastPins.length ? " · " + active : "");
      box.textContent = "";
      if (!lastPins.length) {
        box.innerHTML = '<div class="empty">Nothing pinned yet — pin key findings from tool results</div>';
        return;
      }
      for (const p of lastPins) {
        const row = document.createElement("div");
        row.className = "card pinrow" + (p.superseded ? " superseded" : "");
        if (!p.superseded) {
          const un = document.createElement("button");
          un.className = "unpin";
          un.textContent = "un-pin";
          un.title = "Supersede this pin (stays visible, struck)";
          un.addEventListener("click", () =>
            vscode.postMessage({ type: "pin.unpin", interpretationId: p.interpretationId }));
          row.appendChild(un);
        }
        const finding = document.createElement("div");
        finding.className = "finding";
        finding.textContent = p.finding;
        const meta = document.createElement("div");
        meta.className = "cardmeta";
        meta.textContent = (p.actor === "AI_DELEGATED" ? "AI" : p.actor === "SYSTEM" ? "system" : "analyst")
          + (p.pinnedAt ? " · " + new Date(p.pinnedAt).toLocaleString() : "");
        const refs = document.createElement("div");
        for (const r of p.inputRefs || []) refs.appendChild(refChip(r));
        row.append(finding, meta, refs);
        box.appendChild(row);
      }
    }

    // The action queue: rows are DOM-built (action_type/targets are
    // model-influenced — no innerHTML for them), each with Approve/Reject
    // posting to the host, which does the real call on the human token.
    function renderPending(actions) {
      lastPending = actions || [];
      renderHeaderState();
      const box = $("pending");
      const pend = lastPending.filter((a) => a.pending);
      box.textContent = "";
      // The interrupt pattern: no section at all when nothing needs the
      // analyst; pinned above everything when something does.
      $("pendingSection").style.display = pend.length ? "" : "none";
      if (!pend.length) {
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

        // Decision-grade rows (03 §3.3): the card answers the decision.
        if (a.retryOf) {
          const rl = document.createElement("div");
          rl.className = "cardmeta";
          rl.textContent = "↻ retry of " + a.retryOf.slice(0, 8) + "… (the original can never re-dispatch)";
          row.append(rl);
        }
        if (a.tierEscalated) {
          const esc2 = document.createElement("div");
          esc2.className = "cardmeta";
          esc2.textContent = "⚠ escalated to " + a.tier + ": " + (a.targets || []).length + " targets (blast radius)";
          row.append(esc2);
        }
        if (a.reversibility) {
          const rev = document.createElement("div");
          rev.className = "cardmeta";
          rev.textContent = a.reversibility === "REVERSIBLE" ? "↩ reversible"
            : a.reversibility === "BEST_EFFORT" ? "↩? best-effort reversal — cannot be verified undone; treat as permanent"
            : "⚠ irreversible";
          row.append(rev);
        }
        if ((a.evidenceRefs || []).length) {
          const ev = document.createElement("div");
          ev.className = "cardmeta";
          ev.textContent = "evidence: ";
          for (const r of a.evidenceRefs) ev.appendChild(refChip(r));
          row.append(ev);
        }
        if (!a.expired && a.expiresAt) {
          const cd = document.createElement("div");
          cd.className = "cardmeta countdown";
          cd.dataset.expires = String(Date.parse(a.expiresAt));
          cd.textContent = "…";
          row.append(cd);
        }

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

    // ---- pin card: collect the finding in-context (not a top-of-window box) -
    let pinRefs = [];
    function openPinDialog(refs) {
      pinRefs = refs || [];
      $("pinFinding").value = "";
      const box = $("pinRefs");
      box.textContent = "";
      for (const r of pinRefs.slice(0, 12)) box.appendChild(refChip(r));
      if (pinRefs.length > 12) {
        const more = document.createElement("span");
        more.className = "cardmeta";
        more.textContent = "+" + (pinRefs.length - 12) + " more";
        box.appendChild(more);
      }
      $("pinConfirm").disabled = true;
      $("pinDialog").style.display = "flex";
      $("pinFinding").focus();
    }
    $("pinFinding").addEventListener("input", () => {
      $("pinConfirm").disabled = $("pinFinding").value.trim() === "";
    });
    // ⌘/Ctrl+Enter confirms; Escape cancels.
    $("pinFinding").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && !$("pinConfirm").disabled) submitPin();
      else if (e.key === "Escape") $("pinDialog").style.display = "none";
    });
    $("pinCancel").addEventListener("click", () => { $("pinDialog").style.display = "none"; });
    $("pinConfirm").addEventListener("click", submitPin);
    function submitPin() {
      const finding = $("pinFinding").value.trim();
      if (!finding || !pinRefs.length) return;
      vscode.postMessage({ type: "pin.add", refs: pinRefs, finding });
      $("pinDialog").style.display = "none";
    }

    // ---- verdict dialog: preflight + residual (02 §2.10) -------------------
    // The engine's gates rendered BEFORE the attempt (non-negotiable #7): the
    // rejection message is the fallback, never the first thing seen.
    function openVerdictDialog() {
      const activePins = lastPins.filter((p) => !p.superseded);
      const check = $("verdictChecklist");
      check.textContent = "";
      const item = (ok, text) => {
        const d = document.createElement("div");
        d.className = "item " + (ok ? "ok" : "unmet");
        d.textContent = (ok ? "☑ " : "☐ ") + text;
        check.appendChild(d);
      };
      item(activePins.length > 0, activePins.length > 0
        ? activePins.length + " evidence item(s) pinned"
        : "no pinned evidence — pin the key findings first (the engine will refuse)");
      item(true, "cites the pinned evidence (attached automatically)");
      if (lastVerdict) {
        item(true, "revises the current verdict (" + lastVerdict.disposition + ") — history is preserved");
      }

      // The residual: what the analyst is signing over (02 §2.10).
      const res = $("verdictResidual");
      res.textContent = "";
      const rt = document.createElement("div");
      rt.className = "rtitle";
      rt.textContent = "Not investigated — you are signing over this residual";
      res.appendChild(rt);
      const unavailable = (lastCaps || []).filter((c) => c.status === "unavailable").map((c) => c.verb);
      const untested = [];
      for (const h of lastHyps) {
        for (const p of h.predictions || []) {
          if (p.status === "UNTESTED") untested.push(p.statement);
        }
      }
      const line = (text) => {
        const d = document.createElement("div");
        d.textContent = "· " + text;
        res.appendChild(d);
      };
      if (unavailable.length) line("verbs never checkable in this tenant: " + unavailable.join(", "));
      for (const s of untested.slice(0, 5)) line("untested prediction: " + s);
      if (untested.length > 5) line("… and " + (untested.length - 5) + " more untested predictions");
      if (!unavailable.length && !untested.length) line("no known gaps — all configured verbs available, no untested predictions");

      $("verdictRationale").value = "";
      for (const r of document.querySelectorAll('input[name="disp"]')) r.checked = false;
      updateVerdictSubmit();
      $("verdictDialog").style.display = "flex";
    }
    function updateVerdictSubmit() {
      const disp = document.querySelector('input[name="disp"]:checked');
      const rationale = $("verdictRationale").value.trim();
      const pinsOk = lastPins.some((p) => !p.superseded);
      $("verdictSubmit").disabled = !(disp && rationale && pinsOk);
    }
    $("verdictBtn").addEventListener("click", openVerdictDialog);
    $("verdictCancel").addEventListener("click", () => { $("verdictDialog").style.display = "none"; });
    $("verdictRationale").addEventListener("input", updateVerdictSubmit);
    $("dispositions").addEventListener("change", updateVerdictSubmit);
    $("verdictSubmit").addEventListener("click", () => {
      const disp = document.querySelector('input[name="disp"]:checked');
      if (!disp) return;
      const refs = [];
      for (const p of lastPins.filter((x) => !x.superseded)) {
        for (const r of p.inputRefs || []) if (!refs.includes(r)) refs.push(r);
      }
      vscode.postMessage({
        type: "verdict.submit",
        disposition: disp.value,
        rationale: $("verdictRationale").value.trim(),
        refs,
      });
      $("verdictDialog").style.display = "none";
    });

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
          $("meta").innerHTML = '<code>' + esc(msg.investigation.id) + '</code> · seq ' + esc(msg.investigation.lastEventSequence);
          lastHyps = msg.hypotheses || [];
          lastCaps = msg.capabilities;
          lastVerdict = msg.investigation.verdict || null;
          renderHeaderState(msg.investigation.state);
          renderHypotheses(msg.hypotheses);
          renderCapabilities(msg.capabilities);
          renderHistory(msg.thread);
          break;
        case "pins":
          renderPins(msg.pins);
          break;
        case "history.turns":
          renderRestored(msg.turns);
          break;
        case "evidence.label":
          // Enrich every chip for this ref, in place (chips added later read
          // the cache on creation).
          resolvedLabels[msg.ref] = msg.label;
          for (const c of document.querySelectorAll(".refchip")) {
            if (c.dataset.ref === msg.ref) c.textContent = chipText(msg.ref);
          }
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
        case "turn.step":
          // A subtle step divider from round 2 on (round 1 is the turn start).
          if (turn && msg.round > 1) {
            turn.seg = null;
            const d = document.createElement("div");
            d.className = "stepmark";
            d.textContent = "· step " + msg.round + " ·";
            turn.wrap.appendChild(d);
          }
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

/**
 * A short human label for an opened evidence ref — what it IS, not its id.
 * OCSF records label by class; STIX objects by the salient property of their
 * type (hostname, account, process+pid, address). Empty when nothing sensible
 * can be read, leaving the chip its type-only label.
 */
function deriveEvidenceLabel(doc: EvidenceDoc): string {
  if (doc.kind === "ocsf") {
    return doc.type || "event";
  }
  const p = (doc.payload ?? {}) as Record<string, unknown>;
  const props = (typeof p.properties === "object" && p.properties ? p.properties : p) as Record<string, unknown>;
  const first = (...keys: string[]): string => {
    for (const k of keys) {
      const v = props[k];
      if (typeof v === "string" && v !== "") return v;
      if (typeof v === "number") return String(v);
    }
    return "";
  };
  const val = first("hostname", "value", "address", "name", "user_id", "account_login", "display_name", "path");
  if (val) {
    const pid = props.pid;
    return typeof pid === "number" ? `${val} (pid ${pid})` : val;
  }
  if (doc.type === "observed-data" && Array.isArray(p.object_refs)) {
    const n = p.object_refs.length;
    return `${n} object${n === 1 ? "" : "s"}`;
  }
  return "";
}
