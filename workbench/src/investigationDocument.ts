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

import { randomUUID } from "crypto";
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
  | { type: "action.approve"; actionId: string; tier: string; actionType: string; challenge?: string }
  | { type: "action.reject"; actionId: string; actionType: string; reason: string }
  | { type: "action.rerequest"; actionId: string; actionType: string; rationale: string }
  | { type: "pin.add"; refs: string[]; finding: string }
  | { type: "pin.unpin"; interpretationId: string; reason: string }
  | { type: "verdict.submit"; disposition: string; rationale: string; refs: string[] }
  | { type: "hyp.ack"; hypothesisRef: string }
  | { type: "lifecycle"; transition: string; reason?: string; summary?: string }
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
      } else if (msg.type === "action.rerequest") {
        void this.rerequest(id, panel, msg);
      } else if (msg.type === "pin.add") {
        void this.pinCommit(id, panel, msg.refs, msg.finding);
      } else if (msg.type === "pin.unpin") {
        void this.unpin(id, panel, msg.interpretationId, msg.reason);
      } else if (msg.type === "verdict.submit") {
        void this.submitVerdict(id, panel, msg);
      } else if (msg.type === "hyp.ack") {
        void this.ackHypothesis(id, panel, msg.hypothesisRef);
      } else if (msg.type === "lifecycle") {
        void this.lifecycleTransition(id, panel, msg);
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

  /**
   * Un-pin = supersession with a reason; the pin stays visible, struck. The
   * reason is collected in the webview prompt card, so this just records it.
   */
  private async unpin(id: string, panel: vscode.WebviewPanel, interpretationId: string, reason: string): Promise<void> {
    if (reason.trim() === "") {
      return;
    }
    try {
      await this.client.supersedeInterpretation(interpretationId, id, reason.trim());
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: un-pin failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /**
   * Acknowledge an AI-PROPOSED hypothesis — the human taking ownership of the
   * line of inquiry (02 §2.9). The aggregate enforces that this is a human act;
   * a rejection surfaces verbatim.
   */
  private async ackHypothesis(id: string, panel: vscode.WebviewPanel, hypothesisRef: string): Promise<void> {
    try {
      await this.client.acknowledgeHypothesis(id, hypothesisRef);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: acknowledge failed — ${errText(err)}`);
    }
    await this.load(id, panel);
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
   * Drive one lifecycle transition — always the analyst's act on the human
   * token (the aggregate's actor allowlist bars an AI delegate from
   * conclude/reopen/archive). Conclude mints the STIX Report id here — the
   * Report object itself is v1; the aggregate requires the reference — and the
   * aggregate refuses to conclude without a verdict of record, an error we
   * surface verbatim. A full reload follows: status, thread, and (after
   * conclude) the export trail all changed.
   */
  private async lifecycleTransition(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { transition: string; reason?: string; summary?: string },
  ): Promise<void> {
    try {
      const body: { transition: string; reason?: string; reportRef?: string; summary?: string } = {
        transition: msg.transition,
        reason: msg.reason?.trim() || undefined,
      };
      if (msg.transition === "conclude") {
        body.reportRef = `report--${randomUUID()}`;
        body.summary = msg.summary?.trim() || undefined;
      }
      const res = await this.client.lifecycle(id, body);
      const exportNote = res.exportWorkflowId ? " · export started" : "";
      void vscode.window.showInformationMessage(`reckon: investigation → ${res.status}${exportNote}`);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: ${msg.transition} failed — ${errText(err)}`);
    }
    await this.load(id, panel);
    await this.postPending(id, panel);
  }

  /**
   * Approve one action — the analyst's own act, extension→backend on the
   * HUMAN token, never through the sidecar (implementation/agent-sidecar.md
   * §5). A T3 approval carries the typed challenge (04 §5.5), collected in the
   * webview prompt card before this fires.
   */
  private async approve(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { actionId: string; tier: string; actionType: string; challenge?: string },
  ): Promise<void> {
    if (msg.tier === "T3" && (!msg.challenge || msg.challenge.trim() === "")) {
      await this.postPending(id, panel); // no challenge — re-enable the buttons
      return;
    }
    try {
      const decision = await this.client.approveAction(msg.actionId, msg.challenge);
      void vscode.window.showInformationMessage(
        `reckon: ${msg.actionType} → ${decision.status}${decision.stage ? ` (${decision.stage})` : ""}`,
      );
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: approve failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /** Reject one action — human token only; reason from the webview prompt card. */
  private async reject(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { actionId: string; actionType: string; reason: string },
  ): Promise<void> {
    try {
      const decision = await this.client.rejectAction(
        msg.actionId,
        msg.reason.trim() === "" ? "rejected from the workbench" : msg.reason.trim(),
      );
      void vscode.window.showInformationMessage(`reckon: ${msg.actionType} → ${decision.status}`);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: reject failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /**
   * Re-request an expired action — a fresh request (same targets & evidence,
   * new window, retry_of lineage) the analyst then approves. Not a bypass of
   * expiry: the conscious re-affirmation it exists to elicit.
   */
  private async rerequest(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { actionId: string; actionType: string; rationale: string },
  ): Promise<void> {
    try {
      await this.client.rerequestAction(msg.actionId, msg.rationale);
      void vscode.window.showInformationMessage(`reckon: ${msg.actionType} re-requested — approve the new request`);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: re-request failed — ${errText(err)}`);
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
    /* =====================================================================
       design/ui/01-design-system.md, applied. Three tiers of tokens:
       1. chrome-adjacent — DERIVED from --vscode-* so the panel never fights
          the user's theme (backgrounds, text, dividers, inputs);
       2. reckon semantic — FIXED (analysts learn these as meaning): indigo
          primary, ok/warn/bad/info, the pin amber, trust tiers;
       3. entity palette — FIXED per type, used identically everywhere.
       Fills/hovers use color-mix over the theme foreground so density reads
       the same on any theme without hardcoding a navy ramp here.
       ===================================================================== */
    :root {
      /* type scale (01 §Typography) */
      --fs-xs: 11px; --fs-sm: 12px; --fs-base: 13px; --fs-md: 14px; --fs-lg: 16px;
      --sans: var(--vscode-font-family);
      --mono: var(--vscode-editor-font-family, monospace);
      /* spacing — 4px base; density target: terminal, not airy */
      --sp-1: 4px; --sp-2: 8px; --sp-3: 12px; --sp-4: 16px; --sp-5: 20px; --sp-6: 24px;
      /* radius */
      --r-xs: 3px; --r-sm: 5px; --r: 7px; --r-lg: 10px; --r-pill: 999px;
      /* motion */
      --dur-fast: .16s; --dur: .28s;
      --ease: cubic-bezier(.4, 0, .2, 1);
      --ease-out: cubic-bezier(.16, 1, .3, 1);
      /* brand */
      --he-primary: #7371fc; --he-primary-soft: #8b8aff; --he-primary-deep: #5d5be0;
      /* chrome-adjacent, theme-derived */
      --text: var(--vscode-foreground);
      --text-2: var(--vscode-descriptionForeground, color-mix(in srgb, var(--vscode-foreground) 62%, transparent));
      --text-3: color-mix(in srgb, var(--vscode-foreground) 40%, transparent);
      --border: var(--vscode-panel-border, color-mix(in srgb, var(--vscode-foreground) 9%, transparent));
      --fill: color-mix(in srgb, var(--vscode-foreground) 5%, transparent);
      --fill-2: color-mix(in srgb, var(--vscode-foreground) 8%, transparent);
      --hover: color-mix(in srgb, var(--vscode-foreground) 6%, transparent);
      --overlay-bg: var(--vscode-editorWidget-background, var(--vscode-editor-background));
      --shadow-pop: 0 12px 40px rgba(0,0,0,.55), 0 2px 8px rgba(0,0,0,.4);
      /* semantic (fixed; dark values) */
      --ok: #4ec77b;   --ok-bg: rgba(78,199,123,.13);   --ok-border: rgba(78,199,123,.32);
      --warn: #f5b53d; --warn-bg: rgba(245,181,61,.13); --warn-border: rgba(245,181,61,.34);
      --bad: #ff5f6e;  --bad-bg: rgba(255,95,110,.13);  --bad-border: rgba(255,95,110,.34);
      --info: #4aa8ff; --info-bg: rgba(74,168,255,.13); --info-border: rgba(74,168,255,.34);
      --pin: #f5b53d;
      /* entity palette (fixed per type; dark values) */
      --ent-host: #6fb6f2;    --ent-host-bg: rgba(111,182,242,.14);
      --ent-account: #c98fe0; --ent-account-bg: rgba(201,143,224,.15);
      --ent-ip: #45c9d6;      --ent-ip-bg: rgba(69,201,214,.14);
      --ent-hash: #f0b94c;    --ent-hash-bg: rgba(240,185,76,.14);
      --ent-domain: #6fd698;  --ent-domain-bg: rgba(111,214,152,.14);
      --ent-email: #a99bf5;   --ent-email-bg: rgba(169,155,245,.15);
      --ent-process: #b6c2cf; --ent-process-bg: rgba(182,194,207,.13);
      --ent-alert: #f59a6b;   --ent-alert-bg: rgba(245,154,107,.14);
    }
    body.vscode-light {
      --shadow-pop: 0 12px 40px rgba(0,0,0,.18), 0 2px 8px rgba(0,0,0,.10);
      --ok: #1f9d52;   --ok-bg: rgba(31,157,82,.10);    --ok-border: rgba(31,157,82,.32);
      --warn: #c8860b; --warn-bg: rgba(200,134,11,.10); --warn-border: rgba(200,134,11,.34);
      --bad: #e0394a;  --bad-bg: rgba(224,57,74,.10);   --bad-border: rgba(224,57,74,.34);
      --info: #1f7fe0; --info-bg: rgba(31,127,224,.10); --info-border: rgba(31,127,224,.34);
      --pin: #c8860b;
      --ent-host: #1f6fc4;    --ent-host-bg: rgba(31,111,196,.10);
      --ent-account: #9333b8; --ent-account-bg: rgba(147,51,184,.10);
      --ent-ip: #0e8a9c;      --ent-ip-bg: rgba(14,138,156,.10);
      --ent-hash: #b3790a;    --ent-hash-bg: rgba(179,121,10,.11);
      --ent-domain: #1c9b57;  --ent-domain-bg: rgba(28,155,87,.10);
      --ent-email: #6a5be0;   --ent-email-bg: rgba(106,91,224,.10);
      --ent-process: #5a6b7b; --ent-process-bg: rgba(90,107,123,.10);
      --ent-alert: #d2671f;   --ent-alert-bg: rgba(210,103,31,.10);
    }

    html, body { height: 100%; }
    body {
      font-family: var(--sans); font-size: var(--fs-base); line-height: 1.55;
      color: var(--text); margin: 0; display: flex; height: 100vh; overflow: hidden;
    }
    ::-webkit-scrollbar { width: 11px; height: 11px; }
    ::-webkit-scrollbar-thumb {
      background: color-mix(in srgb, var(--vscode-foreground) 13%, transparent);
      border: 3px solid transparent; background-clip: content-box; border-radius: var(--r-pill);
    }

    /* ---- two-region layout: conversation + state rail ---- */
    #main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
    #rail {
      flex: none; width: 272px; min-width: 200px;
      border-left: 1px solid var(--border);
      overflow-y: auto; padding: var(--sp-3) var(--sp-3) var(--sp-4);
      background: var(--vscode-sideBar-background, transparent);
    }
    @media (max-width: 640px) { #rail { display: none; } }

    header {
      padding: var(--sp-3) var(--sp-5) var(--sp-2);
      border-bottom: 1px solid var(--border); flex: none;
    }
    .titlerow { display: flex; align-items: baseline; gap: var(--sp-3); }
    header h1 {
      font-size: var(--fs-lg); font-weight: 600; margin: 0; flex: 1;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    /* status pill — tier/state pills are weight-800 micro-labels (01 §Scale) */
    .state {
      font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.06em;
      padding: 2px 9px; border-radius: var(--r-pill);
      background: var(--fill-2); color: var(--text-2); border: 1px solid var(--border);
      white-space: nowrap;
    }
    #state[data-engine="ACTIVE"] { color: var(--he-primary-soft); border-color: color-mix(in srgb, var(--he-primary) 45%, transparent); background: color-mix(in srgb, var(--he-primary) 16%, transparent); }
    #state[data-engine="CONCLUDED"] { color: var(--ok); border-color: var(--ok-border); background: var(--ok-bg); }
    #state[data-engine="ARCHIVED"] { opacity: 0.7; }
    #meta { font-size: var(--fs-xs); color: var(--text-3); margin-top: 2px; }
    #meta code { font-family: var(--mono); background: none; padding: 0; }

    button {
      font: inherit; font-size: var(--fs-sm); color: var(--text);
      background: var(--fill-2); border: 1px solid var(--border);
      padding: 3px 11px; border-radius: var(--r-sm); cursor: pointer;
      transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
    }
    button:hover { background: var(--fill); border-color: color-mix(in srgb, var(--vscode-foreground) 16%, transparent); }
    button:disabled { opacity: 0.45; cursor: default; }
    button.primary, .decide .primary, .pincta {
      color: #fff; background: var(--he-primary); border-color: transparent; font-weight: 600;
    }
    button.primary:hover, .decide .primary:hover, .pincta:hover { background: var(--he-primary-deep); }

    #scroll { flex: 1; overflow-y: auto; padding: var(--sp-2) var(--sp-5) var(--sp-4); }
    #banner { color: var(--bad); margin: var(--sp-2) 0; }
    #banner:empty { display: none; }
    #conversation:empty::before {
      content: "Ask reckon to investigate — it reasons over the evidence, cites what it saw, and proposes actions for your approval.";
      display: block; color: var(--text-3); font-style: italic; margin: var(--sp-6) 0; max-width: 46ch;
    }

    /* ---- conversation ---- */
    .msg { margin: var(--sp-4) 0; max-width: 78ch; font-size: var(--fs-md); }
    .msg.user { display: flex; justify-content: flex-end; max-width: none; }
    .msg.user .bubble {
      max-width: 60ch; white-space: pre-wrap; font-size: var(--fs-base);
      background: var(--fill); border: 1px solid var(--border);
      border-radius: var(--r-lg); padding: 7px 13px;
    }
    .reasoning {
      font-style: italic; color: var(--text-2); font-size: var(--fs-sm); white-space: pre-wrap;
      border-left: 2px solid var(--border); padding-left: 10px; margin: var(--sp-1) 0;
    }
    /* streaming caret (01 §Motion): blinks at the end of the live segment */
    .md.live::after {
      content: "▍"; color: var(--he-primary-soft);
      animation: caret 1s steps(2) infinite;
    }
    @keyframes caret { 50% { opacity: 0; } }

    /* markdown-rendered assistant text */
    .md p { margin: 7px 0; }
    .md ul, .md ol { margin: 6px 0; padding-left: 22px; }
    .md li { margin: 2px 0; }
    .md .mdh { font-weight: 600; margin: 11px 0 5px; }
    .md code, code {
      font-family: var(--mono); font-size: 0.88em;
      background: var(--fill-2); padding: 0.5px 4px; border-radius: var(--r-xs);
    }
    .md pre.codeblock {
      font-family: var(--mono); font-size: var(--fs-sm); line-height: 1.45;
      background: var(--fill); border: 1px solid var(--border);
      border-radius: var(--r); padding: 9px 12px; margin: var(--sp-2) 0;
      overflow-x: auto; white-space: pre;
    }
    .md pre.codeblock code { background: none; padding: 0; }

    /* tool rows: one-line summary, args behind the disclosure — data is mono */
    details.tool {
      font-family: var(--mono); font-size: var(--fs-sm);
      border: 1px solid var(--border); border-radius: var(--r);
      margin: 6px 0; max-width: 78ch; background: var(--fill);
      transition: border-color var(--dur-fast) var(--ease);
    }
    details.tool:hover { border-color: color-mix(in srgb, var(--vscode-foreground) 16%, transparent); }
    details.tool summary {
      cursor: pointer; padding: 5px 10px; list-style: none;
      display: flex; align-items: baseline; gap: var(--sp-2); overflow: hidden;
      min-height: 24px; box-sizing: border-box;
    }
    details.tool summary::-webkit-details-marker { display: none; }
    .tool .mark { flex: none; }
    .tool .mark.ok { color: var(--ok); }
    .tool .mark.err { color: var(--bad); }
    .tool .verb { font-weight: 600; flex: none; }
    .tool .hint {
      color: var(--text-3); white-space: nowrap; overflow: hidden;
      text-overflow: ellipsis; flex: 1; min-width: 0;
    }
    .tool .status { flex: none; color: var(--text-2); }
    .tool pre {
      margin: 0; padding: 8px 10px 9px; border-top: 1px solid var(--border);
      overflow-x: auto; white-space: pre;
    }

    .committed, .usage { font-size: var(--fs-xs); color: var(--text-3); margin: 5px 0; }
    .stepmark { font-size: var(--fs-xs); color: var(--text-3); margin: var(--sp-2) 0 2px; letter-spacing: 0.08em; }
    .sopchip {
      display: inline-block; font-size: var(--fs-xs); padding: 0 7px;
      margin: 2px 3px 0 0; border: 1px solid var(--info-border);
      color: var(--info); background: var(--info-bg); border-radius: var(--r-pill);
    }
    .sopchip.consulted { border-style: dashed; opacity: 0.6; background: none; }
    .translink { cursor: pointer; text-decoration: underline; color: var(--text-2); font-size: var(--fs-xs); }
    .translink:hover { color: var(--text); }
    .error { color: var(--bad); margin: 6px 0; max-width: 78ch; }

    /* micro-label eyebrow (01 §Scale): 10px, 700, tracked, uppercase */
    #rail h2, .railfold > summary, #historyWrap > summary, .dlglabel, .residual .rtitle {
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--text-2);
    }

    /* ---- reasoning history (the thread, 13 §4) ---- */
    #historyWrap { margin: 10px 0 var(--sp-4); max-width: 78ch; }
    #historyWrap > summary { cursor: pointer; margin-bottom: 5px; }
    .step {
      border-left: 2px solid var(--border);
      padding: 2px 0 5px 12px; margin: 9px 0;
    }
    .step.ai { border-left-color: var(--he-primary); }
    .step .stephead {
      font-size: var(--fs-xs); color: var(--text-2);
      display: flex; align-items: baseline; gap: 9px; flex-wrap: wrap;
    }
    .step .stephead .who { font-weight: 600; }
    .step.ai .stephead .who { color: var(--he-primary-soft); }
    .step .stepbody { font-size: var(--fs-sm); margin-top: 2px; }
    .step .stepbody p { margin: 3px 0; }

    /* ---- rail ---- */
    #rail section { margin-bottom: var(--sp-4); }
    #rail h2 { margin: 0 0 7px; }
    .railfold { margin-bottom: var(--sp-4); }
    .railfold > summary { cursor: pointer; margin-bottom: 7px; }
    .card {
      background: var(--fill); border: 1px solid var(--border); border-radius: var(--r);
      padding: 9px 11px; margin: 6px 0; font-size: var(--fs-sm);
      transition: border-color var(--dur-fast) var(--ease);
    }
    .card:hover { border-color: color-mix(in srgb, var(--vscode-foreground) 16%, transparent); }
    .card .statement { font-weight: 600; font-size: var(--fs-base); }
    /* badge: neutral by default; semantic classes color it as meaning */
    .badge {
      font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.04em;
      padding: 1px 7px; border-radius: var(--r-pill); border: 1px solid var(--border);
      color: var(--text-2); margin-left: 6px; vertical-align: middle; white-space: nowrap;
    }
    .badge.ok   { color: var(--ok);   background: var(--ok-bg);   border-color: var(--ok-border); }
    .badge.warn { color: var(--warn); background: var(--warn-bg); border-color: var(--warn-border); }
    .badge.bad  { color: var(--bad);  background: var(--bad-bg);  border-color: var(--bad-border); }
    .badge.info { color: var(--info); background: var(--info-bg); border-color: var(--info-border); }
    /* trust tiers (ui/03 §3.1): T1 info · T2 warning/square · T3 danger/diamond */
    .badge.T1 { color: var(--info); background: var(--info-bg); border-color: var(--info-border); }
    .badge.T2 { color: var(--warn); background: var(--warn-bg); border-color: var(--warn-border); }
    .badge.T3 { color: var(--bad);  background: var(--bad-bg);  border-color: var(--bad-border); }
    .badge.T2::before, .badge.T3::before {
      content: ""; display: inline-block; width: 5px; height: 5px;
      background: currentColor; margin-right: 4px; vertical-align: 1px;
    }
    .badge.T3::before { transform: rotate(45deg); }
    .predictions { list-style: none; padding: 0; margin: 6px 0 0; }
    .predictions li {
      padding: 3px 0 3px 10px; border-left: 2px solid var(--border);
      margin: 4px 0; font-size: var(--fs-sm);
    }
    .testbtn { font-size: var(--fs-xs); padding: 0 8px; margin-left: 6px; }
    /* the suggested next move (02 §2.9): what would decide this, one click to stage */
    .nextmove {
      border: 1px dashed color-mix(in srgb, var(--he-primary) 45%, transparent);
      background: color-mix(in srgb, var(--he-primary) 8%, transparent);
      border-radius: var(--r); padding: 6px 10px; margin: 2px 0 8px;
      font-size: var(--fs-sm); cursor: pointer;
      transition: background var(--dur-fast) var(--ease);
    }
    .nextmove:hover { background: color-mix(in srgb, var(--he-primary) 14%, transparent); }
    .nextmove .nextlabel {
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--he-primary-soft);
    }
    .cardmeta { font-size: var(--fs-xs); color: var(--text-2); margin-top: 4px; word-break: break-word; }
    .decide { margin-top: 7px; display: flex; gap: 6px; flex-wrap: wrap; }
    .decide button { font-size: var(--fs-sm); padding: 3px 10px; }
    .empty { color: var(--text-3); font-style: italic; font-size: var(--fs-sm); }
    .caprow { display: flex; align-items: baseline; gap: 7px; font-size: var(--fs-sm); margin: 2px 0; min-height: 20px; }
    .dot { flex: none; width: 6px; height: 6px; border-radius: 50%; background: var(--ok); }
    .dot.degraded { background: var(--warn); }
    .dot.unavailable { background: var(--bad); opacity: 0.7; }
    .caprow .verb { font-family: var(--mono); }
    .caprow.unavailable .verb { opacity: 0.5; }
    body.loading #rail { opacity: 0.6; }

    /* ---- verdict + pins + citations ---- */
    .verdictbadge.BENIGN    { color: var(--ok);   background: var(--ok-bg);   border-color: var(--ok-border); }
    .verdictbadge.SUSPICIOUS{ color: var(--warn); background: var(--warn-bg); border-color: var(--warn-border); }
    .verdictbadge.MALICIOUS { color: var(--bad);  background: var(--bad-bg);  border-color: var(--bad-border); }

    /* entity chip (01 §Entity chip anatomy): mono, type-colored, leading swatch */
    .refchip {
      display: inline-flex; align-items: center; gap: 4px;
      font-family: var(--mono); font-size: 0.92em; font-weight: 600;
      padding: 1px 7px 1px 6px; margin: 2px 3px 2px 0;
      border-radius: var(--r-sm); line-height: 1.45; border: none;
      color: var(--ent-process); background: var(--ent-process-bg);
      cursor: pointer; max-width: 100%; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom;
      transition: filter var(--dur-fast) var(--ease);
    }
    .refchip::before {
      content: ""; flex: none; width: 6px; height: 6px;
      border-radius: 2px; background: currentColor;
    }
    .refchip:hover { filter: brightness(1.18); box-shadow: 0 0 0 1px currentColor inset; }
    .refchip.pinned { box-shadow: 0 0 0 1px var(--pin) inset; }
    .chip-host    { color: var(--ent-host);    background: var(--ent-host-bg); }
    .chip-account { color: var(--ent-account); background: var(--ent-account-bg); }
    .chip-ip      { color: var(--ent-ip);      background: var(--ent-ip-bg); }
    .chip-hash    { color: var(--ent-hash);    background: var(--ent-hash-bg); }
    .chip-domain  { color: var(--ent-domain);  background: var(--ent-domain-bg); }
    .chip-email   { color: var(--ent-email);   background: var(--ent-email-bg); }
    .chip-alert   { color: var(--ent-alert);   background: var(--ent-alert-bg); }
    .chip-brand   { color: var(--he-primary-soft); background: color-mix(in srgb, var(--he-primary) 15%, transparent); }

    .pinrow { border-left: 2px solid var(--pin); }
    .pinrow .finding { font-size: var(--fs-sm); }
    .pinrow.superseded { border-left-color: var(--border); }
    .pinrow.superseded .finding { text-decoration: line-through; color: var(--text-3); }
    .pinrow .unpin { float: right; font-size: var(--fs-xs); padding: 0 6px; }
    .countdown.warn { color: var(--warn); font-weight: 600; }
    .countdown.due { color: var(--bad); font-weight: 600; }
    .toolrefs { padding: 6px 10px 8px; border-top: 1px solid var(--border); font-family: var(--sans); }
    .toolactions { margin-top: 6px; }
    .pincta { font-size: var(--fs-sm); padding: 2px 10px; border-radius: var(--r-sm); }
    .stepPin { font-size: var(--fs-xs); padding: 1px 8px; margin-left: 6px; }
    /* The pin sits at the right end of the always-visible tool summary. */
    .summaryPin { flex: none; margin-left: auto; font-size: var(--fs-xs); padding: 0 8px; }
    details.tool[open] .summaryPin { opacity: 0.9; }

    /* ---- dialogs: overlay surface, pop shadow, dlgIn entrance ---- */
    #verdictDialog, #promptDialog {
      position: fixed; inset: 0; background: rgba(0,0,0,.45);
      display: flex; align-items: center; justify-content: center; z-index: 10;
    }
    #verdictDialog .dlg, #promptDialog .dlg {
      width: min(480px, 90vw); background: var(--overlay-bg);
      border: 1px solid var(--vscode-widget-border, var(--border));
      border-radius: var(--r-lg); padding: var(--sp-4) var(--sp-5) var(--sp-4);
      box-shadow: var(--shadow-pop);
      animation: dlgIn 0.2s var(--ease-out);
    }
    @keyframes dlgIn {
      from { opacity: 0; transform: translateY(6px) scale(.97); }
      to   { opacity: 1; transform: none; }
    }
    #verdictDialog h3, #promptDialog h3 { margin: 0 0 10px; font-size: var(--fs-lg); }
    #promptInput, #verdictRationale {
      width: 100%; box-sizing: border-box; font: inherit; resize: vertical;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--border));
      border-radius: var(--r-sm); padding: 7px 9px;
    }
    #promptInput:focus, #verdictRationale:focus, #composer textarea:focus {
      outline: none; border-color: var(--he-primary);
    }
    #promptLabel:empty, #promptHelper:empty, #promptRefs:empty { display: none; }
    .pinrefs { margin: var(--sp-2) 0 5px; }
    .pinhelp { font-size: var(--fs-sm); color: var(--text-2); margin: 5px 0 2px; }
    .checklist { margin: 5px 0 10px; font-size: var(--fs-sm); }
    .checklist .item { margin: 3px 0; }
    .checklist .ok { color: var(--ok); }
    .checklist .unmet { color: var(--warn); }
    .dlglabel { margin: 9px 0 4px; }
    .dispositions label { margin-right: var(--sp-4); font-size: var(--fs-base); cursor: pointer; }
    .residual {
      font-size: var(--fs-sm); color: var(--text-2); margin-top: 9px;
      border-left: 2px solid var(--warn-border); padding-left: 10px;
    }
    .residual .rtitle { margin-bottom: 3px; }

    /* ---- composer ---- */
    #composer {
      flex: none; display: flex; gap: var(--sp-2); padding: 10px var(--sp-5);
      border-top: 1px solid var(--border);
    }
    #composer textarea {
      flex: 1; resize: none; font: inherit; color: var(--vscode-input-foreground);
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--border));
      border-radius: var(--r-sm); padding: 7px 10px; min-height: 2.4rem; max-height: 8rem;
      transition: border-color var(--dur-fast) var(--ease);
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
        <span id="lifecycleBtns"></span>
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

  <!-- One reusable prompt card for every text-input action (pin, un-pin,
       reject, T3 challenge): an in-context modal over the document, never the
       top-of-window quick input. -->
  <div id="promptDialog" style="display:none">
    <div class="dlg">
      <h3 id="promptTitle"></h3>
      <div id="promptLabel" class="dlglabel"></div>
      <textarea id="promptInput" rows="3"></textarea>
      <div id="promptRefs" class="pinrefs"></div>
      <div id="promptHelper" class="pinhelp"></div>
      <div class="decide">
        <button class="primary" id="promptConfirm"></button>
        <button id="promptCancel">Cancel</button>
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
    // Entity-type palette classes (ui/01 §Entity-type palette): one fixed
    // color per type, everywhere. Unmapped types fall to the neutral gray.
    const REF_CHIP_CLASS = {
      "x-host": "chip-host", "ipv4-addr": "chip-ip", "ipv6-addr": "chip-ip",
      "user-account": "chip-account", "file": "chip-hash",
      "domain-name": "chip-domain", "url": "chip-domain", "email-addr": "chip-email",
      "indicator": "chip-alert", "sighting": "chip-alert",
      "x-hypothesis": "chip-brand", "x-prediction": "chip-brand",
    };
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
      const t = ref.includes("--") ? ref.slice(0, ref.indexOf("--")) : "";
      const c = document.createElement("span");
      c.className = "refchip" + (REF_CHIP_CLASS[t] ? " " + REF_CHIP_CLASS[t] : "");
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
      // The engine speaks lowercase ("active"); the header vocabulary is
      // uppercase. Normalize once here — every comparison below assumes it.
      if (status) $("state").dataset.engine = String(status).toUpperCase();
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
      renderLifecycleControls(engine);
    }

    // The lifecycle state machine's affordances (01 §Extension 2), contextual
    // to the engine status — every legal move visible as a button, never a
    // menu. Conclude is gated in the aggregate on a verdict of record; the
    // button says so up front rather than offering a click that can only 422.
    function renderLifecycleControls(engine) {
      const box = $("lifecycleBtns");
      box.textContent = "";
      const mk = (text, title, onClick, disabledReason) => {
        const b = document.createElement("button");
        b.textContent = text;
        b.title = disabledReason || title;
        b.disabled = !!disabledReason;
        if (!disabledReason) b.addEventListener("click", onClick);
        box.appendChild(b);
      };
      const send = (transition, reason) =>
        vscode.postMessage({ type: "lifecycle", transition, reason });
      switch (engine) {
        case "DRAFT":
          mk("Activate", "Move to ACTIVE — clears the investigation to request external actions", () => send("activate"));
          break;
        case "ACTIVE":
          mk("Pause", "A reversible hold — resume any time", () => send("pause"));
          mk("Conclude…", "Close with the verdict of record and a summary",
            () => openPrompt({
              title: "Conclude investigation",
              label: "Summary of record — what did this investigation determine?",
              placeholder: "e.g. Confirmed C2 beaconing from WIN-9; host isolated, IOCs blocked.",
              helper: "Concluding consumes the verdict of record (" + (lastVerdict ? lastVerdict.disposition : "none") + ") and files the final report reference. You can reopen later if the world disagrees.",
              confirm: "Conclude",
              onConfirm: (summary) => vscode.postMessage({ type: "lifecycle", transition: "conclude", summary }),
            }),
            lastVerdict ? "" : "Record a verdict first — a conclusion consumes the verdict of record");
          break;
        case "PAUSED":
          mk("Resume", "Back to ACTIVE", () => send("resume"));
          break;
        case "CONCLUDED":
          mk("Reopen…", "Back to ACTIVE — the prior conclusion stays on the record",
            () => openPrompt({
              title: "Reopen investigation",
              label: "Why does this need to be reopened?",
              placeholder: "e.g. New alert on the same host — the conclusion may not hold",
              helper: "Reopening clears the conclusion slot; the prior report stays referenced from the thread.",
              confirm: "Reopen",
              onConfirm: (reason) => vscode.postMessage({ type: "lifecycle", transition: "reopen", reason }),
            }));
          mk("Archive…", "Terminal — accepts no further changes",
            () => openPrompt({
              title: "Archive investigation",
              label: "Archiving is TERMINAL — the record accepts no further changes, ever. Note why (optional):",
              placeholder: "e.g. Retention review complete",
              helper: "Unlike pause or conclude, there is no way back from archived.",
              confirm: "Archive permanently",
              require: false,
              onConfirm: (reason) => vscode.postMessage({ type: "lifecycle", transition: "archive", reason }),
            }));
          break;
      }
      // Terminal / closed states park the interactive surfaces honestly:
      // archived accepts nothing; concluded pauses the conversation until a
      // reopen (the engine would refuse the commit anyway — no affordance
      // that can only fail).
      const closed = engine === "ARCHIVED" || engine === "CONCLUDED";
      conversationClosed = closed;
      input.disabled = closed;
      sendBtn.disabled = closed;
      input.placeholder = engine === "ARCHIVED" ? "Archived — this record is final."
        : engine === "CONCLUDED" ? "Concluded — reopen to continue the conversation."
        : "Ask reckon to investigate… (Enter to send, Shift+Enter for newline)";
      $("verdictBtn").style.display = closed ? "none" : "";
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
    // The live segment carries the streaming caret; closeSeg retires it.
    function closeSeg() {
      if (turn && turn.seg) { turn.seg.classList.remove("live"); turn.seg = null; }
    }
    function appendText(delta) {
      if (!turn) return;
      if (!turn.seg) {
        turn.seg = document.createElement("div");
        turn.seg.className = "md live";
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
      if (turn) { closeSeg(); turn.tools.push(row); }
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
    // badgeClass maps a status word to its semantic tone — confirmed things
    // read green, refuted red, everything undecided stays neutral.
    const BADGE_TONE = {
      CONFIRMED: "ok", SUPPORTED: "ok", TESTED: "ok", SUCCEEDED: "ok",
      REFUTED: "bad", FAILED: "bad", EXPIRED: "warn",
    };
    function badgeClass(status) {
      const tone = BADGE_TONE[String(status || "").toUpperCase()];
      return "badge" + (tone ? " " + tone : "");
    }
    // Stage a question into the composer — the pivot pattern (02 §2.9): staged,
    // never auto-fired. The analyst reads, edits, and sends.
    function stageInComposer(text) {
      if (conversationClosed || input.disabled) return;
      input.value = text;
      input.focus();
      input.setSelectionRange(text.length, text.length);
    }
    function predictionTestText(p) {
      const q = p.testQuery || {};
      if (q.queryText) {
        return "Test this prediction" + (q.tool ? " via " + q.tool : "") + ": " + q.queryText;
      }
      return "Test the prediction: " + p.statement;
    }

    // The hypothesis tracker — the drivable loop (02 §2.9). Hypotheses are the
    // unit of work: PROPOSED cards carry Acknowledge (a human act the engine
    // enforces), UNTESTED predictions carry "Test this" (stages the declared
    // test), and the cheapest untested prediction is surfaced as the suggested
    // next move — "what would decide this?" answered at a glance.
    function renderHypotheses(hs) {
      const box = $("hyps");
      box.textContent = "";
      if (!hs || !hs.length) {
        box.innerHTML = '<div class="empty">None yet</div>';
        return;
      }

      // The suggested next move: the first UNTESTED prediction under a live
      // (PROPOSED/OPEN) hypothesis — earliest first, matching reading order.
      let suggested = null;
      for (const h of hs) {
        if (h.status !== "PROPOSED" && h.status !== "OPEN") continue;
        for (const p of h.predictions || []) {
          if (p.status === "UNTESTED") { suggested = p; break; }
        }
        if (suggested) break;
      }
      if (suggested) {
        const s = document.createElement("div");
        s.className = "nextmove";
        const label = document.createElement("span");
        label.className = "nextlabel";
        label.textContent = "next: ";
        const text = document.createElement("span");
        text.className = "nexttext";
        text.textContent = suggested.statement;
        s.append(label, text);
        s.title = "Stage this test in the composer (you send it)";
        s.addEventListener("click", () => stageInComposer(predictionTestText(suggested)));
        box.appendChild(s);
      }

      for (const h of hs) {
        const card = document.createElement("div");
        card.className = "card";
        const head = document.createElement("div");
        const st = document.createElement("span");
        st.className = "statement";
        st.textContent = h.statement;
        const badge = document.createElement("span");
        badge.className = badgeClass(h.status);
        badge.textContent = h.status;
        head.append(st, badge);
        card.appendChild(head);

        if (h.status === "PROPOSED") {
          const own = document.createElement("div");
          own.className = "decide";
          const ack = document.createElement("button");
          ack.textContent = "Acknowledge";
          ack.title = "Take ownership of this AI-proposed line of inquiry (PROPOSED → OPEN). A human act — the engine refuses it from the AI.";
          ack.addEventListener("click", () => {
            ack.disabled = true;
            vscode.postMessage({ type: "hyp.ack", hypothesisRef: h.id });
          });
          own.appendChild(ack);
          card.appendChild(own);
        }

        const preds = h.predictions || [];
        if (preds.length) {
          const ul = document.createElement("ul");
          ul.className = "predictions";
          for (const p of preds) {
            const li = document.createElement("li");
            const ptext = document.createElement("span");
            ptext.textContent = p.statement;
            const pbadge = document.createElement("span");
            pbadge.className = badgeClass(p.status);
            pbadge.textContent = p.status;
            li.append(ptext, pbadge);
            if (p.status === "UNTESTED") {
              const test = document.createElement("button");
              test.className = "testbtn";
              test.textContent = "Test this";
              test.title = p.testQuery && p.testQuery.queryText
                ? "Stage the declared test in the composer: " + p.testQuery.queryText
                : "Stage a test of this prediction in the composer";
              test.addEventListener("click", () => stageInComposer(predictionTestText(p)));
              li.appendChild(test);
            }
            // The decisive outcomes cite what was observed — every test-result
            // ref opens (02 §2.8).
            for (const r of p.testResultRefs || []) li.appendChild(refChip(r));
            ul.appendChild(li);
          }
          card.appendChild(ul);
        }
        box.appendChild(card);
      }
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
          un.addEventListener("click", () => openPrompt({
            title: "Remove from evidence",
            label: "Why remove this?",
            placeholder: "e.g. re-scoped — this logon was expected activity",
            helper: "The pin stays visible on the thread, struck — nothing is deleted.",
            confirm: "Remove",
            onConfirm: (reason) => vscode.postMessage({ type: "pin.unpin", interpretationId: p.interpretationId, reason }),
          }));
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
        for (const r of p.inputRefs || []) {
          const ch = refChip(r);
          if (!p.superseded) ch.classList.add("pinned"); // amber inset (ui/01 anatomy)
          refs.appendChild(ch);
        }
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
      // The queue: live pending rows, plus EXPIRED ones (they carry the
      // re-request affordance) — but not an EXPIRED action that already has a
      // successor (retry_of pointing at it): its re-request happened, and a
      // dangling button would mint duplicates.
      const retried = new Set(lastPending.map((a) => a.retryOf).filter(Boolean));
      const pend = lastPending.filter((a) =>
        a.pending || (a.status === "EXPIRED" && !retried.has(a.actionId)));
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
        tier.className = "badge " + a.tier;
        tier.textContent = a.tier;
        const state = document.createElement("span");
        state.className = "badge" + (a.expired ? " warn" : "");
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
          // The approval deadline passed — the engine refuses an APPROVE (no
          // affordance that can only fail). But the analyst can RE-REQUEST: a
          // new action, fresh window, retry_of lineage — a conscious
          // re-affirmation, not a bypass.
          row.style.opacity = "0.7";
          const note = document.createElement("div");
          note.className = "cardmeta";
          note.textContent = "approval window elapsed — the world may have moved on";
          row.append(note);
          const decide = document.createElement("div");
          decide.className = "decide";
          const again = document.createElement("button");
          again.className = "primary";
          again.textContent = "↻ Re-request";
          again.title = "Create a fresh request (same targets + evidence, new approval window)";
          again.addEventListener("click", () => openPrompt({
            title: "Re-request " + a.actionType,
            label: "Why is this still warranted?",
            placeholder: "e.g. WIN-9 still shows the beaconing — containment still needed",
            helper: "Creates a NEW action (same targets & evidence, fresh approval window) you then approve. The original stays expired, linked as lineage.",
            confirm: "↻ Re-request",
            onConfirm: (rationale) => vscode.postMessage({ type: "action.rerequest", actionId: a.actionId, actionType: a.actionType, rationale }),
          }));
          decide.append(again);
          row.append(decide);
        } else {
          const decide = document.createElement("div");
          decide.className = "decide";
          const ok = document.createElement("button");
          ok.className = "primary";
          ok.textContent = a.tier === "T3" ? "Approve (challenge)…" : "Approve";
          ok.addEventListener("click", () => {
            if (a.tier === "T3") {
              // T3 (04 §5.5): the typed challenge, in the prompt card.
              openPrompt({
                title: "Approve " + a.actionType + " — Tier 3",
                label: "Type the challenge to confirm",
                helper: "High blast radius (" + (a.targets || []).length + " targets). This action is "
                  + (a.reversibility === "REVERSIBLE" ? "reversible." : a.reversibility === "BEST_EFFORT"
                    ? "best-effort reversal — treat as permanent." : "irreversible."),
                confirm: "Approve",
                onConfirm: (challenge) => vscode.postMessage({
                  type: "action.approve", actionId: a.actionId, tier: a.tier, actionType: a.actionType, challenge,
                }),
              });
            } else {
              setDecideEnabled(false);
              vscode.postMessage({ type: "action.approve", actionId: a.actionId, tier: a.tier, actionType: a.actionType });
            }
          });
          const no = document.createElement("button");
          no.textContent = "Reject…";
          no.addEventListener("click", () => openPrompt({
            title: "Reject " + a.actionType,
            label: "Why is this rejected?",
            placeholder: "recorded on the audit trail",
            confirm: "Reject",
            require: false,
            onConfirm: (reason) => vscode.postMessage({
              type: "action.reject", actionId: a.actionId, actionType: a.actionType, reason,
            }),
          }));
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

    // conversationClosed: the lifecycle parked the composer (CONCLUDED /
    // ARCHIVED) — a turn ending must not re-open it.
    let conversationClosed = false;
    function setComposerEnabled(on) {
      if (on && conversationClosed) return;
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

    // ---- the reusable prompt card ------------------------------------------
    // One in-context modal for every text-input action — never a top-of-window
    // quick input. opts: { title, label, placeholder, helper, confirm, refs,
    // require (default true), onConfirm(value) }.
    let promptOnConfirm = null;
    let promptRequire = true;
    function openPrompt(opts) {
      promptOnConfirm = opts.onConfirm;
      promptRequire = opts.require !== false;
      $("promptTitle").textContent = opts.title || "";
      $("promptLabel").textContent = opts.label || "";
      $("promptHelper").textContent = opts.helper || "";
      const input = $("promptInput");
      input.value = "";
      input.placeholder = opts.placeholder || "";
      const box = $("promptRefs");
      box.textContent = "";
      for (const r of (opts.refs || []).slice(0, 12)) box.appendChild(refChip(r));
      if ((opts.refs || []).length > 12) {
        const more = document.createElement("span");
        more.className = "cardmeta";
        more.textContent = "+" + (opts.refs.length - 12) + " more";
        box.appendChild(more);
      }
      const confirm = $("promptConfirm");
      confirm.textContent = opts.confirm || "Confirm";
      confirm.disabled = promptRequire;
      $("promptDialog").style.display = "flex";
      input.focus();
    }
    function closePrompt() { $("promptDialog").style.display = "none"; promptOnConfirm = null; }
    function submitPrompt() {
      const v = $("promptInput").value.trim();
      if (promptRequire && !v) return;
      const cb = promptOnConfirm;
      closePrompt();
      if (cb) cb(v);
    }
    $("promptInput").addEventListener("input", () => {
      if (promptRequire) $("promptConfirm").disabled = $("promptInput").value.trim() === "";
    });
    $("promptInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submitPrompt();
      else if (e.key === "Escape") closePrompt();
    });
    $("promptCancel").addEventListener("click", closePrompt);
    $("promptConfirm").addEventListener("click", submitPrompt);

    // Pin evidence: the finding note + cited refs, in the prompt card.
    function openPinDialog(refs) {
      openPrompt({
        title: "Pin as evidence",
        label: "What does this evidence show?",
        placeholder: "e.g. First external egress from the svc_backup source host, 15s after the encoded PowerShell",
        helper: "Recorded on the investigation thread and cited by your verdict.",
        confirm: "📌 Pin evidence",
        refs: refs || [],
        onConfirm: (finding) => vscode.postMessage({ type: "pin.add", refs: refs || [], finding }),
      });
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
            closeSeg();
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
          closeSeg();
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
