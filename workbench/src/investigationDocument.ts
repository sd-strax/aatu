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
import { ActionRow, Appearance, BackendClient, Capability, CommsThread, Enablement, EvidenceDoc, Hypothesis, InvestigationDetail, PinRow, ThreadEntry } from "./backend";
import { AgentTransport } from "./agentTransport";

/** What the extension host posts to the webview to render. */
type RenderMessage =
  | { type: "loading" }
  // The unseeded state (design/ui/02 §2.7): render the "root this investigation"
  // surface instead of a document. "seeded" flips back once the seed persists;
  // "draft.error" reports a failed create without leaving the draft.
  | { type: "draft"; mode?: "case" }
  | { type: "seeded" }
  | { type: "draft.error"; message: string }
  // The "from a case" seed surface (13 §3 — operational input lives on the
  // panel, never the top-of-window quick input): the SoR search results, and a
  // search failure rendered inline in the case sub-form.
  | { type: "draft.cases"; cases: { number: string; title: string; status: string }[] }
  | { type: "draft.caseError"; message: string }
  // capabilities is null when the capability layer is off/unreachable — the
  // rail renders that honestly instead of an empty list. thread is the
  // chronological reasoning history (13 §4); null when its fetch failed.
  | { type: "data"; investigation: InvestigationDetail; hypotheses: Hypothesis[]; capabilities: Capability[] | null; thread: ThreadEntry[] | null }
  // The enablement surface (11 §5.1): gap hints + the schema the form renders
  // from. Null when the layer is off or the fetch failed — hints just absent.
  | { type: "enablement"; data: Enablement | null }
  | { type: "error"; message: string }
  // Open the in-document rename card (never the top-of-window quick input) —
  // sent when rename is invoked from the tree, so the modal lives on the
  // document surface like every other text action.
  | { type: "rename.begin"; title: string }
  // Applied rename: update the title in place without a full reload.
  | { type: "renamed"; title: string }
  | { type: "pending"; actions: ActionRow[] }
  | { type: "pins"; pins: PinRow[] }
  // The comms/external-work threads (Phase F, binding §4).
  | { type: "comms"; threads: CommsThread[] }
  // The committed chronicle (design/ui/00 §7): the full thread in sequence
  // order — every reasoning turn AND every act (approval, dispatch, result,
  // pin, verdict, lifecycle). The webview interleaves transcript-bearing turns
  // (reconstructed from the line-framed bodies) with compact act lines.
  | { type: "chronicle"; thread: ThreadEntry[]; turns: { sequenceNo: number; occurredAt: string; body: string }[] }
  // A resolved human label for an evidence ref (e.g. "host · WIN-FILE01"),
  // so the chips read as evidence instead of opaque STIX ids.
  | { type: "evidence.label"; ref: string; label: string }
  // The event-time strip (13 §4 Timeline, minimal at v0): the cited telemetry
  // ordered by EVENT time — when it happened, not when we learned it (the two
  // clocks, binding §7). Each item opens its record.
  | { type: "events.strip"; items: { ref: string; time: string; label: string }[] }
  // The minimal evidence graph (13 §7 step 7): the two-layer structure
  // rendered navigably — interpretation-layer objects (STIX: reasoning nodes
  // and SCOs) on the left, raw telemetry (OCSF) on the right. Acts are not
  // nodes (the chronicle owns them); they collapse into grounding edges from a
  // produced object to the evidence it cites. Edges are actual citations plus
  // observed-data joins (`join`); nothing is inferred.
  | {
      type: "graph";
      refs: { id: string; kind: string; type: string }[];
      edges: { from: string; to: string; ai: boolean; join?: boolean }[];
    }
  // The entity popover's cross-investigation memory (ui/02 §2.4): other
  // investigations citing this ref, current one excluded.
  | { type: "entity.info"; ref: string; appearances: Appearance[] }
  | { type: "turn.start" }
  | { type: "turn.user"; text: string }
  // An aside (the "btw" lens): a scoped agent turn rendered as a collapsed
  // one-liner in the conversation. Same thread of record — different lens.
  | { type: "aside.start"; label: string }
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
  // The seed surface (design/ui/02 §2.7): the analyst's confirmed root. kind is
  // "entity" | "question" (the correction toggle); the alert variant carries an
  // explicit id + source from the "From an alert…" affordance.
  | { type: "seed.submit"; value: string; kind: string }
  | { type: "seed.alert"; alertId: string; source: string }
  // The "from a case" path (13 §3): search the case system of record, then seed
  // from a picked case — both driven from the draft surface, no quick input.
  | { type: "seed.caseSearch"; filter: string }
  | { type: "seed.case"; caseNumber: string }
  | { type: "send"; text: string }
  | { type: "action.approve"; actionId: string; tier: string; actionType: string; challenge?: string }
  | { type: "action.reject"; actionId: string; actionType: string; reason: string }
  | { type: "action.rerequest"; actionId: string; actionType: string; rationale: string }
  | { type: "pin.add"; refs: string[]; finding: string }
  | { type: "pin.unpin"; interpretationId: string; reason: string }
  | { type: "verdict.submit"; disposition: string; rationale: string; refs: string[] }
  | { type: "hyp.ack"; hypothesisRef: string }
  | { type: "hyp.new"; statement: string }
  | { type: "hyp.proposeTests"; hypothesisRef: string; statement: string }
  | { type: "hyp.runTests"; hypothesisRef: string; statement: string }
  | { type: "hyp.decide"; hypothesisRef: string; statement: string }
  | { type: "enablement.apply"; adapter: string; enabled: boolean; config: Record<string, string>; secretFields: string[] }
  | { type: "comms.act"; threadId: string; verb: "ack" | "done" }
  | { type: "comms.snooze"; threadId: string; hours: number }
  | { type: "comms.followup"; threadId: string; actionType: string; target: string; subject: string; message: string; followUpHours: number }
  | { type: "lifecycle"; transition: string; reason?: string; summary?: string }
  | { type: "evidence.open"; ref: string }
  | { type: "evidence.resolve"; ref: string }
  | { type: "entity.info"; ref: string }
  | { type: "export.open" }
  | { type: "copy"; text: string }
  | { type: "investigation.open"; id: string; title?: string }
  | { type: "rename"; title: string }
  | { type: "transcript.open"; interpretationId: string };

export class InvestigationDocuments {
  private readonly open = new Map<string, vscode.WebviewPanel>();
  // Per-investigation refresh timers for in-flight dispatches (APPROVED/
  // EXECUTING → poll until terminal; see scheduleDispatchWatch).
  private readonly dispatchWatch = new Map<string, { timer: ReturnType<typeof setTimeout>; ticks: number }>();
  // Monotonic key for not-yet-seeded draft panels (design/ui/02 §2.7): a draft
  // has no investigation id until its seed is typed, so it lives under a
  // synthetic key until seedDraft re-keys it to the real aggregate id.
  private draftSeq = 0;
  // Draft keys with a create in flight (the host half of the double-submit guard).
  private readonly seeding = new Set<string>();
  // A draft opened in "from a case" mode (via reckon.seedFromCase) — consumed in
  // the ready handshake so the panel opens with the case search already expanded.
  private readonly draftMode = new Map<string, "case">();
  // Investigations whose rename card should pop once their panel goes live
  // (set by beginRename from the tree; consumed in the ready handshake).
  private readonly pendingRename = new Map<string, string>();
  // Resolved evidence-ref labels, shared across panels — deterministic ids
  // mean a ref resolves to the same thing everywhere, so cache once.
  private readonly labelCache = new Map<string, string>();
  // Full evidence docs, cached for the same reason (null = unfetchable). Feeds
  // both label resolution and the event-time strip without duplicate fetches.
  private readonly docCache = new Map<string, EvidenceDoc | null>();
  // Committed turn transcripts, keyed by interpretation id — immutable once
  // committed, so the chronicle re-renders (after every act) reuse them instead
  // of re-fetching. Shared across panels (content-addressed).
  private readonly transcriptCache = new Map<string, string>();

  constructor(
    private readonly client: BackendClient,
    private readonly log: vscode.LogOutputChannel,
    private readonly transport: AgentTransport,
    /**
     * Called after each successful load with the last event sequence the
     * analyst has now seen — feeds the tree's unseen-changes cue (02 §2.12).
     * Last-seen is view state, never investigation state.
     */
    private readonly onLoaded?: (id: string, lastEventSequence: number) => void,
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
    const ref = { id };
    panel.webview.html = this.html(panel.webview);
    panel.webview.onDidReceiveMessage((msg: InboundMessage) => this.route(ref, panel, msg));
    panel.onDidDispose(() => this.open.delete(ref.id));
  }

  /**
   * Open a not-yet-seeded investigation (design/ui/02 §2.7): the same document,
   * rendered in its unseeded state, where the analyst roots the investigation by
   * typing a host/IP/hash or a question into the composer. Nothing is persisted
   * until that first act — which keeps "an investigation always begins from
   * something concrete" honest without a wizard.
   */
  showDraft(mode?: "case"): void {
    const key = `__draft__${++this.draftSeq}`;
    if (mode) {
      this.draftMode.set(key, mode);
    }
    const panel = vscode.window.createWebviewPanel(
      "reckon.investigation",
      "New investigation",
      vscode.ViewColumn.Active,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    this.open.set(key, panel);
    const ref = { id: key };
    panel.webview.html = this.html(panel.webview);
    // The webview asks for its initial state via "ready"; a draft key answers
    // with the unseeded render instead of a load().
    panel.webview.onDidReceiveMessage((msg: InboundMessage) => this.route(ref, panel, msg));
    panel.onDidDispose(() => this.open.delete(ref.id));
  }

  private static isDraft(key: string): boolean {
    return key.startsWith("__draft__");
  }

  /**
   * Rename an investigation on its own document surface: reveal the panel and
   * pop the in-document rename card (never the top-of-window quick input). Used
   * by the tree's context menu; the document header's pencil opens the card
   * directly in the webview. An already-open panel gets the card now; a freshly
   * opened one gets it after the webview's ready handshake.
   */
  beginRename(id: string, titleHint?: string): void {
    const existing = this.open.get(id);
    this.show(id, titleHint);
    if (existing) {
      void this.post(existing, { type: "rename.begin", title: titleHint ?? "" });
    } else {
      this.pendingRename.set(id, titleHint ?? "");
    }
  }

  /**
   * Re-load an investigation's panel from the backend if it is open — used
   * after an out-of-panel act that changed the thread (e.g. a context reset
   * from the tree), so the chronicle shows the committed marker immediately
   * instead of on the next manual refresh.
   */
  refreshOpen(id: string): void {
    const panel = this.open.get(id);
    if (panel) {
      void this.load(id, panel);
    }
  }

  /** Apply a confirmed rename, then update the tab + webview title in place. */
  private async applyRename(id: string, panel: vscode.WebviewPanel, title: string): Promise<void> {
    const trimmed = title.trim();
    if (!trimmed) {
      return;
    }
    try {
      const applied = await this.client.renameInvestigation(id, trimmed);
      panel.title = `⚖ ${applied}`;
      void this.post(panel, { type: "renamed", title: applied });
      // Full reload: the rename appended an event, so the seq meta line and
      // the SeenTracker (via onLoaded) must advance — otherwise the analyst's
      // own rename shows up in the tree as an unseen "● new" change.
      await this.load(id, panel);
      void vscode.commands.executeCommand("reckon.refreshInvestigations");
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: rename failed — ${errText(err)}`);
    }
  }

  /** Route one webview message using the panel's current (mutable) id. */
  private route(ref: { id: string }, panel: vscode.WebviewPanel, msg: InboundMessage): void {
    const id = ref.id;
    if (msg.type === "ready" || msg.type === "refresh") {
      if (InvestigationDocuments.isDraft(id)) {
        const mode = this.draftMode.get(id);
        this.draftMode.delete(id);
        void this.post(panel, { type: "draft", mode });
      } else {
        // A rename invoked from the tree opened this panel; start the in-place
        // edit only AFTER the load has posted its data (so the title field is
        // populated), preserving message order to the webview.
        const pending = this.pendingRename.get(id);
        this.pendingRename.delete(id);
        void this.load(id, panel).then(() => {
          if (pending !== undefined) {
            void this.post(panel, { type: "rename.begin", title: pending });
          }
        });
      }
    } else if (msg.type === "seed.submit") {
      void this.seedDraft(ref, panel, { value: msg.value, kind: msg.kind });
    } else if (msg.type === "seed.alert") {
      void this.seedDraft(ref, panel, { alertId: msg.alertId, source: msg.source });
    } else if (msg.type === "seed.caseSearch") {
      void this.searchCases(panel, msg.filter);
    } else if (msg.type === "seed.case") {
      void this.seedDraft(ref, panel, { value: msg.caseNumber, kind: "case" });
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
    } else if (msg.type === "hyp.new") {
      void this.newHypothesis(id, panel, msg.statement);
    } else if (msg.type === "hyp.proposeTests") {
      void this.proposeTests(id, panel, msg.hypothesisRef, msg.statement);
    } else if (msg.type === "hyp.runTests") {
      void this.runTests(id, panel, msg.hypothesisRef, msg.statement);
    } else if (msg.type === "hyp.decide") {
      void this.decideHypothesis(id, panel, msg.hypothesisRef, msg.statement);
    } else if (msg.type === "enablement.apply") {
      void this.applyEnablement(id, panel, msg);
    } else if (msg.type === "comms.act") {
      void this.commsAct(id, panel, msg.threadId, msg.verb);
    } else if (msg.type === "comms.snooze") {
      void this.commsSnooze(id, panel, msg.threadId, msg.hours);
    } else if (msg.type === "comms.followup") {
      void this.commsFollowUp(id, panel, msg);
    } else if (msg.type === "lifecycle") {
      void this.lifecycleTransition(id, panel, msg);
    } else if (msg.type === "evidence.open") {
      // The current investigation id rides along so the evidence card's
      // cross-investigation memory can exclude it ("also seen in" = OTHERS).
      void vscode.commands.executeCommand("reckon.openEvidence", msg.ref, id);
    } else if (msg.type === "evidence.resolve") {
      void this.resolveLabel(panel, msg.ref);
    } else if (msg.type === "entity.info") {
      void this.entityInfo(id, panel, msg.ref);
    } else if (msg.type === "export.open") {
      void this.openMarkdownExport(id);
    } else if (msg.type === "copy") {
      void vscode.env.clipboard.writeText(msg.text);
    } else if (msg.type === "investigation.open") {
      void vscode.commands.executeCommand("reckon.openInvestigation", msg.id, msg.title);
    } else if (msg.type === "rename") {
      // The in-document rename card confirmed. Drafts have no aggregate id yet
      // (the pencil is hidden there), but guard so a synthetic __draft__ key
      // never reaches the backend.
      if (!InvestigationDocuments.isDraft(id)) {
        void this.applyRename(id, panel, msg.title);
      }
    } else if (msg.type === "transcript.open") {
      void this.openTranscript(msg.interpretationId);
    }
  }

  /**
   * Persist a draft's seed and become the live investigation. On success the
   * panel is re-keyed from its synthetic draft key to the real aggregate id and
   * loaded in place — the surface never closes, it transforms.
   */
  private async seedDraft(
    ref: { id: string },
    panel: vscode.WebviewPanel,
    seed: { value?: string; kind?: string; alertId?: string; source?: string },
  ): Promise<void> {
    // Second line of the double-submit defense (the webview also guards): once
    // this draft key has a create in flight, or has already been re-keyed to a
    // real id, further seed messages are dropped — never a duplicate POST.
    if (!InvestigationDocuments.isDraft(ref.id) || this.seeding.has(ref.id)) {
      return;
    }
    this.seeding.add(ref.id);
    const draftKey = ref.id;
    try {
      const created = seed.alertId !== undefined
        ? await this.client.createInvestigation("", {
            type: "alert", alertId: seed.alertId, source: seed.source,
          })
        : await this.client.createInvestigationFromInput(seed.value ?? "", seed.kind ?? "");
      this.open.delete(ref.id);
      ref.id = created.id;
      this.open.set(created.id, panel);
      panel.title = `⚖ ${created.title}`;
      void this.post(panel, { type: "seeded" });
      void this.load(created.id, panel);
      // The tree should show the new investigation immediately.
      void vscode.commands.executeCommand("reckon.refreshInvestigations");
    } catch (err) {
      void this.post(panel, { type: "draft.error", message: errText(err) });
    } finally {
      this.seeding.delete(draftKey);
    }
  }

  /**
   * Search the case system of record for the draft's "from a case" surface
   * (14 §4.1): the query and its results live on the panel, never the
   * top-of-window quick input (13 §3). A read failure surfaces inline in the
   * sub-form; seeding from a picked case runs the ordinary seedDraft path
   * (kind "case"), which fails closed server-side on a bad case id.
   */
  private async searchCases(panel: vscode.WebviewPanel, filter: string): Promise<void> {
    try {
      const cases = await this.client.queryExternalCases(filter.trim() || undefined);
      void this.post(panel, { type: "draft.cases", cases });
    } catch (err) {
      void this.post(panel, { type: "draft.caseError", message: errText(err) });
    }
  }

  /** Refresh every open document (e.g. after sign-out flips to sign-in). */
  refreshAll(): void {
    for (const [id, panel] of this.open) {
      // Drafts have no aggregate id — loading one is a guaranteed 4xx.
      if (!InvestigationDocuments.isDraft(id)) {
        void this.load(id, panel);
      }
    }
  }

  private async load(id: string, panel: vscode.WebviewPanel): Promise<void> {
    void this.post(panel, { type: "loading" });
    let loadedThread: ThreadEntry[] | undefined;
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
      loadedThread = thread ?? undefined;
      void this.post(panel, { type: "data", investigation, hypotheses, capabilities, thread });
      this.onLoaded?.(id, investigation.lastEventSequence);
      // The event-time strip + evidence graph ride the same load,
      // fire-and-forget: both are lenses over the cited refs, sharing one
      // round of (cached) evidence fetches.
      void this.postDerivedViews(panel, thread ?? []);
      // The enablement view (gap hints + form schemas). Absence is honest:
      // a 503/failed fetch just means no hints render.
      void this.client.enablement()
        .then((data) => this.post(panel, { type: "enablement", data }))
        .catch(() => this.post(panel, { type: "enablement", data: null }));

    } catch (err) {
      const message = errText(err);
      this.log.error(`load investigation ${id}: ${message}`);
      void this.post(panel, { type: "error", message });
    }
    // The durable action queue rides every load (open, refresh, post-turn,
    // post-decision) — the panel always shows what actually awaits the
    // analyst, not just what the last turn proposed. The thread this load
    // already fetched rides along so the chronicle doesn't re-fetch it.
    await this.postPending(id, panel, loadedThread);
  }

  /** Fetch + render the action queue and pin fold. Failure logs, never breaks. */
  private async postPending(id: string, panel: vscode.WebviewPanel, thread?: ThreadEntry[]): Promise<void> {
    try {
      const actions = await this.client.actions(id);
      void this.post(panel, { type: "pending", actions });
      // Dispatch is asynchronous (a Temporal workflow) and its result events are
      // recorded by the worker, not the HTTP path — no delta reaches this panel.
      // While any action is mid-dispatch, keep refreshing until it settles, so
      // DISPATCHING never sticks past the real outcome (SNOW cold calls + the
      // retry budget can take a minute or more).
      this.scheduleDispatchWatch(id, panel, actions);
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
    try {
      const threads = await this.client.comms(id);
      void this.post(panel, { type: "comms", threads });
    } catch (err) {
      // A 503 just means the comms layer is off — not a broken panel.
      this.log.debug(`list comms ${id}: ${errText(err)}`);
    }
    // The chronicle rides the same refresh cycle: every act (approve, dispatch,
    // result, pin, verdict) is a sequenced interpretation, so re-fetching the
    // thread after any rail action keeps the reading surface complete. (A
    // caller that already fetched the thread — load — hands it down instead.)
    await this.postChronicle(id, panel, thread);
  }

  /**
   * Fetch the thread and its committed turn transcripts and post them as one
   * chronicle render (design/ui/00 §7 "structural navigation"): the reading
   * surface interleaves agent turns with the compact act lines (approvals,
   * dispatches, results, pins, verdicts) in sequence order. Transcripts are
   * cached, so this is one thread query plus only newly-committed turns.
   */
  private async postChronicle(id: string, panel: vscode.WebviewPanel, preFetched?: ThreadEntry[]): Promise<void> {
    try {
      const thread = preFetched ?? await this.client.thread(id);
      const withTranscript = thread.filter((e) => e.hasTranscript).slice(-40);
      const turns = (await Promise.all(withTranscript.map(async (e) => {
        let body = this.transcriptCache.get(e.interpretationId);
        if (body === undefined) {
          try {
            body = (await this.client.transcript(e.interpretationId)).body;
            this.transcriptCache.set(e.interpretationId, body);
          } catch {
            return null;
          }
        }
        return { sequenceNo: e.sequenceNo, occurredAt: e.occurredAt, body };
      }))).filter((t): t is { sequenceNo: number; occurredAt: string; body: string } => t !== null);
      void this.post(panel, { type: "chronicle", thread, turns });
    } catch (err) {
      this.log.debug(`chronicle ${id}: ${errText(err)}`);
    }
  }

  /** Acknowledge a reply or mark a thread done — recorded on the trail. */
  private async commsAct(id: string, panel: vscode.WebviewPanel, threadId: string, verb: "ack" | "done"): Promise<void> {
    try {
      await this.client.commsAct(threadId, verb);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: comms ${verb} failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /** Push a thread's follow-up clock. */
  private async commsSnooze(id: string, panel: vscode.WebviewPanel, threadId: string, hours: number): Promise<void> {
    try {
      await this.client.commsSnooze(threadId, hours);
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: snooze failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
  }

  /**
   * Send a follow-up: a NEW notify.* action carrying thread_ref (binding §4 —
   * every outbound message is an action through Gate 2), which lands in the
   * approval queue as a preview card. On its SUCCEEDED dispatch the thread's
   * counter increments and its clock restarts.
   */
  private async commsFollowUp(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { threadId: string; actionType: string; target: string; subject: string; message: string; followUpHours: number },
  ): Promise<void> {
    const parameters: Record<string, unknown> = {
      thread_ref: msg.threadId,
      follow_up_hours: msg.followUpHours,
    };
    if (msg.actionType === "notify.email") {
      parameters.subject = msg.subject ? `Re: ${msg.subject}` : "Follow-up";
      parameters.body = msg.message;
    } else {
      parameters.message = msg.message;
    }
    try {
      const res = await this.client.requestAction({
        investigationRef: id,
        actionType: msg.actionType,
        targets: [{ resolvedIdentifier: msg.target }],
        parameters,
        rationale: `follow-up on comms thread ${msg.threadId}`,
      });
      void vscode.window.showInformationMessage(
        `reckon: follow-up requested (${res.status}) — approve to send`,
      );
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: follow-up failed — ${errText(err)}`);
    }
    await this.postPending(id, panel);
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

  /** Fetch one evidence doc through the cache (null = unfetchable). */
  private async getDoc(ref: string): Promise<EvidenceDoc | null> {
    const hit = this.docCache.get(ref);
    if (hit !== undefined) {
      return hit;
    }
    let doc: EvidenceDoc | null;
    try {
      doc = await this.client.evidence(ref);
    } catch {
      doc = null;
    }
    this.docCache.set(ref, doc);
    return doc;
  }

  /**
   * Resolve a human label for an evidence ref (host · WIN-FILE01, account ·
   * svc_backup) from the evidence endpoint, cached. Posts back only on a hit;
   * a ref that can't be opened keeps its type-only label in the webview.
   */
  private async resolveLabel(panel: vscode.WebviewPanel, ref: string): Promise<void> {
    let label = this.labelCache.get(ref);
    if (label === undefined) {
      const doc = await this.getDoc(ref);
      label = doc ? deriveEvidenceLabel(doc) : "";
      this.labelCache.set(ref, label);
    }
    if (label) {
      void this.post(panel, { type: "evidence.label", ref, label });
    }
  }

  /**
   * The derived lenses over the thread's citations, sharing one round of
   * (cached) evidence fetches — bounded; failures just leave gaps (both are
   * lenses, never load-bearing):
   *
   *   - the event-time strip (13 §4 Timeline, minimal at v0): every ref that
   *     carries an EVENT time — OCSF `time` and observed-data `first_observed`;
   *   - the minimal evidence graph (13 §7 step 7): the two-layer join —
   *     interpretation-layer STIX objects ↔ OCSF telemetry, acts collapsed
   *     into grounding edges, with the observed-data → entity object_refs
   *     making the join explicit.
   */
  private async postDerivedViews(panel: vscode.WebviewPanel, thread: ThreadEntry[]): Promise<void> {
    const refs: string[] = [];
    for (const e of thread) {
      for (const r of [...e.inputRefs, ...e.outputRefs]) {
        if (r && !refs.includes(r)) {
          refs.push(r);
        }
      }
    }
    const bounded = refs.slice(0, 80);
    const items: { ref: string; time: string; label: string }[] = [];
    // Small batches: local backend, but no reason to fire 80 at once.
    for (let i = 0; i < bounded.length; i += 8) {
      const docs = await Promise.all(bounded.slice(i, i + 8).map((r) => this.getDoc(r)));
      for (const doc of docs) {
        if (!doc) {
          continue;
        }
        let time = doc.kind === "ocsf" ? doc.time : undefined;
        if (!time && doc.type === "observed-data") {
          const p = (doc.payload ?? {}) as Record<string, unknown>;
          if (typeof p.first_observed === "string") {
            time = p.first_observed;
          }
        }
        if (time && Number.isFinite(Date.parse(time))) {
          items.push({ ref: doc.ref, time, label: doc.type || doc.kind });
        }
      }
    }
    items.sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
    void this.post(panel, { type: "events.strip", items });

    // --- the graph: the two-layer evidence structure ----------------------
    // Interpretation-layer objects (STIX: reasoning nodes AND SCOs) on the
    // left, telemetry (OCSF) on the right. Acts are NOT nodes here — the
    // chronicle owns "what happened, in order"; the graph owns "what grounds
    // what." Each act collapses into grounding edges: every object it produced
    // (outputRefs) points at every piece of evidence it consumed (inputRefs),
    // tinted by whether a human or the AI asserted the link. A reasoning
    // object that produces no such edge is floating on assertion — the alarm
    // the graph exists to raise.
    // Edges dedup by (from,to) — the same citation asserted by several acts is
    // ONE edge, and a human assertion outranks an AI one for the tint (drawing
    // duplicates would stack paths and let paint order pick the tint).
    const edgeByPair = new Map<string, { from: string; to: string; ai: boolean; join?: boolean }>();
    const addEdge = (from: string, to: string, ai: boolean, join?: boolean) => {
      const key = from + "|" + to;
      const prior = edgeByPair.get(key);
      if (!prior) {
        edgeByPair.set(key, { from, to, ai, join });
      } else if (prior.ai && !ai) {
        prior.ai = false;
      }
    };
    const inGraph = new Set<string>();
    for (const e of thread.slice(-40)) {
      const ins = e.inputRefs.filter(Boolean);
      const outs = e.outputRefs.filter(Boolean);
      for (const r of [...ins, ...outs]) {
        inGraph.add(r);
      }
      const ai = e.actor.kind === "AI_DELEGATED";
      for (const o of outs) {
        for (const i of ins) {
          if (o !== i) {
            addEdge(o, i, ai);
          }
        }
      }
    }
    // The explicit two-layer join: observed-data → the entities it observed.
    // Snapshot first — join targets are new nodes, not new observed-data.
    for (const r of [...inGraph]) {
      const doc = this.docCache.get(r) ?? null;
      if (doc?.kind === "stix" && doc.type === "observed-data") {
        const p = doc.payload as { object_refs?: unknown } | null;
        const objRefs = Array.isArray(p?.object_refs) ? p.object_refs : [];
        for (const or of objRefs) {
          if (typeof or !== "string" || or === "") {
            continue;
          }
          inGraph.add(or);
          addEdge(r, or, false, true);
        }
      }
    }
    const edges = [...edgeByPair.values()];
    const graphRefs: { id: string; kind: string; type: string }[] = [];
    for (const r of inGraph) {
      const doc = this.docCache.get(r) ?? null;
      graphRefs.push({
        id: r,
        kind: doc?.kind ?? "",
        type: doc?.type ?? (r.includes("--") ? r.slice(0, r.indexOf("--")) : "event"),
      });
    }
    void this.post(panel, { type: "graph", refs: graphRefs, edges });
  }

  /**
   * The entity popover's data: every OTHER investigation citing this ref
   * (cross-investigation memory, binding §6.1). Failure posts an empty list —
   * the popover renders "first seen here" honestly rather than hanging.
   */
  private async entityInfo(id: string, panel: vscode.WebviewPanel, ref: string): Promise<void> {
    let apps: Appearance[] = [];
    try {
      apps = (await this.client.appearances(ref)).filter((a) => a.investigationId !== id);
    } catch (err) {
      this.log.debug(`appearances ${ref}: ${errText(err)}`);
    }
    void this.post(panel, { type: "entity.info", ref, appearances: apps });
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

  /**
   * Record an analyst-authored hypothesis — e.g. the alternate explanation
   * that competes with the AI's. Lands OPEN (human-authored); rejections
   * surface verbatim.
   */
  private async newHypothesis(id: string, panel: vscode.WebviewPanel, statement: string): Promise<void> {
    if (statement.trim() === "") {
      return;
    }
    try {
      await this.client.recordHypothesis(id, statement.trim());
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: hypothesis failed — ${errText(err)}`);
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
   * Apply an enablement change (11 §5.1). The webview form collected the
   * non-secret fields; here the flow becomes NATIVE: a modal confirm bound to
   * the human's identity, and secret fields captured through a secure input —
   * out-of-band of the webview and the conversation, so a secret value never
   * touches chat content or the transcript store. What is captured for an
   * x-secret field is a secret REFERENCE (keychain:// env:// vault://), per
   * 11 §4.3 — the engine refuses literals at config load.
   */
  private async applyEnablement(
    id: string,
    panel: vscode.WebviewPanel,
    msg: { adapter: string; enabled: boolean; config: Record<string, string>; secretFields: string[] },
  ): Promise<void> {
    const verb = msg.enabled ? "Enable" : "Disable";
    const pick = await vscode.window.showWarningMessage(
      `reckon: ${verb} adapter "${msg.adapter}"? This edits the tenant config file (the source of truth) and records an attributed config-plane audit entry.`,
      { modal: true },
      verb,
    );
    if (pick !== verb) {
      return;
    }
    const config = { ...msg.config };
    for (const field of msg.secretFields ?? []) {
      const v = await vscode.window.showInputBox({
        title: `reckon — ${msg.adapter}.${field} (secret reference)`,
        prompt: "A secret REFERENCE (keychain://…, env://NAME, vault://…) — never the literal value; the engine refuses literals at config load.",
        password: true,
        ignoreFocusOut: true,
      });
      if (v === undefined) {
        return; // cancelled — nothing applied
      }
      if (v.trim() !== "") {
        config[field] = v.trim();
      }
    }
    try {
      await this.client.applyEnablement(msg.adapter, msg.enabled, config);
      void vscode.window.showInformationMessage(
        `reckon: ${msg.adapter} ${msg.enabled ? "enabled" : "disabled"} — capability surface rebuilt`,
      );
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: enablement failed — ${errText(err)}`);
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
    // postPending arms the dispatch watch: the approved action is now
    // APPROVED/EXECUTING, so the ledger keeps refreshing until it settles.
  }

  /**
   * Keep the ledger honest through an async dispatch: while any action sits in
   * a transient state (APPROVED/EXECUTING), re-fetch on a short interval until
   * everything is terminal — regardless of which surface (this panel, the
   * agent, auto-approval) started the dispatch. Bounded (~3 min) so a truly
   * wedged workflow cannot poll forever; the ledger then shows the honest
   * transient state until the next interaction.
   */
  private scheduleDispatchWatch(id: string, panel: vscode.WebviewPanel, actions: ActionRow[]): void {
    const existing = this.dispatchWatch.get(id);
    const inFlight = actions.some((a) => a.status === "APPROVED" || a.status === "EXECUTING");
    if (!inFlight) {
      if (existing) {
        clearTimeout(existing.timer);
        this.dispatchWatch.delete(id);
      }
      return;
    }
    const ticks = existing ? existing.ticks + 1 : 0;
    if (existing) {
      clearTimeout(existing.timer);
    }
    if (ticks >= 45 || this.open.get(id) !== panel) {
      this.dispatchWatch.delete(id);
      return;
    }
    const timer = setTimeout(() => {
      void this.postPending(id, panel); // re-arms (or clears) the watch from fresh state
    }, 4000);
    this.dispatchWatch.set(id, { timer, ticks });
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

  /**
   * The live markdown export in an editor tab (binding §6 item 10): rendered
   * backend-side from the projections, opened as an untitled markdown doc the
   * analyst can read, save, or paste into a ticket unedited.
   */
  private async openMarkdownExport(id: string): Promise<void> {
    try {
      const md = await this.client.exportMarkdown(id);
      const doc = await vscode.workspace.openTextDocument({ content: md, language: "markdown" });
      await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
    } catch (err) {
      void vscode.window.showErrorMessage(`reckon: export failed — ${errText(err)}`);
    }
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

  /**
   * Fire the propose-tests aside (ui/02 §2.9, the "btw" lens): a scoped
   * agent turn the analyst ordered with one click. Same audit record as any
   * turn — the transcript commits to the one thread — but rendered collapsed
   * in the conversation; the predictions it records land on the tracker.
   * The "⚡ Propose tests:" prefix doubles as the cold-restore marker.
   */
  private async proposeTests(id: string, panel: vscode.WebviewPanel, hypothesisRef: string, statement: string): Promise<void> {
    const clipped = statement.length > 60 ? statement.slice(0, 59) + "…" : statement;
    const instruction = `⚡ Propose tests: for the hypothesis "${statement}" (${hypothesisRef}), `
      + "record the falsifiable predictions that would decide it — one prediction per test, "
      + "each with a concrete test query against the available capability verbs. Prove it or break it. "
      + "Record them with the tools ONLY; keep your final message to one sentence and do not "
      + "restate the predictions in prose — the tracker renders them.";
    await this.runTurn(id, panel, instruction, { label: `⚡ propose tests · ${clipped}` });
  }

  /**
   * Run the untested predictions — the execute half of the drivable loop.
   * They are independent claims, so the agent runs them in parallel where
   * possible; outcomes must cite what was observed (the aggregate refuses a
   * CONFIRMED/DISCONFIRMED without test_result_refs).
   */
  private async runTests(id: string, panel: vscode.WebviewPanel, hypothesisRef: string, statement: string): Promise<void> {
    const clipped = statement.length > 60 ? statement.slice(0, 59) + "…" : statement;
    const instruction = `⚡ Run tests: execute the UNTESTED predictions under the hypothesis "${statement}" (${hypothesisRef}). `
      + "They are independent — run their declared test queries in parallel where possible, then record each "
      + "outcome (CONFIRMED / DISCONFIRMED / INCONCLUSIVE) citing the observed evidence as test_result_refs. "
      + "Keep your final message to one or two sentences on what was decisive — do not restate the outcomes; the tracker renders them.";
    await this.runTurn(id, panel, instruction, { label: `⚡ run tests · ${clipped}` });
  }

  /**
   * Decide the hypothesis — the judgment rung, ordered by the analyst once
   * every prediction is decided. The agent weighs the outcomes and records
   * support / refutation / inconclusive citing the decisive test evidence.
   * Terminal in v0 (01): a changed judgment later is a NEW hypothesis
   * chained via parent_ref, keeping every reversal auditable.
   */
  private async decideHypothesis(id: string, panel: vscode.WebviewPanel, hypothesisRef: string, statement: string): Promise<void> {
    const clipped = statement.length > 60 ? statement.slice(0, 59) + "…" : statement;
    const instruction = `⚡ Decide: every prediction under the hypothesis "${statement}" (${hypothesisRef}) has been tested. `
      + "Weigh the outcomes and record the hypothesis outcome — support, refutation, or inconclusive — citing the "
      + "decisive test evidence. Be honest about mixed results: confirmed predictions support only what they actually tested. "
      + "Keep your final message to one or two sentences on the judgment and why — the tracker renders the status.";
    await this.runTurn(id, panel, instruction, { label: `⚡ decide · ${clipped}` });
  }

  /** Drive one analyst turn through the transport, streaming progress to the webview. */
  private async runTurn(id: string, panel: vscode.WebviewPanel, text: string, aside?: { label: string }): Promise<void> {
    if (aside) {
      void this.post(panel, { type: "aside.start", label: aside.label });
    } else {
      void this.post(panel, { type: "turn.user", text });
      void this.post(panel, { type: "turn.start" });
    }
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

    /* ---- two-region layout: conversation + grip + state rail ---- */
    #main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
    #railGrip {
      flex: none; width: 5px; cursor: col-resize;
      border-left: 1px solid var(--border);
      transition: background var(--dur-fast) var(--ease);
    }
    #railGrip:hover, body.railDragging #railGrip {
      background: color-mix(in srgb, var(--he-primary) 40%, transparent);
    }
    body.railDragging { cursor: col-resize; user-select: none; }
    #rail {
      flex: none; width: var(--rail-w, 400px); min-width: 200px; max-width: 60vw;
      overflow-y: auto; padding: var(--sp-3) var(--sp-3) var(--sp-4);
      background: var(--vscode-sideBar-background, transparent);
    }
    @media (max-width: 640px) { #rail, #railGrip { display: none; } }

    header {
      padding: var(--sp-3) var(--sp-5) var(--sp-2);
      border-bottom: 1px solid var(--border); flex: none;
    }
    .titlerow { display: flex; align-items: baseline; gap: var(--sp-3); }
    .titlename { display: flex; align-items: baseline; gap: 6px; flex: 1; min-width: 0; }
    header h1 {
      font-size: var(--fs-lg); font-weight: 600; margin: 0; min-width: 0;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .iconbtn {
      flex: none; background: none; border: none; color: var(--text-3);
      cursor: pointer; font-size: 13px; padding: 0 4px; line-height: 1;
      border-radius: var(--r-sm, 4px);
    }
    .iconbtn:hover { color: var(--text); background: var(--fill-2); }
    /* In-place title editor: looks like the title, edits like a file rename. */
    .titleedit {
      flex: 1; min-width: 0; font-size: var(--fs-lg); font-weight: 600;
      font-family: inherit; color: var(--text); background: var(--fill-2);
      border: 1px solid var(--he-primary); border-radius: var(--r-sm, 4px);
      padding: 1px 6px; margin: 0; outline: none;
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
    /* markdown pipe tables (ui/02 §2.3 result-table treatment) */
    .md .tblwrap { overflow-x: auto; margin: var(--sp-2) 0; }
    .md table.mdtable {
      border-collapse: collapse; font-size: var(--fs-sm); line-height: 1.45;
    }
    .md .mdtable th, .md .mdtable td {
      border: 1px solid var(--border); padding: 4px 9px;
      text-align: left; vertical-align: top;
    }
    .md .mdtable th {
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.06em; background: var(--fill); color: var(--text-2);
      white-space: nowrap;
    }

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
    .sopchip {
      display: inline-block; font-size: var(--fs-xs); padding: 0 7px;
      margin: 2px 3px 0 0; border: 1px solid var(--info-border);
      color: var(--info); background: var(--info-bg); border-radius: var(--r-pill);
    }
    .sopchip.consulted { border-style: dashed; opacity: 0.6; background: none; }
    .error { color: var(--bad); margin: 6px 0; max-width: 78ch; }

    /* micro-label eyebrow (01 §Scale): 10px, 700, tracked, uppercase */
    #rail h2, .railfold > summary, #stripWrap > summary, #graphWrap > summary, .dlglabel, .residual .rtitle {
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--text-2);
    }

    /* ---- event-time strip (13 §4 Timeline, minimal): the OTHER clock ---- */
    #stripWrap { margin: 10px 0 var(--sp-3); max-width: 78ch; }
    #stripWrap > summary { cursor: pointer; margin-bottom: 6px; }
    #strip {
      position: relative; height: 26px; margin: 2px 6px 0;
      border-bottom: 1px solid var(--border);
    }
    #strip .evdot {
      position: absolute; bottom: -4px; width: 7px; height: 7px;
      border-radius: 50%; background: var(--info); border: 1px solid var(--vscode-editor-background);
      cursor: pointer; transform: translateX(-50%);
      transition: transform var(--dur-fast) var(--ease);
    }
    #strip .evdot:hover { transform: translateX(-50%) scale(1.5); }
    #strip .evdot.od { background: var(--he-primary-soft); }
    #stripAxis {
      display: flex; justify-content: space-between; margin: 6px 6px 0;
      font-family: var(--mono); font-size: var(--fs-xs); color: var(--text-3);
    }

    /* ---- evidence graph (13 §7 step 7, minimal): the two-layer join ---- */
    #graphWrap { margin: 10px 0 var(--sp-3); max-width: 78ch; }
    #graphWrap > summary { cursor: pointer; margin-bottom: 6px; }
    #graphBox { overflow-x: auto; }
    #graphBox svg { display: block; font-family: var(--mono); }
    #graphBox .gedge { stroke: color-mix(in srgb, var(--vscode-foreground) 18%, transparent); stroke-width: 1; fill: none; }
    #graphBox .gedge.human { stroke: color-mix(in srgb, var(--ok-border) 55%, transparent); }
    #graphBox .gedge.join { stroke: color-mix(in srgb, var(--he-primary) 40%, transparent); stroke-dasharray: 3 2; }
    #graphBox .gnode { cursor: pointer; }
    #graphBox .gnode rect { rx: 4; fill: var(--fill-2); stroke: var(--border); }
    #graphBox .gnode.reason rect { fill: color-mix(in srgb, var(--he-primary) 8%, transparent); stroke: color-mix(in srgb, var(--he-primary) 50%, transparent); }
    #graphBox .gnode.ungrounded rect { stroke: var(--warn-border); stroke-dasharray: 3 2; }
    #graphBox .gnode.ocsf rect { fill: color-mix(in srgb, var(--info) 10%, transparent); stroke: var(--info-border); }
    #graphBox .gnode text { font-size: 10px; fill: var(--text); }
    #graphBox .gnode.ungrounded text { fill: var(--warn); }
    #graphBox .gnode:hover rect { stroke-width: 2; }
    #graphBox .gcol { font-size: 9px; font-weight: 700; letter-spacing: 0.08em; fill: var(--text-3); text-transform: uppercase; }

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
    /* ---- action ledger rows (rail) ---- */
    .actrow { padding: 6px 0; border-top: 1px solid var(--border); }
    .actrow:first-child { border-top: none; }
    .actrow.pend { opacity: 1; }
    .actrow.settled { opacity: 0.82; }
    .actrow .artop { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }
    .actrow .atype { font-weight: 600; font-size: var(--fs-sm); }
    .actrow .artgt { color: var(--text-3); font-size: var(--fs-xs); margin-top: 2px; }
    .actrow .armeta { color: var(--text-3); font-size: var(--fs-xs); margin-top: 2px; }
    .actrow .armeta.via { font-family: var(--mono, ui-monospace, monospace); color: var(--text-2); }
    .actrow .armeta.err { color: var(--bad, #e5534b); word-break: break-word; }
    /* Context-reset boundary: a visible break in the chronicle — above it is
       narration the agent no longer holds; below, it reasons from the record. */
    .ctxreset { display: flex; align-items: center; gap: 10px; margin: 14px 0;
      color: var(--text-2); font-size: var(--fs-xs); font-style: italic; white-space: nowrap; }
    .ctxreset::before, .ctxreset::after { content: ""; flex: 1; border-top: 1px dashed var(--border); }
    .predictions { list-style: none; padding: 0; margin: 6px 0 0; }
    .predictions li {
      padding: 3px 0 3px 10px; border-left: 2px solid var(--border);
      margin: 4px 0; font-size: var(--fs-sm);
    }
    .testbtn { font-size: var(--fs-xs); padding: 0 8px; margin-left: 6px; }
    /* prediction controls: badge · chips · action, action always right-anchored */
    .predrow {
      display: flex; flex-wrap: wrap; align-items: center;
      gap: 3px 6px; margin-top: 4px;
    }
    .predrow .refchip { margin: 0; }
    .predrow .badge { margin-left: 0; }
    .predrow .predact { margin-left: auto; }
    .railadd {
      font-size: var(--fs-xs); padding: 0 7px; margin-left: 5px;
      text-transform: none; letter-spacing: normal; vertical-align: 1px;
    }
    /* the drive affordance: reads as the suggested move, not chrome */
    button.askdecide {
      color: var(--he-primary-soft);
      border: 1px dashed color-mix(in srgb, var(--he-primary) 45%, transparent);
      background: color-mix(in srgb, var(--he-primary) 8%, transparent);
    }
    button.askdecide:hover { background: color-mix(in srgb, var(--he-primary) 15%, transparent); }
    /* asides: a scoped turn as a collapsed one-liner (same record, quieter lens) */
    details.aside {
      margin: var(--sp-2) 0; max-width: 78ch; font-size: var(--fs-sm);
      border-left: 2px dashed color-mix(in srgb, var(--he-primary) 45%, transparent);
      padding-left: 10px;
    }
    details.aside > summary {
      cursor: pointer; list-style: none; color: var(--text-2);
      font-size: var(--fs-sm);
    }
    details.aside > summary::-webkit-details-marker { display: none; }
    details.aside > summary:hover { color: var(--text); }
    details.aside .asidebody { padding: 4px 0 2px; }
    /* clamped statements: the rail is a scoreboard, not an essay — click expands */
    .clamp {
      display: -webkit-box; -webkit-box-orient: vertical; overflow: hidden;
      cursor: pointer;
    }
    .clamp.c2 { -webkit-line-clamp: 2; }
    .clamp.c4 { -webkit-line-clamp: 4; }
    .clamp.expanded { -webkit-line-clamp: unset; display: inline; }
    .hyphead { display: flex; align-items: baseline; gap: 6px; }
    .hyphead .statement { flex: 1; min-width: 0; }
    .cardmeta { font-size: var(--fs-xs); color: var(--text-2); margin-top: 4px; word-break: break-word; }
    .cardmeta.via { font-family: var(--mono, ui-monospace, monospace); color: var(--text-1); }
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

    /* ---- entity popover (ui/02 §2.4): overlay surface, viewport-clamped ---- */
    .popover {
      position: fixed; z-index: 20; width: min(320px, 86vw);
      background: var(--overlay-bg); border: 1px solid var(--vscode-widget-border, var(--border));
      border-radius: var(--r-lg); box-shadow: var(--shadow-pop);
      padding: 11px 13px; animation: dlgIn 0.16s var(--ease-out);
    }
    .pop-head { display: flex; align-items: baseline; gap: 8px; }
    .pop-type {
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.07em; flex: none; background: none;
    }
    .pop-value {
      font-family: var(--mono); font-size: var(--fs-md); font-weight: 600;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .pop-id {
      font-family: var(--mono); font-size: var(--fs-xs); color: var(--text-3);
      margin: 4px 0 8px; word-break: break-all;
    }
    .pop-apps { border-top: 1px solid var(--border); padding-top: 7px; margin-bottom: 8px; }
    .pop-appshead {
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--text-2); margin-bottom: 4px;
    }
    .pop-first { font-size: var(--fs-xs); color: var(--text-3); font-style: italic; }
    .app-row {
      display: flex; align-items: baseline; gap: 7px; font-size: var(--fs-sm);
      padding: 2px 4px; margin: 0 -4px; border-radius: var(--r-xs); cursor: pointer;
    }
    .app-row:hover { background: var(--hover); }
    .app-row .app-title { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .app-row .app-status { flex: none; font-size: var(--fs-xs); color: var(--text-3); }
    .pop-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
    .pop-grid button { font-size: var(--fs-sm); padding: 4px 8px; }

    /* ---- comms cards (ui/04): the external-work trail ---- */
    .commscard.replied { border-color: var(--ok-border); }
    .commscard .quote {
      font-size: var(--fs-xs); color: var(--text-2); font-style: italic;
      border-left: 2px solid var(--border); padding-left: 8px; margin: 5px 0;
      white-space: pre-wrap; word-break: break-word;
    }
    .commscard .quote.inbound { border-left-color: var(--ok); }
    .commscard .esc {
      font-size: var(--fs-xs); color: var(--bad); background: var(--bad-bg);
      border: 1px solid var(--bad-border); border-radius: var(--r-sm);
      padding: 4px 8px; margin-top: 5px;
    }
    /* the pre-send preview body on a notify.* approval card (binding §4) */
    .sendpreview {
      font-size: var(--fs-sm); background: var(--fill);
      border: 1px solid var(--border); border-radius: var(--r-sm);
      padding: 6px 9px; margin: 6px 0; white-space: pre-wrap; word-break: break-word;
    }
    .sendpreview .subj { font-weight: 600; }

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
    .pincta:disabled, .pincta.pinnedInert { opacity: 0.6; cursor: default; background: none; }
    /* The pin sits at the right end of the always-visible tool summary. */
    .summaryPin { flex: none; margin-left: auto; font-size: var(--fs-xs); padding: 0 8px; }
    details.tool[open] .summaryPin { opacity: 0.9; }

    /* ---- dialogs: overlay surface, pop shadow, dlgIn entrance ---- */
    #verdictDialog, #promptDialog, #enableDialog {
      position: fixed; inset: 0; background: rgba(0,0,0,.45);
      display: flex; align-items: center; justify-content: center; z-index: 10;
    }
    #verdictDialog .dlg, #promptDialog .dlg, #enableDialog .dlg {
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
    #verdictDialog h3, #promptDialog h3, #enableDialog h3 { margin: 0 0 10px; font-size: var(--fs-lg); }
    #enableFields .field { margin: 8px 0; }
    #enableFields label { display: block; font-size: var(--fs-sm); margin-bottom: 3px; }
    #enableFields .fdesc { font-size: var(--fs-xs); color: var(--text-3); margin-top: 2px; }
    #enableFields input {
      width: 100%; box-sizing: border-box; font: inherit;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--border));
      border-radius: var(--r-sm); padding: 6px 9px;
    }
    #enableFields input:focus { outline: none; border-color: var(--he-primary); }
    #enableFields .secretnote {
      font-size: var(--fs-xs); color: var(--warn); border: 1px dashed var(--warn-border);
      border-radius: var(--r-sm); padding: 5px 8px;
    }
    .gaphint {
      font-size: var(--fs-xs); border: 1px dashed var(--info-border);
      background: var(--info-bg); color: var(--info);
      border-radius: var(--r-sm); padding: 4px 8px; margin: 5px 0;
      font-family: var(--sans);
    }
    .gaphint button { font-size: var(--fs-xs); padding: 0 8px; margin-left: 6px; }
    .caprow .setup { font-size: var(--fs-xs); padding: 0 7px; margin-left: auto; }
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

    /* ---- seed chip: the investigation's root, at the document head ---- */
    .seedchip {
      margin: 2px 0 10px; padding: 6px 10px; font-size: 0.92em;
      border: 1px solid var(--border); border-left: 3px solid var(--accent, var(--vscode-textLink-foreground));
      border-radius: var(--r-sm); background: var(--fill, var(--vscode-editorWidget-background));
      color: var(--vscode-descriptionForeground);
    }
    .seedchip b { color: var(--vscode-foreground); font-weight: 600; }

    /* ---- chronicle act lines: the connective tissue between turns ---- */
    .actline {
      display: flex; align-items: baseline; gap: 8px;
      padding: 3px 4px 3px 8px; margin: 1px 0;
      font-size: 0.9em; color: var(--vscode-descriptionForeground);
      border-left: 2px solid var(--border);
    }
    .actline.ai { border-left-color: var(--ai, var(--vscode-charts-purple)); }
    .actline.strong {
      color: var(--vscode-foreground); font-weight: 600;
      border-left-color: var(--accent, var(--vscode-textLink-foreground));
    }
    .actline .acticon { flex: none; width: 1.1em; text-align: center; opacity: 0.85; }
    .actline .acttext { flex: 1; min-width: 0; }
    .actline .acttime { flex: none; font-size: 0.85em; opacity: 0.6; }
    .actline .refchip { flex: none; }
    .actline.superseded { opacity: 0.6; }
    .actline.superseded.strong { font-weight: 400; }
    .actline.superseded .acttext { text-decoration: line-through; color: var(--text-3); }
    .actline .actsuperseded {
      flex: none; font-size: 10px; font-style: italic; color: var(--text-3);
      text-transform: uppercase; letter-spacing: 0.05em;
    }

    /* The invisible-activate note on a draft's first-action approval card. */
    .actnote { font-style: italic; opacity: 0.85; margin: 2px 0 6px; }

    /* ---- the unseeded (draft) state: root this investigation ---- */
    #draftView {
      position: fixed; inset: 0; z-index: 60; display: flex;
      align-items: center; justify-content: center; padding: 24px;
      background: var(--vscode-editor-background);
    }
    .draftCard { width: 100%; max-width: 560px; }
    .draftCard h2 { margin: 0 0 4px; font-size: 1.25em; }
    .draftLead { margin: 0 0 14px; color: var(--vscode-descriptionForeground); }
    #draftInput {
      width: 100%; box-sizing: border-box; resize: none; font: inherit; font-size: 1.15em;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--border));
      border-radius: var(--r-sm); padding: 10px 12px; min-height: 2.6rem; max-height: 8rem;
    }
    #draftInput:focus { outline: none; border-color: var(--vscode-focusBorder); }
    .draftInterp { min-height: 24px; margin: 8px 2px 0; font-size: 0.95em; color: var(--vscode-descriptionForeground); }
    .draftInterp b { color: var(--vscode-foreground); font-weight: 600; }
    .draftInterp .toggle {
      margin-left: 8px; cursor: pointer; color: var(--vscode-textLink-foreground);
      border-bottom: 1px dashed currentColor;
    }
    .draftActions { display: flex; align-items: center; gap: 14px; margin-top: 16px; }
    .linklike {
      background: none; border: none; padding: 0; cursor: pointer;
      color: var(--vscode-textLink-foreground); text-decoration: underline;
    }
    #draftAlertForm { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
    #draftAlertForm input {
      font: inherit; color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--border)); border-radius: var(--r-sm); padding: 7px 10px;
    }
    #draftAlertForm button { align-self: flex-start; }
    #draftCaseForm { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
    .draftCaseSearch { display: flex; gap: 8px; }
    #draftCaseFilter {
      flex: 1; font: inherit; color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--border)); border-radius: var(--r-sm); padding: 7px 10px;
    }
    .draftCaseStatus { font-size: 0.9em; color: var(--vscode-descriptionForeground); min-height: 16px; }
    .draftCaseResults { display: flex; flex-direction: column; gap: 6px; max-height: 260px; overflow-y: auto; }
    .caseRow {
      text-align: left; cursor: pointer; font: inherit; padding: 8px 10px;
      color: var(--vscode-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--border)); border-radius: var(--r-sm);
    }
    .caseRow:hover { border-color: var(--vscode-focusBorder); }
    .caseNum { font-weight: 600; }
    .caseStatus { color: var(--vscode-descriptionForeground); margin-left: 8px; font-size: 0.85em; }
    .caseTitle { display: block; margin-top: 2px; color: var(--vscode-descriptionForeground); }
    .draftErr { margin-top: 12px; color: var(--vscode-errorForeground); min-height: 18px; }
  </style>
</head>
<body class="loading">
  <div id="main">
    <header>
      <div class="titlerow">
        <span class="titlename">
          <h1 id="title" title="Double-click to rename">Investigation</h1>
          <input id="titleEdit" class="titleedit" style="display:none" spellcheck="false" />
          <button id="renameBtn" class="iconbtn" title="Rename this investigation" style="display:none">✎</button>
        </span>
        <span class="state" id="state"></span>
        <span class="state verdictbadge" id="verdictBadge" style="display:none"></span>
        <button id="verdictBtn" title="Record the disposition of record">Verdict…</button>
        <span id="lifecycleBtns"></span>
        <button id="exportBtn" title="The live markdown snapshot — paste into a ticket unedited">Export</button>
        <button id="refresh" title="Reload from the backend">Refresh</button>
      </div>
      <div id="meta"></div>
    </header>

    <div id="scroll">
      <div id="banner"></div>
      <div id="seedChip" class="seedchip" style="display:none"></div>
      <details id="stripWrap" style="display:none">
        <summary id="stripSummary">Event time</summary>
        <div id="strip"></div>
        <div id="stripAxis"></div>
      </details>
      <details id="graphWrap" style="display:none">
        <summary id="graphSummary">Evidence graph</summary>
        <div id="graphBox"></div>
      </details>
      <div id="restored"></div>
      <div id="conversation"></div>
    </div>

    <div id="composer">
      <textarea id="input" rows="1" placeholder="Ask reckon to investigate… (Enter to send, Shift+Enter for newline)"></textarea>
      <button id="send">Send</button>
    </div>
  </div>

  <div id="railGrip" title="Drag to resize"></div>
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
      <h2>Hypotheses <button id="hypNew" class="railadd" title="Frame your own hypothesis — e.g. the alternate (benign or different-attacker) explanation. Lands OPEN, tested like any other.">+ new…</button></h2>
      <div id="hyps"><div class="empty">None yet</div></div>
    </section>
    <section>
      <h2 id="pinsHead">Pinned evidence</h2>
      <div id="pinsBox"><div class="empty">Nothing pinned yet</div></div>
    </section>
    <!-- The action ledger: the durable record of every action requested on this
         investigation and where it landed — the current-state lens the chat
         chronicle can't be. "Needs your approval" above is the urgent overlay;
         this is the complete list, settled and pending alike. -->
    <section id="actionsSection" style="display:none">
      <h2 id="actionsHead">Actions</h2>
      <div id="actionsBox"></div>
    </section>
    <section id="commsSection" style="display:none">
      <h2 id="commsHead">External work</h2>
      <div id="commsBox"></div>
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

  <!-- The enablement form (11 §5.1): rendered by the EXTENSION from the
       adapter's config schema — the model never generates it, and free-text
       model output is never parsed into config. Confirming hands off to a
       NATIVE modal + secure inputs in the extension host. -->
  <div id="enableDialog" style="display:none">
    <div class="dlg">
      <h3 id="enableTitle"></h3>
      <div id="enableIntro" class="pinhelp"></div>
      <div id="enableFields"></div>
      <div class="decide">
        <button class="primary" id="enableConfirm"></button>
        <button id="enableCancel">Cancel</button>
      </div>
    </div>
  </div>

  <!-- The unseeded state (design/ui/02 §2.7): a full-cover overlay where the
       analyst roots the investigation. NOT a wizard — one line in the same kind
       of composer, with a live interpretation and a one-click correction. The
       "From an alert…" path stays explicit (no ingestion to infer from at v0). -->
  <div id="draftView" style="display:none">
    <div class="draftCard">
      <h2>What are you investigating?</h2>
      <p class="draftLead">A host, an IP, or a file hash — or a question to hunt.</p>
      <textarea id="draftInput" rows="1" placeholder="WIN-FILE01   ·   185.220.101.5   ·   a file hash   —   or a question"></textarea>
      <div id="draftInterp" class="draftInterp"></div>
      <div class="draftActions">
        <button class="primary" id="draftStart" disabled>Start investigation</button>
        <button id="draftAlertToggle" class="linklike">From an alert…</button>
        <button id="draftCaseToggle" class="linklike">From a case…</button>
      </div>
      <div id="draftAlertForm" style="display:none">
        <input id="draftAlertId" type="text" placeholder="alert id in its tool (e.g. EDR-ALERT-7741)">
        <input id="draftAlertSource" type="text" placeholder="which tool raised it (e.g. crowdstrike-edr)">
        <button class="primary" id="draftAlertStart" disabled>Start from alert</button>
      </div>
      <!-- From a system-of-record case (14 §4.1): search the SoR and pick, all
           on this surface — the filter is a real field here, never the
           top-of-window quick input (13 §3). -->
      <div id="draftCaseForm" style="display:none">
        <div class="draftCaseSearch">
          <input id="draftCaseFilter" type="text" placeholder="filter your case system of record (blank = recent) — e.g. reimage">
          <button class="primary" id="draftCaseSearchBtn">Search cases</button>
        </div>
        <div id="draftCaseStatus" class="draftCaseStatus"></div>
        <div id="draftCaseResults" class="draftCaseResults"></div>
      </div>
      <div id="draftErr" class="draftErr"></div>
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
    // The enablement view (11 §5.1): gap hints + form schemas. Null = layer
    // off or unreachable — hints simply absent.
    let lastEnablement = null;

    // The chronicle (design/ui/00 §7): the committed thread + its turn bodies,
    // and whether a turn is actively streaming. #restored renders the whole
    // committed thread (turns interleaved with act lines); #conversation holds
    // ONLY the in-flight streaming turn, cleared into the chronicle once idle.
    let lastThread = [];
    const restoredBodies = new Map(); // sequenceNo → { occurredAt, body }
    let streaming = false;
    // Set when a turn FAILED before commit: the live copy is the only record of
    // it, so chronicle renders must not clear #conversation until a new turn
    // starts (which supersedes the stale error view).
    let preserveLive = false;
    let CUR_TITLE = ""; // current title, for the rename prefill

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
    // Entity types get the popover (ui/02 §2.4: chip → popover → staged pivot);
    // observed-data / events / reasoning nodes open their record directly
    // (§2.8: every citation opens).
    const ENTITY_POPOVER_TYPES = new Set([
      "x-host", "ipv4-addr", "ipv6-addr", "user-account", "process", "file",
      "domain-name", "email-addr", "url", "windows-registry-key", "indicator",
    ]);
    function refChip(ref) {
      const t = ref.includes("--") ? ref.slice(0, ref.indexOf("--")) : "";
      const c = document.createElement("span");
      c.className = "refchip" + (REF_CHIP_CLASS[t] ? " " + REF_CHIP_CLASS[t] : "");
      c.dataset.ref = ref;
      c.textContent = chipText(ref);
      c.title = ENTITY_POPOVER_TYPES.has(t) ? "Entity details: " + ref : "Open evidence: " + ref;
      c.addEventListener("click", (e) => {
        e.stopPropagation();
        if (ENTITY_POPOVER_TYPES.has(t)) {
          openEntityPopover(ref, c);
        } else {
          vscode.postMessage({ type: "evidence.open", ref });
        }
      });
      if (resolvedLabels[ref] === undefined) {
        vscode.postMessage({ type: "evidence.resolve", ref });
      }
      return c;
    }

    // ---- entity popover (ui/02 §2.4) ---------------------------------------
    // One at a time; fixed-positioned near the chip, viewport-clamped. Pivot
    // STAGES a question in the composer — it never fires (the pivot pattern).
    let popEl = null;
    function closePopover() {
      if (popEl) { popEl.remove(); popEl = null; }
    }
    document.addEventListener("click", (e) => {
      if (popEl && !popEl.contains(e.target)) closePopover();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closePopover();
    });

    function openEntityPopover(ref, anchor) {
      closePopover();
      const t = ref.includes("--") ? ref.slice(0, ref.indexOf("--")) : "";
      const pop = document.createElement("div");
      pop.className = "popover";
      pop.dataset.ref = ref;

      const head = document.createElement("div");
      head.className = "pop-head";
      const typeEl = document.createElement("div");
      typeEl.className = "pop-type " + (REF_CHIP_CLASS[t] || "");
      typeEl.textContent = refTypeLabel(ref);
      const valueEl = document.createElement("div");
      valueEl.className = "pop-value";
      valueEl.textContent = resolvedLabels[ref] || "…";
      head.append(typeEl, valueEl);

      // The deterministic id (03 §7): the engine's UUIDv5 — same entity, same
      // id, across producers and investigations. Displayed, never computed here.
      const idEl = document.createElement("div");
      idEl.className = "pop-id";
      idEl.textContent = ref;
      idEl.title = "Deterministic id (engine-minted UUIDv5) — same entity, same id, everywhere";

      const apps = document.createElement("div");
      apps.className = "pop-apps";
      apps.innerHTML = '<div class="empty">checking other investigations…</div>';

      const grid = document.createElement("div");
      grid.className = "pop-grid";
      const mkAct = (label, title, primary, onClick) => {
        const b = document.createElement("button");
        b.textContent = label;
        b.title = title;
        if (primary) b.className = "primary";
        b.addEventListener("click", (e) => { e.stopPropagation(); onClick(); });
        grid.appendChild(b);
      };
      mkAct("Pivot on entity", "Stage a pivot question in the composer — you review and send it", true, () => {
        const label = resolvedLabels[ref] || refTypeLabel(ref) + " " + ref;
        closePopover();
        stageInComposer("Pivot on " + label + ": what other activity involves this " + refTypeLabel(ref) + " across the available telemetry?");
      });
      mkAct("Pin as evidence", "Pin this entity with a finding note", false, () => {
        closePopover();
        openPinDialog([ref]);
      });
      mkAct("Open raw JSON", "The underlying record, read-only (02 §2.8)", false, () => {
        closePopover();
        vscode.postMessage({ type: "evidence.open", ref });
      });
      mkAct("Copy value", "Copy the resolved value (falls back to the id)", false, () => {
        const label = resolvedLabels[ref];
        vscode.postMessage({ type: "copy", text: label ? label : ref });
        closePopover();
      });

      pop.append(head, idEl, apps, grid);
      document.body.appendChild(pop);
      popEl = pop;

      // Position near the chip, clamped to the viewport (never clipped).
      const r = anchor.getBoundingClientRect();
      const w = pop.offsetWidth, h = pop.offsetHeight;
      let x = Math.min(r.left, window.innerWidth - w - 8);
      let y = r.bottom + 6;
      if (y + h > window.innerHeight - 8) y = Math.max(8, r.top - h - 6);
      pop.style.left = Math.max(8, x) + "px";
      pop.style.top = y + "px";

      if (resolvedLabels[ref] === undefined) {
        vscode.postMessage({ type: "evidence.resolve", ref });
      }
      vscode.postMessage({ type: "entity.info", ref });
    }

    // Fill the popover's appearances section once the host answers.
    function renderPopoverApps(ref, appearances) {
      if (!popEl || popEl.dataset.ref !== ref) return;
      const box = popEl.querySelector(".pop-apps");
      box.textContent = "";
      if (!appearances || !appearances.length) {
        const d = document.createElement("div");
        d.className = "pop-first";
        d.textContent = "First seen in this investigation. Cross-investigation identity is preserved by deterministic id — not surveillance, just join keys.";
        box.appendChild(d);
        return;
      }
      const head = document.createElement("div");
      head.className = "pop-appshead";
      head.textContent = "Appears in " + appearances.length + " other investigation" + (appearances.length === 1 ? "" : "s");
      box.appendChild(head);
      for (const a of appearances.slice(0, 6)) {
        const row = document.createElement("div");
        row.className = "app-row";
        const dot = document.createElement("span");
        dot.className = "dot" + (a.status === "concluded" || a.status === "archived" ? " unavailable" : "");
        const title = document.createElement("span");
        title.className = "app-title";
        title.textContent = a.title;
        const st = document.createElement("span");
        st.className = "app-status";
        st.textContent = a.status + " · " + a.mentions + "×";
        row.append(dot, title, st);
        row.title = (a.seedSummary || a.title) + " — open";
        row.addEventListener("click", (e) => {
          e.stopPropagation();
          vscode.postMessage({ type: "investigation.open", id: a.investigationId, title: a.title });
          closePopover();
        });
        box.appendChild(row);
      }
      if (appearances.length > 6) {
        const more = document.createElement("div");
        more.className = "cardmeta";
        more.textContent = "+" + (appearances.length - 6) + " more";
        box.appendChild(more);
      }
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
          // No explicit Activate (01 §Extension 2, invisible activate): a draft
          // activates automatically when its first external action is approved —
          // the reasoning→acting boundary. Reasoning flows freely meanwhile, so
          // there is nothing to click here.
          break;
        case "ACTIVE":
          mk("Pause", "A reversible hold — resume any time", () => send("pause"));
          mk("Conclude…", "Close with the verdict of record and a summary",
            () => {
              // The comms conclude-gate input (binding §4, ui/04 §4.10):
              // open external work is decision support at the moment of
              // closing — surfaced, never silently ignored.
              const openComms = lastComms.filter((t) => t.status === "awaiting_reply" || t.status === "followed_up").length;
              const commsWarn = openComms
                ? " ⚠ " + openComms + " comms thread(s) still await replies — mark them done or accept leaving them open."
                : "";
              openPrompt({
                title: "Conclude investigation",
                label: "Summary of record — what did this investigation determine?",
                placeholder: "e.g. Confirmed C2 beaconing from WIN-9; host isolated, IOCs blocked.",
                helper: "Concluding consumes the verdict of record (" + (lastVerdict ? lastVerdict.disposition : "none") + ") and files the final report reference. You can reopen later if the world disagrees." + commsWarn,
                confirm: "Conclude",
                onConfirm: (summary) => vscode.postMessage({ type: "lifecycle", transition: "conclude", summary }),
              });
            },
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
      // Rename is refused on a settled record (concluded/archived) — hide the
      // pencil rather than offer an affordance that can only fail. Never
      // re-show it while the inline editor is open (a refresh mid-edit would
      // render pencil + edit field side by side).
      if (!renameEditing()) {
        $("renameBtn").style.display = closed ? "none" : "";
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
    // Pipe tables (ui/02 §2.3 result-table treatment). Cells go through
    // inlineMd, so they stay escape-first like every other path.
    function mdRow(line) {
      let s = line.trim();
      if (s.charAt(0) === "|") s = s.slice(1);
      if (s.charAt(s.length - 1) === "|") s = s.slice(0, -1);
      return s.split("|").map((c) => c.trim());
    }
    function mdTable(block) {
      const rows = block.map(mdRow);
      let header = null, body = rows;
      if (rows.length >= 2 && rows[1].length > 0 && rows[1].every((c) => /^:?-{2,}:?$/.test(c))) {
        header = rows[0];
        body = rows.slice(2);
      }
      let html = '<div class="tblwrap"><table class="mdtable">';
      if (header) {
        html += "<thead><tr>" + header.map((c) => "<th>" + inlineMd(c) + "</th>").join("") + "</tr></thead>";
      }
      html += "<tbody>"
        + body.map((r) => "<tr>" + r.map((c) => "<td>" + inlineMd(c) + "</td>").join("") + "</tr>").join("")
        + "</tbody></table></div>";
      return html;
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
        if (/^\\s*\\|/.test(line)) {
          flushPara(); flushList();
          const block = [line];
          for (i++; i < lines.length && /^\\s*\\|/.test(lines[i]); i++) block.push(lines[i]);
          i--;
          out.push(mdTable(block));
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
          flushPara();
          // A blank line inside a list is inter-item spacing (a "loose" list):
          // keep the list open when the next content is another item of the
          // same kind, so an <ol> numbers continuously (1, 2, 3) instead of
          // splitting into single-item lists that each restart at 1.
          if (list) {
            let j = i + 1;
            while (j < lines.length && lines[j].trim() === "") j++;
            const next = j < lines.length ? lines[j] : "";
            const sameKind = list.tag === "ul"
              ? /^\\s*[-*•]\\s+/.test(next)
              : /^\\s*\\d+[.)]\\s+/.test(next);
            if (!sameKind) flushList();
          }
        } else if (list && /^\\s+\\S/.test(line)) {
          // An indented continuation line wraps into the current list item
          // rather than breaking the list.
          list.items[list.items.length - 1] += " " + line.trim();
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

      // The gap hint (11 §5.1): the verb came back unavailable AND an
      // installed-but-disabled adapter could serve it. Mentionable here;
      // actionable only through the human-confirmed form.
      if (!msg.isError && typeof msg.coverage === "string" && msg.coverage.indexOf("UNAVAILABLE") === 0) {
        appendGapHint(row, msg.name);
      }
    }

    // appendGapHint attaches the installed-not-enabled note under a tool row
    // when the enablement view knows a closable adapter for the verb.
    function appendGapHint(container, verb) {
      if (!lastEnablement) return;
      const v = (lastEnablement.verbs || []).find((x) => x.verb === verb);
      if (!v || v.enabled || !(v.closableBy || []).length) return;
      const adapter = v.closableBy[0];
      const hint = document.createElement("div");
      hint.className = "gaphint";
      hint.textContent = "⚡ " + adapter + " could answer this — installed, not enabled.";
      const btn = document.createElement("button");
      btn.textContent = "Set up…";
      btn.title = "Opens the schema-derived form; you confirm natively — the AI cannot apply config";
      btn.addEventListener("click", (e) => { e.stopPropagation(); openEnableForm(adapter); });
      hint.appendChild(btn);
      container.appendChild(hint);
    }

    // A tool result's refs are already pinned when some active pin cites all of
    // them — the same dedup the tracker's pin uses, so the display never mints
    // duplicate pins (the engine permits overlap; this is a UI guard).
    function refsAlreadyPinned(refs) {
      if (!refs || !refs.length) return false;
      return lastPins.some((x) => !x.superseded && refs.every((r) => (x.inputRefs || []).includes(r)));
    }
    function setResultPinInert(pin) {
      pin.textContent = "📌 pinned";
      pin.disabled = true;
      pin.classList.add("pinnedInert");
      pin.title = "Already in the pinned evidence — un-pin there to revise";
    }
    function setResultPinActive(pin) {
      pin.textContent = "📌 Pin";
      pin.disabled = false;
      pin.classList.remove("pinnedInert");
      pin.title = "Pin this result as evidence (cites all " + ((pin._refs || []).length) + " refs)";
    }
    // Re-evaluate every tool-result pin button against the current pins (called
    // when the pin fold refreshes) — BOTH ways: a result pinned from the chat
    // goes inert in place, and an un-pinned (superseded) one recovers, so a
    // button that outlives a chronicle rebuild never stays wrongly frozen.
    function syncResultPins() {
      for (const pin of document.querySelectorAll(".summaryPin")) {
        const pinned = refsAlreadyPinned(pin._refs);
        if (!pin.disabled && pinned) setResultPinInert(pin);
        else if (pin.disabled && !pinned) setResultPinActive(pin);
      }
    }

    // attachResultRefs puts a pin button on the row's summary (always visible)
    // and the citation chips in the expanded body. Shared by the live and the
    // reconstructed tool rows.
    function attachResultRefs(row, refs) {
      if (!refs || !refs.length) return;
      const pin = document.createElement("button");
      pin.className = "pincta summaryPin";
      pin._refs = refs;
      pin.textContent = "📌 Pin";
      pin.title = "Pin this result as evidence (cites all " + refs.length + " refs)";
      pin.addEventListener("click", (e) => {
        e.stopPropagation();       // don't toggle the disclosure
        e.preventDefault();
        if (pin.disabled) return;
        openPinDialog(refs);
      });
      if (refsAlreadyPinned(refs)) setResultPinInert(pin);
      row.querySelector("summary").appendChild(pin);

      const box = document.createElement("div");
      box.className = "toolrefs";
      for (const r of refs.slice(0, 12)) box.appendChild(refChip(r));
      row.appendChild(box);
    }

    // ---- event-time strip (13 §4 Timeline, minimal at v0) ------------------
    // Attacks are sequences, and event time is not investigation time (the two
    // clocks, binding §7): the thread is ordered by when we LEARNED things;
    // this strip orders the cited telemetry by when it HAPPENED. Each dot
    // opens its record — the 7-second anomaly should be visible, not buried.
    function renderEventStrip(items) {
      const wrap = $("stripWrap");
      if (!items || items.length < 2) {
        wrap.style.display = "none";
        return;
      }
      wrap.style.display = "";
      const t0 = Date.parse(items[0].time);
      const t1 = Date.parse(items[items.length - 1].time);
      const span = Math.max(1, t1 - t0);
      $("stripSummary").textContent =
        "Event time · " + items.length + " events over " + fmtSpan(span);
      const strip = $("strip");
      strip.textContent = "";
      for (const it of items) {
        const dot = document.createElement("span");
        dot.className = "evdot" + (it.label === "observed-data" ? " od" : "");
        dot.style.left = (((Date.parse(it.time) - t0) / span) * 100).toFixed(2) + "%";
        dot.title = it.label + " · " + new Date(it.time).toLocaleString() + " — open record";
        dot.addEventListener("click", () => vscode.postMessage({ type: "evidence.open", ref: it.ref }));
        strip.appendChild(dot);
      }
      const axis = $("stripAxis");
      axis.textContent = "";
      const a = document.createElement("span");
      a.textContent = new Date(t0).toLocaleString();
      const b = document.createElement("span");
      b.textContent = new Date(t1).toLocaleString();
      axis.append(a, b);
    }
    function fmtSpan(ms) {
      const s = Math.round(ms / 1000);
      if (s < 120) return s + "s";
      const m = Math.round(s / 60);
      if (m < 120) return m + "m";
      const h = Math.round(m / 60);
      if (h < 48) return h + "h";
      return Math.round(h / 24) + "d";
    }

    // ---- evidence graph (13 §7 step 7, minimal) ----------------------------
    // Two layers, left to right: interpretation-layer objects (STIX — reasoning
    // nodes and SCOs) → raw telemetry (OCSF). Acts are edges, not nodes (the
    // chronicle owns "what happened"): a produced object points at the evidence
    // it cites, plus the explicit observed-data → entity join — never
    // inference. Click any node to open its record. Richness is deferred to
    // v1; navigability is the v0 bar.
    const SVGNS = "http://www.w3.org/2000/svg";
    function svgEl(tag, attrs) {
      const el2 = document.createElementNS(SVGNS, tag);
      for (const k in attrs) el2.setAttribute(k, attrs[k]);
      return el2;
    }
    function renderGraph(msg) {
      const wrap = $("graphWrap");
      const box = $("graphBox");
      const refs = msg.refs || [], edges = msg.edges || [];
      if (!refs.length) {
        wrap.style.display = "none";
        return;
      }
      wrap.style.display = "";
      // Two layers, not three. The chronicle owns the acts (what happened, in
      // order); the graph owns the structure (what grounds what). Left =
      // interpretation-layer STIX objects (reasoning nodes + SCOs); right = raw
      // telemetry (OCSF). Unfetched refs classify by shape — a STIX id has the
      // "type--uuid" separator.
      const stix = refs.filter((r) => r.kind === "stix" || (r.kind === "" && r.id.includes("--")));
      const ocsf = refs.filter((r) => !stix.includes(r));
      const isReason = (r) => r.type === "x-hypothesis" || r.type === "x-prediction";

      // A reasoning object is grounded if it reaches ANY concrete evidence
      // (observed-data, an SCO, or telemetry) by following citations — even
      // through other reasoning objects. One that reaches nothing but its own
      // kind is floating on assertion: the alarm this graph exists to raise.
      const adj = {};
      for (const e of edges) (adj[e.from] = adj[e.from] || []).push(e.to);
      const reasonIds = new Set(stix.filter(isReason).map((r) => r.id));
      const grounded = (id) => {
        const seen = new Set([id]), stack = [id];
        while (stack.length) {
          for (const nxt of adj[stack.pop()] || []) {
            if (!reasonIds.has(nxt)) return true;
            if (!seen.has(nxt)) { seen.add(nxt); stack.push(nxt); }
          }
        }
        return false;
      };
      const ungrounded = new Set(
        stix.filter((r) => isReason(r) && !grounded(r.id)).map((r) => r.id));

      $("graphSummary").textContent = "Evidence graph · " + stix.length + " objects · "
        + ocsf.length + " events"
        + (ungrounded.size ? " · " + ungrounded.size + " ungrounded" : "");

      const ROW = 24, TOP = 22, NW = [252, 240], CX = [30, 360];
      const H = TOP + 10 + Math.max(stix.length, ocsf.length, 1) * ROW;
      const svg = svgEl("svg", { viewBox: "0 0 620 " + H, width: "100%" });

      const pos = {}; // node id → {x, y, w}
      const layNodes = (list, col, base, label) => {
        svg.appendChild(Object.assign(svgEl("text", { x: CX[col], y: 12, class: "gcol" }),
          { textContent: label }));
        list.forEach((n, i) => {
          const y = TOP + i * ROW;
          pos[n.id] = { x: CX[col], y: y + 8, w: NW[col] };
          let cls = "gnode " + (base === "stix" && isReason(n) ? "reason" : base);
          if (ungrounded.has(n.id)) cls += " ungrounded";
          const g = svgEl("g", { class: cls, transform: "translate(" + CX[col] + "," + y + ")" });
          g.appendChild(svgEl("rect", { width: NW[col], height: 17 }));
          const t = svgEl("text", { x: 5, y: 12 });
          t.textContent = nodeLabel(n);
          g.appendChild(t);
          g.addEventListener("click", () => vscode.postMessage({ type: "evidence.open", ref: n.id }));
          svg.appendChild(g);
        });
      };
      function nodeLabel(n) {
        const short = resolvedLabels[n.id] || (n.type + (n.id.includes("--") ? " " + n.id.slice(n.id.indexOf("--") + 2, n.id.indexOf("--") + 8) : ""));
        return short.length > 32 ? short.slice(0, 31) + "…" : short;
      }

      // Edges under the nodes: draw first.
      const eg = svgEl("g", {});
      svg.appendChild(eg);
      layNodes(stix, 0, "stix", "interpretation layer (stix)");
      layNodes(ocsf, 1, "ocsf", "telemetry (ocsf)");

      for (const e of edges) {
        const a = pos[e.from], b2 = pos[e.to];
        if (!a || !b2) continue;
        let d;
        if (a.x === b2.x) {
          // Intra-layer citation (e.g. hypothesis → observed-data, or the
          // observed-data → SCO join): route it as a lobe to the LEFT of the
          // column so it never crosses the STIX↔OCSF channel.
          const bx = a.x - 20;
          d = "M" + a.x + "," + a.y + " C" + bx + "," + a.y + " " + bx + "," + b2.y + " " + b2.x + "," + b2.y;
        } else {
          const x1 = a.x + a.w, mid = (x1 + b2.x) / 2;
          d = "M" + x1 + "," + a.y + " C" + mid + "," + a.y + " " + mid + "," + b2.y + " " + b2.x + "," + b2.y;
        }
        eg.appendChild(svgEl("path", {
          d,
          class: "gedge" + (e.join ? " join" : (e.ai ? "" : " human")),
        }));
      }
      box.textContent = "";
      box.appendChild(svg);
    }

    // ---- reasoning history: superseded by the interleaved chronicle -------
    // The old collapsed "how this investigation got here" fold rendered acts
    // in a separate surface; the chronicle (#restored) now interleaves them
    // with the turns in one reading order, so the fold is gone.

    // ---- cold restore: the committed conversation --------------------------
    // Transcripts are line-framed ([user]/[assistant]/[tool_use]/[tool_result]
    // records, one per line, content newlines escaped) and results carry the
    // FULL payloads — so reconstruction renders real coverage, refs, and
    // pinnable chips, not a summary. Rebuilt idempotently on every load;
    // entries past the first-load cutoff arrive as live turns instead.
    function unescapeT(s) {
      return String(s ?? "").replace(/\\\\n/g, "\\n").replace(/\\\\r/g, "\\r");
    }

    // The act types that render as compact chronicle lines (everything else is
    // either a full agent turn, rendered from its transcript, or an agent
    // sub-record — hypothesis/prediction — that already lives in the tracker).
    const CHRONICLE_ACTS = {
      "action-request":   { icon: "▹", verb: "requested" },
      "action-approval":  { icon: "✔", verb: "approved" },
      "action-rejection": { icon: "✕", verb: "rejected" },
      "action-dispatch":  { icon: "→", verb: "dispatched" },
      "action-result":    { icon: "●", verb: "" },
      "action-reversal":  { icon: "↺", verb: "reversed" },
      "action-expiry":    { icon: "⌛", verb: "expired" },
      "evidence-pin":     { icon: "📌", verb: "pinned" },
      "verdict":          { icon: "⚖", verb: "verdict" },
      "lifecycle":        { icon: "◆", verb: "" },
      "conclusion":       { icon: "■", verb: "concluded" },
    };

    function actLine(e) {
      const spec = CHRONICLE_ACTS[e.interpretationType];
      const row = document.createElement("div");
      row.className = "actline"
        + (e.actor.kind === "AI_DELEGATED" ? " ai" : "")
        + (e.interpretationType === "verdict" || e.interpretationType === "conclusion" ? " strong" : "")
        + (e.superseded ? " superseded" : "");

      const icon = document.createElement("span");
      icon.className = "acticon";
      icon.textContent = spec ? spec.icon : "·";
      row.appendChild(icon);

      const text = document.createElement("span");
      text.className = "acttext";
      // The interpretation's own summary is the authoritative description; the
      // verb prefixes it only when the summary doesn't already read as a phrase.
      text.textContent = e.summary || (spec ? spec.verb : e.interpretationType);
      row.appendChild(text);

      // A superseded act (e.g. a verdict a later one revised) stays in the
      // record, struck, tagged — the history reads as a revision, not a gap.
      if (e.superseded) {
        const tag = document.createElement("span");
        tag.className = "actsuperseded";
        tag.textContent = "superseded";
        row.appendChild(tag);
      }

      // Any cited refs stay clickable — the chronicle is a working lens, not a
      // dead log (02 §2.8). Kept to a couple so the line stays a line.
      const refs = [];
      for (const r of (e.inputRefs || []).concat(e.outputRefs || [])) {
        if (r && !refs.includes(r)) refs.push(r);
      }
      for (const r of refs.slice(0, 2)) row.appendChild(refChip(r));

      const when = document.createElement("span");
      when.className = "acttime";
      when.textContent = e.occurredAt ? new Date(e.occurredAt).toLocaleTimeString() : "";
      row.appendChild(when);
      return row;
    }

    // Render the committed chronicle into #restored: the whole thread in
    // sequence order, transcript-bearing entries as full turns, act-typed
    // entries as one-line entries, and a transcript-bearing entry whose body is
    // NOT loaded (older than the fetch window, or its transcript fetch failed)
    // as a compact fallback line that opens the transcript on demand — early
    // history must never silently vanish from the reading surface. When no turn
    // is streaming (and no failed turn's live copy is being preserved), the
    // live #conversation has all been committed into this chronicle: clear it.
    function renderChronicle() {
      const box = $("restored");
      box.textContent = "";
      const entries = (lastThread || []).slice().sort((a, b) => a.sequenceNo - b.sequenceNo);
      for (const e of entries) {
        const body = restoredBodies.get(e.sequenceNo);
        // A context reset is a BOUNDARY, not a line: everything above it is
        // narration the agent no longer holds; below it the agent reasons from
        // the engine record. The analyst must see the break to judge which
        // statements predate the re-grounding. (Prefix contract shared with
        // the agent's rehydrate marker — keep in lockstep.)
        if (e.summary && e.summary.indexOf("context reset:") === 0) {
          const hr = document.createElement("div");
          hr.className = "ctxreset";
          const when = e.occurredAt ? " · " + new Date(e.occurredAt).toLocaleTimeString() : "";
          hr.textContent = "⟲ context reset — agent re-grounded from the investigation record" + when;
          box.appendChild(hr);
          continue;
        }
        if (body) {
          box.appendChild(restoredTurn({ sequenceNo: e.sequenceNo, occurredAt: e.occurredAt, body: body.body }));
          appendSopChips(box, e);
        } else if (CHRONICLE_ACTS[e.interpretationType]) {
          box.appendChild(actLine(e));
        } else if (e.hasTranscript) {
          box.appendChild(turnStub(e));
        }
      }
      if (!streaming && !preserveLive) conversation.textContent = "";
    }

    // Knowledge-retrieval provenance (ui/02 §2.11): which SOPs the turn pulled,
    // followed (solid) vs merely consulted (dashed). Rides under the turn.
    function appendSopChips(box, e) {
      const sops = e.consultedSops || [];
      const similar = e.consultedSimilar || [];
      if (!sops.length && !similar.length) return;
      const row = document.createElement("div");
      row.className = "usage";
      for (const s of sops) {
        const chip = document.createElement("span");
        chip.className = "sopchip" + (s.used ? "" : " consulted");
        chip.textContent = (s.used ? "followed: " : "consulted: ") + (s.title || s.sopId);
        row.appendChild(chip);
      }
      // Similar-investigation provenance (K4, 06 §6): prior cases the turn drew
      // on. Same solid/dashed used-vs-consulted convention as SOP chips.
      for (const s of similar) {
        const chip = document.createElement("span");
        chip.className = "sopchip" + (s.used ? "" : " consulted");
        chip.textContent = (s.used ? "drew on case: " : "similar case: ") + (s.title || s.investigationRef);
        row.appendChild(chip);
      }
      box.appendChild(row);
    }

    // A committed turn whose transcript body isn't loaded: one line carrying the
    // act's own summary, clickable to open the full transcript in an editor.
    function turnStub(e) {
      const row = document.createElement("div");
      row.className = "actline turnstub" + (e.actor.kind === "AI_DELEGATED" ? " ai" : "");
      const icon = document.createElement("span");
      icon.className = "acticon";
      icon.textContent = "…";
      row.appendChild(icon);
      const text = document.createElement("span");
      text.className = "acttext";
      text.textContent = (e.summary || "committed turn") + " — open transcript";
      row.appendChild(text);
      const when = document.createElement("span");
      when.className = "acttime";
      when.textContent = e.occurredAt ? new Date(e.occurredAt).toLocaleTimeString() : "";
      row.appendChild(when);
      row.style.cursor = "pointer";
      row.addEventListener("click", () => vscode.postMessage({ type: "transcript.open", interpretationId: e.interpretationId }));
      return row;
    }

    function restoredTurn(t) {
      const wrap = document.createElement("div");
      const hdr = document.createElement("div");
      hdr.className = "usage";
      hdr.textContent = (t.occurredAt ? new Date(t.occurredAt).toLocaleString() + " · " : "") + "committed turn";
      wrap.appendChild(hdr);

      // An aside turn (the ⚡ marker on its user line) reconstructs COLLAPSED —
      // the same record, the same quieter lens it had live.
      let wasAside = false;
      let asideLabel = "⚡ aside";

      const rows = new Map(); // tool call id → row, for result matching
      for (const line of String(t.body).split("\\n")) {
        let m;
        if ((m = line.match(/^\\[user\\] ([^]*)$/))) {
          const utext = unescapeT(m[1]);
          if (utext.indexOf("⚡ ") === 0) {
            wasAside = true;
            const colon = utext.indexOf(":");
            asideLabel = (colon > 0 && colon < 40 ? utext.slice(0, colon) : utext.slice(0, 24)).toLowerCase();
          }
          const u = document.createElement("div");
          u.className = "msg user";
          const b = document.createElement("span");
          b.className = "bubble";
          b.textContent = utext;
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
      if (wasAside) {
        const det = document.createElement("details");
        det.className = "aside";
        const sum = document.createElement("summary");
        sum.textContent = asideLabel + " · committed aside"
          + (t.occurredAt ? " · " + new Date(t.occurredAt).toLocaleString() : "");
        det.append(sum, wrap);
        return det;
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
      // comms thread states (ui/04 §4.2)
      AWAITING_REPLY: "warn", REPLIED: "ok", FOLLOWED_UP: "warn",
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

    // Frame your own hypothesis — the competing-explanation move. Analyst-
    // authored ones land OPEN (no acknowledgment step: that exists only for
    // AI proposals); the tracker then scores the alternates side by side.
    $("hypNew").addEventListener("click", () => openPrompt({
      title: "New hypothesis",
      label: "The claim to test — often the ALTERNATE explanation",
      placeholder: "e.g. The svc_backup RDP logon was legitimate maintenance by the backup team, not lateral movement.",
      helper: "Recorded as yours, OPEN immediately. Then hit “Propose tests” on it — competing hypotheses are decided by evidence, not argument.",
      confirm: "Record hypothesis",
      onConfirm: (statement) => vscode.postMessage({ type: "hyp.new", statement }),
    }));

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

      for (const h of hs) {
        const card = document.createElement("div");
        card.className = "card";
        const head = document.createElement("div");
        head.className = "hyphead";
        const st = document.createElement("span");
        st.className = "statement clamp c4";
        st.textContent = h.statement;
        st.title = h.statement;
        st.addEventListener("click", () => st.classList.toggle("expanded"));
        const badge = document.createElement("span");
        badge.className = badgeClass(h.status);
        badge.textContent = h.status;
        head.append(st, badge);
        card.appendChild(head);

        const preds = h.predictions || [];
        const live = h.status === "PROPOSED" || h.status === "OPEN";
        const hasUntested = preds.some((p) => p.status === "UNTESTED");
        const decide = document.createElement("div");
        decide.className = "decide";
        if (h.status === "PROPOSED") {
          const ack = document.createElement("button");
          ack.className = "primary";
          ack.textContent = "✓ Acknowledge";
          ack.title = "Take ownership of this AI-proposed line of inquiry (PROPOSED → OPEN). A human act — the engine refuses it from the AI.";
          ack.addEventListener("click", () => {
            ack.disabled = true;
            vscode.postMessage({ type: "hyp.ack", hypothesisRef: h.id });
          });
          decide.appendChild(ack);
        }
        // The drive affordance (02 §2.9) follows the state of the work — one
        // rung at a time. PROPOSED: the only decision is ownership
        // (Acknowledge). OPEN with no predictions: Propose tests. Untested
        // predictions remain: Run tests (independent → parallel; per-row
        // Test this runs just one). All decided: Decide — record the
        // hypothesis outcome from the evidence (terminal in v0: a changed
        // judgment later is a NEW hypothesis chained via parent_ref).
        if (h.status === "OPEN") {
          const mkAside = (label, working, title, type) => {
            const b = document.createElement("button");
            b.className = "askdecide";
            b.textContent = label;
            b.title = title;
            b.addEventListener("click", () => {
              if (sendBtn.disabled) return; // a turn is already running
              b.disabled = true;
              b.textContent = working;
              vscode.postMessage({ type, hypothesisRef: h.id, statement: h.statement });
            });
            decide.appendChild(b);
          };
          if (!preds.length) {
            mkAside("⚡ Propose tests", "⚡ proposing…",
              "Runs a scoped agent turn: record the falsifiable predictions that would decide this. Lands as a collapsed aside; predictions appear here.",
              "hyp.proposeTests");
          } else if (hasUntested) {
            mkAside("⚡ Run tests", "⚡ testing…",
              "Runs the untested predictions — they are independent, so they run in parallel where possible. Outcomes and evidence land back on these rows.",
              "hyp.runTests");
          } else {
            mkAside("⚡ Decide", "⚡ deciding…",
              "Weighs the tested predictions and records the hypothesis outcome (supported / refuted / inconclusive) citing the decisive evidence. Terminal in v0 — a later change of judgment is a new hypothesis.",
              "hyp.decide");
          }
        }
        if (decide.childElementCount) card.appendChild(decide);
        if (preds.length) {
          const ul = document.createElement("ul");
          ul.className = "predictions";
          for (const p of preds) {
            // Predictions are INDEPENDENT, parallel-testable claims — every
            // row renders as an equal peer; no implied ordering.
            const li = document.createElement("li");
            const ptext = document.createElement("span");
            ptext.className = "clamp c2";
            ptext.textContent = p.statement;
            ptext.title = p.statement;
            ptext.addEventListener("click", () => ptext.classList.toggle("expanded"));
            li.appendChild(ptext);

            // One structured controls row per prediction: status badge, then
            // evidence chips, action anchored at the right edge — the same
            // place on every row, never wherever the text happened to wrap.
            const row = document.createElement("div");
            row.className = "predrow";
            const pbadge = document.createElement("span");
            pbadge.className = badgeClass(p.status);
            pbadge.textContent = p.status;
            row.appendChild(pbadge);
            // The decisive outcomes cite what was observed — every test-result
            // ref opens (02 §2.8).
            const trefs = p.testResultRefs || [];
            for (const r of trefs) row.appendChild(refChip(r));
            if (p.status === "UNTESTED") {
              const test = document.createElement("button");
              test.className = "testbtn predact";
              test.textContent = "Test this";
              test.title = p.testQuery && p.testQuery.queryText
                ? "Stage just this test in the composer: " + p.testQuery.queryText
                : "Stage a test of just this prediction in the composer";
              test.addEventListener("click", () => stageInComposer(predictionTestText(p)));
              row.appendChild(test);
            } else if (trefs.length) {
              // A decided prediction is pinnable: statement + outcome + its
              // citations, prefilled. The pin cites the PREDICTION NODE too,
              // so an active pin is detectable and the affordance goes inert
              // instead of minting duplicates (un-pin brings it back —
              // supersession, not deletion).
              const alreadyPinned = lastPins.some((x) => !x.superseded && (
                (x.inputRefs || []).includes(p.id) ||
                trefs.every((r) => (x.inputRefs || []).includes(r))));
              const pin = document.createElement("button");
              pin.className = "pincta testbtn predact";
              if (alreadyPinned) {
                pin.textContent = "📌 pinned";
                pin.disabled = true;
                pin.title = "Already in the pinned evidence — un-pin there to revise";
              } else {
                pin.textContent = "📌 Pin";
                pin.title = "Pin this decided prediction + its test evidence (feeds the verdict gate)";
                pin.addEventListener("click", () =>
                  openPinDialog([p.id].concat(trefs), "[" + p.status + "] " + p.statement));
              }
              row.appendChild(pin);
            }
            li.appendChild(row);
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
        // Installed-not-enabled (11 §6.2): the operator-facing affordance on
        // the health row itself — the agent's tool surface never sees it.
        if (c.status === "unavailable" && lastEnablement) {
          const ev = (lastEnablement.verbs || []).find((x) => x.verb === c.verb);
          if (ev && !ev.enabled && (ev.closableBy || []).length) {
            const setup = document.createElement("button");
            setup.className = "setup";
            setup.textContent = "set up";
            setup.title = ev.closableBy[0] + " is installed but not enabled — enable it to serve " + c.verb;
            setup.addEventListener("click", () => openEnableForm(ev.closableBy[0]));
            row.appendChild(setup);
          }
        }
        box.appendChild(row);
      }
    }

    // ---- the enablement form (11 §5.1) -------------------------------------
    // Schema-derived, extension-rendered. Prefills are visible and editable —
    // a prefill is a suggestion, not a value. Secrets never get a field here:
    // they are captured through the HOST's secure input after the native
    // confirm, and what is captured is a secret REFERENCE.
    let enableCtx = null; // { adapter, inputs: {field: el}, secretFields }
    function openEnableForm(adapterName) {
      if (!lastEnablement) return;
      const a = (lastEnablement.adapters || []).find((x) => x.name === adapterName);
      if (!a) return;
      if (!a.supportable) return; // no affordance for classes v0 cannot spawn
      $("enableTitle").textContent = (a.enabled ? "Configure " : "Enable ") + a.name;
      $("enableIntro").textContent = "Class " + a.class + ". Applying edits the tenant config file (the source of truth) and is recorded with your identity. You confirm in a native dialog next.";
      const box = $("enableFields");
      box.textContent = "";
      const inputs = {};
      const secretFields = [];
      const prefill = { scenario: a.scenario || "" };
      for (const name in (a.configFields || {})) {
        const f = a.configFields[name];
        const wrap = document.createElement("div");
        wrap.className = "field";
        if (f.secret) {
          secretFields.push(name);
          const note = document.createElement("div");
          note.className = "secretnote";
          note.textContent = name + ": secret — captured via secure input when you apply (a keychain:// / env:// / vault:// reference, never the value, never in this conversation)";
          wrap.appendChild(note);
        } else {
          const label = document.createElement("label");
          label.textContent = name + ((a.requiredFields || []).includes(name) ? " (required)" : "");
          const input = document.createElement("input");
          input.type = "text";
          input.value = prefill[name] !== undefined ? prefill[name] : "";
          inputs[name] = input;
          wrap.append(label, input);
          if (f.description) {
            const d = document.createElement("div");
            d.className = "fdesc";
            d.textContent = f.description;
            wrap.appendChild(d);
          }
        }
        box.appendChild(wrap);
      }
      $("enableConfirm").textContent = a.enabled ? "Apply changes" : "Enable " + a.name;
      enableCtx = { adapter: a.name, inputs, secretFields, enabled: a.enabled };
      $("enableDialog").style.display = "flex";
    }
    function closeEnableForm() { $("enableDialog").style.display = "none"; enableCtx = null; }
    $("enableCancel").addEventListener("click", closeEnableForm);
    $("enableConfirm").addEventListener("click", () => {
      if (!enableCtx) return;
      const config = {};
      for (const name in enableCtx.inputs) {
        const v = enableCtx.inputs[name].value.trim();
        if (v !== "") config[name] = v;
      }
      vscode.postMessage({
        type: "enablement.apply",
        adapter: enableCtx.adapter,
        enabled: true,
        config,
        secretFields: enableCtx.secretFields,
      });
      closeEnableForm();
    });

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

    // ---- comms threads (Phase F, ui/04) ------------------------------------
    // Every card is conversation state that FOLLOWED an approved, dispatched
    // notify.* action — nothing here sends anything; Follow up requests a new
    // action that lands in the approval queue.
    let lastComms = [];
    function renderComms(threads) {
      lastComms = threads || [];
      const box = $("commsBox");
      $("commsSection").style.display = lastComms.length ? "" : "none";
      const open = lastComms.filter((t) => t.status === "awaiting_reply" || t.status === "followed_up").length;
      $("commsHead").textContent = "External work" + (lastComms.length ? " · " + open + " open" : "");
      box.textContent = "";
      for (const t of lastComms) {
        const card = document.createElement("div");
        card.className = "card commscard" + (t.status === "replied" ? " replied" : "");
        if (t.status === "closed") card.style.opacity = "0.7";

        const head = document.createElement("div");
        const target = document.createElement("span");
        target.className = "statement";
        target.textContent = (t.actionType === "notify.email" ? "✉ " : "# ") + t.target;
        const st = document.createElement("span");
        st.className = badgeClass(t.status.toUpperCase());
        st.textContent = t.status.replace("_", " ");
        head.append(target, st);
        card.appendChild(head);

        if (t.subject) {
          const subj = document.createElement("div");
          subj.className = "cardmeta";
          subj.textContent = t.subject;
          card.appendChild(subj);
        }

        // The last trail entry, quoted — inbound reads green (a reply).
        const last = (t.trail || [])[t.trail.length - 1];
        if (last) {
          const q = document.createElement("div");
          q.className = "quote" + (last.direction === "inbound" ? " inbound" : "");
          q.textContent = (last.direction === "inbound" ? "↩ " : "") + last.author + ": " + last.body;
          card.appendChild(q);
        }

        const meta = document.createElement("div");
        meta.className = "cardmeta";
        const bits = ["sent " + new Date(t.sentAt).toLocaleString()];
        if (t.followUpHours) bits.push("follow-up " + t.followUpHours + "h · " + t.followUps + " sent");
        if (t.followUpDue) bits.push("⏰ follow-up due");
        meta.textContent = bits.join(" · ");
        card.appendChild(meta);

        if (t.escalationTriggered) {
          const esc3 = document.createElement("div");
          esc3.className = "esc";
          esc3.textContent = "⚠ Escalation policy triggered (" + (t.escalationPolicy || "") + ") — repeated follow-ups, no resolution. Consider escalating; nothing auto-fires.";
          card.appendChild(esc3);
        }

        const acts = document.createElement("div");
        acts.className = "decide";
        const openThread = t.status === "awaiting_reply" || t.status === "followed_up" || t.status === "replied";
        if (t.unackedReply) {
          const ack = document.createElement("button");
          ack.className = "primary";
          ack.textContent = "Acknowledge";
          ack.title = "Record that you saw the reply (kept on the trail)";
          ack.addEventListener("click", () => vscode.postMessage({ type: "comms.act", threadId: t.threadId, verb: "ack" }));
          acts.appendChild(ack);
        }
        if (openThread) {
          const fu = document.createElement("button");
          if (t.followUpDue && !t.unackedReply) fu.className = "primary";
          fu.textContent = "Follow up…";
          fu.title = "Drafts a follow-up message — it becomes a new action you approve before anything is sent";
          fu.addEventListener("click", () => openPrompt({
            title: "Follow up — " + t.target,
            label: "The follow-up message (you approve before it sends)",
            placeholder: "Any update on this? Still needed for the investigation.",
            helper: "Requests a new " + t.actionType + " action carrying this thread's lineage; it lands in the approval queue as a preview.",
            confirm: "Request follow-up",
            onConfirm: (message) => vscode.postMessage({
              type: "comms.followup", threadId: t.threadId, actionType: t.actionType,
              target: t.target, subject: t.subject || "", message, followUpHours: t.followUpHours,
            }),
          }));
          acts.appendChild(fu);
          if (t.followUpDue) {
            const sn = document.createElement("button");
            sn.textContent = "Snooze 24h";
            sn.addEventListener("click", () => vscode.postMessage({ type: "comms.snooze", threadId: t.threadId, hours: 24 }));
            acts.appendChild(sn);
          }
          const done = document.createElement("button");
          done.textContent = "Mark done";
          done.title = "The external work is resolved — closes the thread";
          done.addEventListener("click", () => vscode.postMessage({ type: "comms.act", threadId: t.threadId, verb: "done" }));
          acts.appendChild(done);
        }
        if (acts.childElementCount) card.appendChild(acts);
        box.appendChild(card);
      }
    }

    // The action queue: rows are DOM-built (action_type/targets are
    // model-influenced — no innerHTML for them), each with Approve/Reject
    // posting to the host, which does the real call on the human token.
    // The status badge for a settled or in-flight action: label + colour class.
    // Pending rows keep their approval vocabulary; the rest map the engine's
    // lifecycle status to an outcome colour.
    function actionStatusBadge(a) {
      if (a.pending) return { label: a.pendingLabel || "PENDING", cls: "warn" };
      switch (a.status) {
        case "SUCCEEDED": return { label: "SUCCEEDED", cls: "ok" };
        case "PARTIAL":   return { label: "PARTIAL", cls: "warn" };
        case "FAILED":    return { label: "FAILED", cls: "bad" };
        case "TIMEOUT":   return { label: "TIMEOUT", cls: "bad" };
        case "REVERSED":  return { label: "REVERSED", cls: "info" };
        case "REJECTED":  return { label: "REJECTED", cls: "" };
        case "EXPIRED":   return { label: "EXPIRED", cls: "warn" };
        case "APPROVED":  return { label: "APPROVED", cls: "info" };
        case "EXECUTING": return { label: "DISPATCHING", cls: "info" };
        default:          return { label: a.status || "—", cls: "" };
      }
    }

    // The action ledger (rail): every action on this investigation, newest
    // first, with where it landed. Completed actions vanish from the "Needs
    // your approval" interrupt — this is where they persist. Read-only: the
    // approval affordances stay in the interrupt and the chat, so the ledger
    // never becomes a second, competing place to act.
    function renderActions(actions) {
      const all = actions || [];
      const box = $("actionsBox");
      $("actionsSection").style.display = all.length ? "" : "none";
      $("actionsHead").textContent = all.length ? "Actions · " + all.length : "Actions";
      box.textContent = "";
      if (!all.length) return;
      for (const a of all.slice().reverse()) {
        const row = document.createElement("div");
        row.className = "actrow " + (a.pending ? "pend" : "settled");

        const top = document.createElement("div");
        top.className = "artop";
        const name = document.createElement("span");
        name.className = "atype";
        // A reversal action is marked as such — host.unisolate undoing an
        // isolate must not read like a first-order act.
        name.textContent = (a.isReversal ? "↺ " : "") + a.actionType;
        const tier = document.createElement("span");
        tier.className = "badge " + a.tier;
        tier.textContent = a.tier;
        const sb = actionStatusBadge(a);
        const st = document.createElement("span");
        st.className = "badge " + sb.cls;
        st.textContent = sb.label;
        top.append(name, tier, st);

        const tgt = document.createElement("div");
        tgt.className = "artgt";
        tgt.textContent = "→ " + (a.targets || []).join(", ");
        row.append(top, tgt);

        // Write-side provenance: WHICH tool dispatched it (set once executing),
        // and the operational reference it returned (e.g. the INC number) —
        // the analyst's handle into the external system of record.
        if (a.adapter) {
          const via = document.createElement("div");
          via.className = "armeta via";
          via.textContent = "via " + a.adapter + (a.resultRef ? " → " + a.resultRef : "");
          row.append(via);
        }

        // Reversal lineage / classification, stated honestly for the record.
        if (a.status === "REVERSED") {
          const m = document.createElement("div");
          m.className = "armeta";
          m.textContent = "↺ reversed";
          row.append(m);
        } else if (a.status === "SUCCEEDED" && a.reversibility === "BEST_EFFORT") {
          const m = document.createElement("div");
          m.className = "armeta";
          m.textContent = "↩? best-effort — cannot be verified undone";
          row.append(m);
        }
        if (a.tierEscalated) {
          const m = document.createElement("div");
          m.className = "armeta";
          m.textContent = "⚠ escalated to " + a.tier + " (blast radius)";
          row.append(m);
        }
        // Why a FAILED action failed — the honest reason, not a bare badge.
        if (a.errorDetail && (a.status === "FAILED" || a.status === "TIMEOUT" || a.status === "PARTIAL")) {
          const e = document.createElement("div");
          e.className = "armeta err";
          e.textContent = "✗ " + a.errorDetail;
          row.append(e);
        }

        box.appendChild(row);
      }
    }

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

        // Pre-approval provenance (08 §4): which tool WILL execute this if
        // approved now — so the analyst confirms the destination system of
        // record (e.g. servicenow, not a fixture) BEFORE committing.
        if (a.plannedAdapter) {
          const via = document.createElement("div");
          via.className = "cardmeta via";
          via.textContent = "⇒ will dispatch via " + a.plannedAdapter;
          row.append(via);
        }

        // The mandatory pre-send preview (binding §4): approving a notify.*
        // action IS sending the message, so the approver sees exactly what
        // will go out — subject and body verbatim from the frozen request.
        if (a.actionType && a.actionType.indexOf("notify.") === 0 && a.parameters) {
          const p = a.parameters;
          const prev = document.createElement("div");
          prev.className = "sendpreview";
          if (typeof p.subject === "string" && p.subject) {
            const s = document.createElement("div");
            s.className = "subj";
            s.textContent = p.subject;
            prev.appendChild(s);
          }
          const bodyText = typeof p.message === "string" && p.message ? p.message
            : typeof p.body === "string" ? p.body : "";
          prev.appendChild(document.createTextNode(bodyText));
          row.append(prev);
          if (typeof p.thread_ref === "string" && p.thread_ref) {
            const fu2 = document.createElement("div");
            fu2.className = "cardmeta";
            fu2.textContent = "↻ follow-up on an existing thread";
            row.append(fu2);
          }
        }

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
          // Invisible activate (01 §Extension 2): any pending action on a DRAFT
          // investigation is its first action on the world, and approving it is
          // the activation moment — surface that so the transition is understood,
          // not silent.
          if (($("state").dataset.engine || "") === "DRAFT") {
            const note = document.createElement("div");
            note.className = "cardmeta actnote";
            note.textContent = "First action on the world — approving activates the investigation.";
            row.append(note);
          }
          const decide = document.createElement("div");
          decide.className = "decide";
          const isNotify = a.actionType && a.actionType.indexOf("notify.") === 0;
          const ok = document.createElement("button");
          ok.className = "primary";
          ok.textContent = a.tier === "T3" ? "Approve (challenge)…" : isNotify ? "Approve · Send" : "Approve";
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
    $("exportBtn").addEventListener("click", () => vscode.postMessage({ type: "export.open" }));

    // ---- the seed chip: the investigation's root, at the document head ------
    function seedTypeLabel(ref) {
      const t = String(ref || "").split("--")[0];
      if (t === "x-host") return "host";
      if (t === "ipv4-addr" || t === "ipv6-addr") return "IP";
      if (t === "file") return "file";
      if (t === "user-account") return "account";
      if (t === "domain-name") return "domain";
      return "entity";
    }
    function renderSeedChip(seed) {
      const el = $("seedChip");
      if (!seed || !seed.type) { el.style.display = "none"; el.innerHTML = ""; return; }
      let html = "";
      if (seed.type === "entity") {
        const label = seedTypeLabel(seed.entityRef);
        const who = seed.entityIdentifier || seed.entityRef || "";
        html = "Investigating " + label + " <b>" + esc(who) + "</b>";
      } else if (seed.type === "question") {
        html = "Hunting — <b>" + esc(seed.hypothesisStatement || "") + "</b>";
      } else if (seed.type === "alert") {
        const src = seed.source ? esc(seed.source) + ": " : "";
        html = "From alert <b>" + src + esc(seed.alertId || "") + "</b>";
      } else if (seed.type === "case") {
        const src = seed.source ? esc(seed.source) + ": " : "";
        html = "From case <b>" + src + esc(seed.caseId || "") + "</b>";
      }
      el.innerHTML = html;
      el.style.display = html ? "" : "none";
    }

    // ---- the unseeded (draft) state: root this investigation ---------------
    // Two rules, mirrored from the server so the live hint matches what will be
    // persisted: whitespace or a trailing "?" is a question; anything else is an
    // entity (a host/IP/hash). The entity sub-label is cosmetic — the server
    // mints the id.
    let draftOverride = null; // "entity" | "question" when the analyst corrects
    function classifyDraft(v) {
      const s = v.trim();
      if (!s) return "";
      if (/\\s/.test(s) || s.endsWith("?")) return "question";
      return "entity";
    }
    function entitySubLabel(v) {
      if (/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(v) || v.includes(":")) return "IP";
      if (/^[0-9a-fA-F]+$/.test(v) && (v.length === 32 || v.length === 40 || v.length === 64)) return "file";
      return "host";
    }
    function effectiveDraftKind(v) {
      const inferred = classifyDraft(v);
      if (!inferred) return "";
      return draftOverride || inferred;
    }
    function renderDraftInterp() {
      const v = $("draftInput").value.trim();
      const interp = $("draftInterp");
      $("draftStart").disabled = v === "";
      if (!v) { interp.innerHTML = ""; return; }
      const kind = effectiveDraftKind(v);
      const singleToken = !/\\s/.test(v) && !v.endsWith("?");
      if (kind === "entity") {
        interp.innerHTML = "→ investigate " + entitySubLabel(v) + " <b>" + esc(v) + "</b>"
          + '<span class="toggle" id="draftToQuestion">hunt this as a question instead</span>';
        const t = $("draftToQuestion");
        if (t) t.onclick = () => { draftOverride = "question"; renderDraftInterp(); };
      } else {
        interp.innerHTML = "→ a hunt (open question)"
          + (singleToken ? '<span class="toggle" id="draftToEntity">investigate a specific host/IP instead</span>' : "");
        const t = $("draftToEntity");
        if (t) t.onclick = () => { draftOverride = "entity"; renderDraftInterp(); };
      }
    }
    // One submit per draft: the Enter path bypasses the disabled button, so an
    // explicit in-flight flag guards both — a double Enter must never mint two
    // investigations. Cleared on error (retry) and on a fresh draft.
    let draftSubmitting = false;
    function showDraft(mode) {
      draftOverride = null;
      draftSubmitting = false;
      $("draftView").style.display = "flex";
      $("draftInput").value = "";
      $("draftErr").textContent = "";
      $("draftInterp").innerHTML = "";
      $("draftAlertForm").style.display = "none";
      $("draftCaseForm").style.display = "none";
      $("draftCaseFilter").value = "";
      $("draftCaseResults").innerHTML = "";
      $("draftCaseStatus").textContent = "";
      $("draftStart").disabled = true;
      // reckon.seedFromCase opens the draft straight into the case search.
      if (mode === "case") { toggleCaseForm(true); } else { $("draftInput").focus(); }
    }
    function hideDraft() { $("draftView").style.display = "none"; }
    function submitDraft() {
      const v = $("draftInput").value.trim();
      if (!v || draftSubmitting) return;
      draftSubmitting = true;
      $("draftStart").disabled = true;
      $("draftErr").textContent = "";
      vscode.postMessage({ type: "seed.submit", value: v, kind: effectiveDraftKind(v) });
    }
    $("draftInput").addEventListener("input", () => { draftOverride = null; renderDraftInterp(); });
    $("draftInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submitDraft(); }
    });
    $("draftStart").addEventListener("click", submitDraft);
    $("draftAlertToggle").addEventListener("click", () => {
      const f = $("draftAlertForm");
      f.style.display = f.style.display === "none" ? "flex" : "none";
      if (f.style.display === "flex") { $("draftCaseForm").style.display = "none"; $("draftAlertId").focus(); }
    });
    function alertReady() {
      $("draftAlertStart").disabled = !($("draftAlertId").value.trim() && $("draftAlertSource").value.trim());
    }
    $("draftAlertId").addEventListener("input", alertReady);
    $("draftAlertSource").addEventListener("input", alertReady);
    $("draftAlertStart").addEventListener("click", () => {
      const alertId = $("draftAlertId").value.trim(), source = $("draftAlertSource").value.trim();
      if (!alertId || !source || draftSubmitting) return;
      draftSubmitting = true;
      $("draftAlertStart").disabled = true;
      vscode.postMessage({ type: "seed.alert", alertId, source });
    });

    // ---- the "from a case" path (14 §4.1): search the case system of record
    // and pick, all on this surface — the filter is a field here, never the
    // top-of-window quick input (workbench discipline, 13 §3). The pick fails
    // closed server-side, so a bad case never seeds a half-loaded investigation.
    function toggleCaseForm(force) {
      const f = $("draftCaseForm");
      const show = force !== undefined ? force : f.style.display === "none";
      f.style.display = show ? "flex" : "none";
      if (show) { $("draftAlertForm").style.display = "none"; $("draftCaseFilter").focus(); }
    }
    function submitCaseSearch() {
      $("draftCaseStatus").textContent = "Searching the case system of record…";
      $("draftCaseResults").innerHTML = "";
      vscode.postMessage({ type: "seed.caseSearch", filter: $("draftCaseFilter").value });
    }
    function renderCases(cases) {
      const box = $("draftCaseResults");
      box.innerHTML = "";
      if (!cases.length) {
        $("draftCaseStatus").textContent = "No matching cases in the system of record.";
        return;
      }
      $("draftCaseStatus").textContent =
        cases.length + " case" + (cases.length === 1 ? "" : "s") + " — pick one to investigate.";
      for (const c of cases) {
        const row = document.createElement("button");
        row.className = "caseRow";
        row.innerHTML = '<span class="caseNum">' + esc(c.number) + "</span>"
          + '<span class="caseStatus">' + esc(c.status || "") + "</span>"
          + '<span class="caseTitle">' + esc(c.title || "") + "</span>";
        row.addEventListener("click", () => {
          if (draftSubmitting) return;
          draftSubmitting = true;
          $("draftCaseStatus").textContent = "Seeding from " + c.number + "…";
          vscode.postMessage({ type: "seed.case", caseNumber: c.number });
        });
        box.appendChild(row);
      }
    }
    $("draftCaseToggle").addEventListener("click", () => toggleCaseForm());
    $("draftCaseSearchBtn").addEventListener("click", submitCaseSearch);
    $("draftCaseFilter").addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); submitCaseSearch(); }
    });

    // ---- resizable rail ----------------------------------------------------
    // Drag the grip to size the rail; the width persists in webview state so
    // a reload (and retainContextWhenHidden round-trips) keep it.
    (function () {
      const saved = vscode.getState();
      if (saved && Number.isFinite(saved.railW)) {
        document.documentElement.style.setProperty("--rail-w", saved.railW + "px");
      }
      const grip = $("railGrip");
      let dragging = false;
      grip.addEventListener("pointerdown", (e) => {
        dragging = true;
        document.body.classList.add("railDragging");
        grip.setPointerCapture(e.pointerId);
        e.preventDefault();
      });
      grip.addEventListener("pointermove", (e) => {
        if (!dragging) return;
        const w = Math.min(Math.max(window.innerWidth - e.clientX, 200), Math.floor(window.innerWidth * 0.6));
        document.documentElement.style.setProperty("--rail-w", w + "px");
      });
      grip.addEventListener("pointerup", (e) => {
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove("railDragging");
        grip.releasePointerCapture(e.pointerId);
        const w = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--rail-w"), 10);
        if (Number.isFinite(w)) vscode.setState({ ...(vscode.getState() || {}), railW: w });
      });
    })();

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
      input.value = opts.value || "";
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
      confirm.disabled = promptRequire && input.value.trim() === "";
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
    // suggested prefills the finding (visible and editable — a suggestion,
    // never a silently-applied value).
    function openPinDialog(refs, suggested) {
      openPrompt({
        title: "Pin as evidence",
        label: "What does this evidence show?",
        placeholder: "e.g. First external egress from the svc_backup source host, 15s after the encoded PowerShell",
        helper: "Recorded on the investigation thread and cited by your verdict.",
        confirm: "📌 Pin evidence",
        refs: refs || [],
        value: suggested || "",
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
    // In-place rename, like a file rename: the title becomes an editable field
    // right where it sits. Enter commits, Escape cancels, blur commits. The host
    // applies it and echoes "renamed" to update the title text. Guarded on
    // closed records for EVERY entry point (pencil, dblclick, tree) — the
    // engine refuses a rename on concluded/archived, so no path may offer one.
    function startInlineRename(prefill) {
      if (conversationClosed) return;
      const inp = $("titleEdit");
      if (inp.style.display !== "none") return; // already editing
      inp.value = prefill || CUR_TITLE;
      $("title").style.display = "none";
      $("renameBtn").style.display = "none";
      inp.style.display = "";
      inp.focus();
      inp.select();
    }
    function renameEditing() { return $("titleEdit").style.display !== "none"; }
    function endInlineRename(commit) {
      const inp = $("titleEdit");
      if (inp.style.display === "none") return; // already ended (guards Esc→blur)
      const v = inp.value.trim();
      inp.style.display = "none";
      $("title").style.display = "";
      $("renameBtn").style.display = conversationClosed ? "none" : "";
      if (commit && v && v !== CUR_TITLE) {
        vscode.postMessage({ type: "rename", title: v });
      }
    }
    $("renameBtn").addEventListener("click", () => startInlineRename());
    $("title").addEventListener("dblclick", () => startInlineRename());
    $("titleEdit").addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); endInlineRename(true); }
      else if (e.key === "Escape") { e.preventDefault(); endInlineRename(false); }
    });
    $("titleEdit").addEventListener("blur", () => endInlineRename(true));
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
        case "draft":
          showDraft(msg.mode);
          break;
        case "seeded":
          hideDraft();
          break;
        case "draft.cases":
          renderCases(msg.cases);
          break;
        case "draft.caseError":
          draftSubmitting = false;
          $("draftCaseStatus").textContent = msg.message;
          break;
        case "draft.error":
          draftSubmitting = false;
          $("draftErr").textContent = msg.message;
          $("draftStart").disabled = false;
          $("draftAlertStart").disabled = false;
          break;
        case "error":
          document.body.classList.remove("loading");
          $("banner").textContent = "Could not load: " + msg.message;
          break;
        case "data":
          document.body.classList.remove("loading");
          $("banner").textContent = "";
          $("title").textContent = msg.investigation.title;
          CUR_TITLE = msg.investigation.title;
          // renderHeaderState (below) owns the pencil's visibility — it knows
          // the closed-record and mid-edit rules; showing it here unconditionally
          // would resurface it on a concluded record or during an inline edit.
          $("meta").innerHTML = '<code>' + esc(msg.investigation.id) + '</code> · seq ' + esc(msg.investigation.lastEventSequence);
          lastHyps = msg.hypotheses || [];
          lastCaps = msg.capabilities;
          lastVerdict = msg.investigation.verdict || null;
          renderHeaderState(msg.investigation.state);
          renderSeedChip(msg.investigation.seed);
          renderHypotheses(msg.hypotheses);
          renderCapabilities(msg.capabilities);
          break;
        case "pins":
          renderPins(msg.pins);
          // Pin state feeds the tracker's pin affordances AND the chat's
          // tool-result pin buttons — keep both honest so nothing double-pins.
          if (lastHyps.length) renderHypotheses(lastHyps);
          syncResultPins();
          break;
        case "comms":
          renderComms(msg.threads);
          break;
        case "rename.begin":
          // The tree-supplied title hint covers the edge where this panel's
          // last load failed and CUR_TITLE is empty.
          startInlineRename(msg.title || CUR_TITLE);
          break;
        case "renamed":
          CUR_TITLE = msg.title;
          $("title").textContent = msg.title;
          break;
        case "chronicle":
          lastThread = msg.thread || [];
          for (const t of (msg.turns || [])) restoredBodies.set(t.sequenceNo, { occurredAt: t.occurredAt, body: t.body });
          renderChronicle();
          break;
        case "evidence.label": {
          // Enrich every chip for this ref, in place (chips added later read
          // the cache on creation).
          resolvedLabels[msg.ref] = msg.label;
          for (const c of document.querySelectorAll(".refchip")) {
            if (c.dataset.ref === msg.ref) c.textContent = chipText(msg.ref);
          }
          if (popEl && popEl.dataset.ref === msg.ref) {
            popEl.querySelector(".pop-value").textContent = msg.label;
          }
          break;
        }
        case "entity.info":
          renderPopoverApps(msg.ref, msg.appearances);
          break;
        case "enablement":
          lastEnablement = msg.data;
          // Re-render the health rows so the set-up affordances appear.
          if (lastCaps) renderCapabilities(lastCaps);
          break;
        case "events.strip":
          renderEventStrip(msg.items);
          break;
        case "graph":
          renderGraph(msg);
          break;
        case "turn.user":
          preserveLive = false; // a new turn supersedes a preserved error view
          el("msg user", '<span class="bubble">' + esc(msg.text) + '</span>');
          break;
        case "turn.start":
          streaming = true;
          preserveLive = false;
          turn = { wrap: el("msg assistant"), seg: null, buf: "", tools: [], reasoningEl: null };
          break;
        case "aside.start": {
          streaming = true;
          preserveLive = false;
          // The "btw" lens: the full exchange streams into a COLLAPSED
          // disclosure — expandable live for anyone watching; the working
          // surface is the tracker, where the results land.
          setComposerEnabled(false);
          const det = document.createElement("details");
          det.className = "aside";
          const sum = document.createElement("summary");
          sum.textContent = msg.label + " · working…";
          const body = document.createElement("div");
          body.className = "asidebody";
          det.append(sum, body);
          conversation.appendChild(det);
          turn = { wrap: body, seg: null, buf: "", tools: [], reasoningEl: null, asideSum: sum, asideLabel: msg.label };
          break;
        }
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
          renderActions(msg.actions);
          break;
        case "turn.error":
          streaming = false;
          // The failed turn was never committed, so the next chronicle render
          // won't contain it — keep the live copy (partial text + this error
          // line) on screen instead of wiping the analyst's only record of it.
          preserveLive = true;
          el("error", esc(msg.message));
          break;
        case "turn.end": {
          streaming = false;
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
          if (turn && turn.asideSum) {
            turn.asideSum.textContent = turn.asideLabel + " · done — see the tracker";
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
