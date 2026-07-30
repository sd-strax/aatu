// Thin client for the reckon backend's public HTTP surface.
//
// Mirrors server.StatusResponse (server/backend.go), including the API contract
// version that drives the design/13 §2 handshake: the extension pins a set of
// backend API versions it supports and fails closed with a diagnostic on
// mismatch, rather than dispatching against an incompatible surface.

/**
 * SUPPORTED_API_VERSIONS is the set of backend API contract versions
 * (server.APIVersion) this build of the workbench speaks. Add a version here
 * when the extension is updated to handle a new backend contract; a backend
 * outside this set is a hard, diagnosable incompatibility — never a silent
 * best-effort call.
 */
export const SUPPORTED_API_VERSIONS: readonly number[] = [1];

/** Mirrors server.ComponentStatus. */
export interface ComponentStatus {
  ready: boolean;
  message: string;
}

/** Mirrors server.StatusResponse, plus reachability and derived compatibility. */
export interface BackendStatus {
  reachable: boolean;
  overall: string;
  components: Record<string, ComponentStatus>;
  /** Backend's advertised API version, or null if it predates the field. */
  apiVersion: number | null;
  /** True only when reachable AND apiVersion is in SUPPORTED_API_VERSIONS. */
  compatible: boolean;
}

/** Login config from GET /api/auth-config (mirrors server.AuthConfigResponse). */
export interface AuthConfig {
  issuer: string;
  clientId: string;
  /**
   * The delegate-path OIDC client (stamps delegate_kind issuer-side). The
   * second, silent PKCE flow runs against it (implementation/agent-sidecar.md
   * §5); absent when the deployment did not configure one.
   */
  agentClientId?: string;
}

/** Mirrors server.MeResponse (the fields the UI uses). */
export interface Me {
  subject: string;
  username: string;
  tenantId: string;
  roles: string[];
}

/** One investigation summary row (subset of the /api/investigations item). */
export interface InvestigationSummary {
  id: string;
  title: string;
  state: string;
  /** The triage line: what this case is about (01 §Extension 1). */
  seedSummary?: string;
}

/** The investigation's root (mirrors server.SeedBody, 01 §Extension 1). */
export interface Seed {
  type: string; // alert | entity | question
  alertId?: string;
  source?: string;
  detectionFindingRef?: string;
  entityRef?: string;
  hypothesisStatement?: string;
}

/** The verdict of record (mirrors server.VerdictView) — absent when none. */
export interface Verdict {
  disposition: string; // BENIGN | SUSPICIOUS | MALICIOUS
  rationale?: string;
  verdictAt: string;
}

/** A single investigation's detail (mirrors server.InvestigationView). */
export interface InvestigationDetail {
  id: string;
  title: string;
  state: string;
  lastEventSequence: number;
  verdict?: Verdict;
  seed?: Seed;
  seedSummary?: string;
}

/** One pinned-evidence row (mirrors server.PinView). */
export interface PinRow {
  interpretationId: string;
  finding: string;
  inputRefs: string[];
  actor: string; // HUMAN | AI_DELEGATED | SYSTEM
  pinnedAt: string;
  superseded: boolean;
}

/** One opened citation (mirrors server.EvidenceView). */
export interface EvidenceDoc {
  ref: string;
  kind: string; // "stix" | "ocsf"
  type: string;
  payload: unknown;
  classUid?: number;
  time?: string;
  recordedAt?: string;
  sourceTool?: string;
}

/** One prediction under a hypothesis (mirrors server.PredictionView). */
export interface Prediction {
  id: string;
  statement: string;
  status: string;
  testResultRefs: string[];
}

/** One reasoning node with its predictions nested (mirrors server.HypothesisView). */
export interface Hypothesis {
  id: string;
  statement: string;
  status: string;
  parentRef?: string;
  rootedAtRef?: string;
  labels: string[];
  predictions: Prediction[];
}

/** One typed input of a capability verb (mirrors capability.InputParam). */
export interface CapabilityInput {
  name: string;
  type: string; // "entity" | "time_window" | "string" | "int" | "enum" | ...
  required: boolean;
  desc?: string;
}

/** A capability verb + its current tenant availability (mirrors capability.CapabilitySummary). */
export interface Capability {
  verb: string;
  intent: string;
  inputs: CapabilityInput[];
  output: string;
  /** "available" | "degraded" | "unavailable". */
  status: string;
}

/** The envelope a verb invocation returns (subset of server.CapabilityInvokeResponse). */
export interface CapabilityResult {
  verb: string;
  coverage: string;
  ocsfEventRefs: string[];
  observedDataRefs: string[];
  entityRefs: string[];
  degradationNotes: string[];
  events: unknown[];
  normalized: unknown[];
}

/** One tool call to record in an interpretation's side store. */
export interface ToolCallRecord {
  callId: string;
  toolName: string;
  args: unknown;
}

/** One reasoning act in the thread (mirrors server.ThreadEntryView). */
export interface ThreadEntry {
  sequenceNo: number;
  occurredAt: string;
  actor: { principal: string; kind: string; model?: string };
  interpretationId: string;
  interpretationType: string;
  summary: string;
  confidence?: string;
  inputRefs: string[];
  outputRefs: string[];
  toolCalls: number;
  hasTranscript: boolean;
  consultedSops: { sopId: string; title?: string; used: boolean }[];
}

/** One row of the durable action queue (mirrors server.ActionView). */
export interface ActionRow {
  actionId: string;
  actionType: string;
  tier: string;
  /** Raw engine lifecycle status (REQUESTED, PENDING_SECONDARY, APPROVED, …). */
  status: string;
  requiredMode: string;
  targets: string[];
  /** True while the action still awaits a human decision. */
  pending: boolean;
  /** The awaiting state in approval vocabulary (PENDING_MANUAL / PENDING_TWO_PARTY). */
  pendingLabel: string;
  /**
   * True when the request's approval deadline (expires_at, frozen at request
   * time) has passed: the engine will refuse an approve, so the UI must not
   * offer one. The status may still read REQUESTED — v0 has no expiry timer;
   * the engine checks lazily at the approve attempt.
   */
  expired: boolean;
  /** The approval deadline (ISO), for the live countdown. */
  expiresAt?: string;
  /** REVERSIBLE | BEST_EFFORT | IRREVERSIBLE — frozen at request time. */
  reversibility?: string;
  /** The blast-radius escalator raised this above the type's default tier. */
  tierEscalated: boolean;
  /** Cited evidence — each ref opens (02 §2.8). */
  evidenceRefs: string[];
  /** Lineage: the FAILED/EXPIRED action this request replaces. */
  retryOf?: string;
}

/** Where an approve/reject left the action (mirrors server.ActionDecisionResponse). */
export interface ActionDecision {
  actionId: string;
  status: string;
  stage?: string;
}

/** Raw server.InvestigationView row, as served under {investigations: [...]}. */
interface RawInvestigation {
  aggregate_id: string;
  title: string;
  status: string;
  last_event_sequence?: number;
  verdict?: { disposition?: string; rationale?: string; verdict_at?: string };
  seed?: {
    type?: string; alert_id?: string; source?: string;
    detection_finding_ref?: string; entity_ref?: string; hypothesis_statement?: string;
  };
  seed_summary?: string;
}

/** Raw server.HypothesisView, as served under {hypotheses: [...]}. */
interface RawHypothesis {
  id: string;
  statement: string;
  status: string;
  parent_ref?: string;
  rooted_at_ref?: string;
  labels?: string[];
  predictions?: RawPrediction[];
}

/** Raw server.PredictionView. */
interface RawPrediction {
  id: string;
  statement: string;
  status: string;
  test_result_refs?: string[];
}

export class BackendClient {
  /**
   * @param baseUrl read per-call so a settings change needs no reload.
   * @param token   supplies a bearer token for authenticated calls; omitted for
   *                the public /status and /auth-config probes.
   */
  constructor(
    private readonly baseUrl: () => string,
    private readonly token?: () => Promise<string>,
  ) {}

  async status(): Promise<BackendStatus> {
    try {
      const res = await fetch(`${this.baseUrl()}/status`, {
        signal: AbortSignal.timeout(3_000),
      });
      const body = (await res.json()) as {
        overall?: string;
        components?: Record<string, ComponentStatus>;
        api_version?: number;
      };
      const apiVersion = typeof body.api_version === "number" ? body.api_version : null;
      return {
        reachable: true,
        overall: body.overall ?? "unknown",
        components: body.components ?? {},
        apiVersion,
        compatible: apiVersion !== null && SUPPORTED_API_VERSIONS.includes(apiVersion),
      };
    } catch {
      return {
        reachable: false,
        overall: "unreachable",
        components: {},
        apiVersion: null,
        compatible: false,
      };
    }
  }

  /** GET /api/auth-config — public; the login prerequisites. Throws on 503/unreachable. */
  async authConfig(): Promise<AuthConfig> {
    const res = await fetch(`${this.baseUrl()}/api/auth-config`, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) {
      throw new Error(`auth-config ${res.status} (interactive login may be unconfigured)`);
    }
    const body = (await res.json()) as { issuer?: string; client_id?: string; agent_client_id?: string };
    if (!body.issuer || !body.client_id) {
      throw new Error("auth-config missing issuer/client_id");
    }
    return { issuer: body.issuer, clientId: body.client_id, agentClientId: body.agent_client_id };
  }

  /** GET /api/me — the signed-in identity. Authenticated. */
  async me(): Promise<Me> {
    const body = await this.authedGet<{
      subject?: string;
      preferred_username?: string;
      tenant_id?: string;
      roles?: string[];
    }>("/api/me");
    return {
      subject: body.subject ?? "",
      username: body.preferred_username ?? "",
      tenantId: body.tenant_id ?? "",
      roles: body.roles ?? [],
    };
  }

  /** GET /api/capabilities — count of resolvable verbs. Authenticated. */
  async capabilityCount(): Promise<number> {
    const body = await this.authedGet<{ capabilities?: unknown[] } | unknown[]>("/api/capabilities");
    if (Array.isArray(body)) {
      return body.length;
    }
    return body.capabilities?.length ?? 0;
  }

  /**
   * GET /api/capabilities — the verb catalog with per-tenant availability
   * (03 §2.8). The agent loop trims this to `available` verbs before turning
   * them into LLM tool definitions (03 §6.3). Authenticated.
   */
  async capabilities(): Promise<Capability[]> {
    interface Raw {
      descriptor?: { verb?: string; intent?: string; inputs?: CapabilityInput[]; output?: string };
      status?: string;
    }
    const body = await this.authedGet<{ capabilities?: Raw[] }>("/api/capabilities");
    return (body.capabilities ?? []).map((c) => ({
      verb: c.descriptor?.verb ?? "",
      intent: c.descriptor?.intent ?? "",
      inputs: c.descriptor?.inputs ?? [],
      output: c.descriptor?.output ?? "",
      status: c.status ?? "unavailable",
    }));
  }

  /**
   * POST /api/capability/{verb} — the agent loop's read-tool dispatch target
   * (03 §3.4). The body carries the entity to resolve templates against, an
   * optional window, and extra template roots. Analyst role.
   */
  async invokeCapability(
    verb: string,
    body: { entity?: unknown; window?: { from: string; to: string }; extra?: Record<string, unknown> },
  ): Promise<CapabilityResult> {
    interface Raw {
      verb?: string;
      coverage?: string;
      ocsf_event_refs?: string[];
      observed_data_refs?: string[];
      entity_refs?: string[];
      degradation_notes?: string[];
      events?: unknown[];
      normalized?: unknown[];
    }
    const r = await this.authedPost<Raw>(`/api/capability/${encodeURIComponent(verb)}`, body);
    return {
      verb: r.verb ?? verb,
      coverage: r.coverage ?? "UNKNOWN",
      ocsfEventRefs: r.ocsf_event_refs ?? [],
      observedDataRefs: r.observed_data_refs ?? [],
      entityRefs: r.entity_refs ?? [],
      degradationNotes: r.degradation_notes ?? [],
      events: r.events ?? [],
      normalized: r.normalized ?? [],
    };
  }

  /**
   * POST /api/interpretations — commit one reasoning act plus the turn's
   * transcript and tool-call side store (05 §3.4). The AI authors as the
   * analyst's delegate; the backend stamps Actor.Kind from the JWT. Returns the
   * minted interpretation id. Analyst role.
   */
  async recordInterpretation(rec: {
    investigationRef: string;
    interpretationType: string;
    rationale: string;
    inputRefs?: string[];
    outputRefs?: string[];
    transcript?: { transcriptId?: string; turnId?: string; body: string };
    toolCalls?: ToolCallRecord[];
  }): Promise<{ interpretationId: string }> {
    const body = {
      investigation_ref: rec.investigationRef,
      interpretation_type: rec.interpretationType,
      rationale: rec.rationale,
      input_refs: rec.inputRefs,
      output_refs: rec.outputRefs,
      transcript: rec.transcript
        ? { transcript_id: rec.transcript.transcriptId, turn_id: rec.transcript.turnId, body: rec.transcript.body }
        : undefined,
      tool_calls: rec.toolCalls?.map((t) => ({ call_id: t.callId, tool_name: t.toolName, args: t.args })),
    };
    const r = await this.authedPost<{ interpretation_id?: string }>("/api/interpretations", body);
    return { interpretationId: r.interpretation_id ?? "" };
  }

  /** GET /api/investigations — the investigation list (server.InvestigationView). Authenticated. */
  async investigations(): Promise<InvestigationSummary[]> {
    const body = await this.authedGet<{ investigations?: RawInvestigation[] }>("/api/investigations");
    return (body.investigations ?? []).map((r) => ({
      id: r.aggregate_id,
      title: r.title || "(untitled)",
      state: r.status,
      seedSummary: r.seed_summary,
    }));
  }

  /** GET /api/investigations/{id} — one investigation's detail. Authenticated. */
  async getInvestigation(id: string): Promise<InvestigationDetail> {
    const r = await this.authedGet<RawInvestigation>(`/api/investigations/${encodeURIComponent(id)}`);
    return {
      id: r.aggregate_id,
      title: r.title || "(untitled)",
      state: r.status,
      lastEventSequence: r.last_event_sequence ?? 0,
      verdict: r.verdict?.disposition ? {
        disposition: r.verdict.disposition,
        rationale: r.verdict.rationale,
        verdictAt: r.verdict.verdict_at ?? "",
      } : undefined,
      seed: r.seed?.type ? {
        type: r.seed.type,
        alertId: r.seed.alert_id,
        source: r.seed.source,
        detectionFindingRef: r.seed.detection_finding_ref,
        entityRef: r.seed.entity_ref,
        hypothesisStatement: r.seed.hypothesis_statement,
      } : undefined,
      seedSummary: r.seed_summary,
    };
  }

  /**
   * GET /api/investigations/{id}/hypotheses — the reasoning nodes, predictions
   * nested under the hypothesis they test (D.2). Authenticated.
   */
  async hypotheses(id: string): Promise<Hypothesis[]> {
    const body = await this.authedGet<{ hypotheses?: RawHypothesis[] }>(
      `/api/investigations/${encodeURIComponent(id)}/hypotheses`,
    );
    return (body.hypotheses ?? []).map((h) => ({
      id: h.id,
      statement: h.statement,
      status: h.status,
      parentRef: h.parent_ref,
      rootedAtRef: h.rooted_at_ref,
      labels: h.labels ?? [],
      predictions: (h.predictions ?? []).map((p) => ({
        id: p.id,
        statement: p.statement,
        status: p.status,
        testResultRefs: p.test_result_refs ?? [],
      })),
    }));
  }

  /**
   * GET /api/investigations/{id}/thread — the chronological reasoning thread
   * (13 §4): every recorded reasoning act, including the interpretations
   * paired with lifecycle/action transitions, in aggregate sequence order.
   * This is the "how did it get here" surface.
   */
  async thread(id: string): Promise<ThreadEntry[]> {
    interface Raw {
      sequence_no?: number;
      occurred_at?: string;
      actor?: { principal?: string; kind?: string; model?: string };
      interpretation_id?: string;
      interpretation_type?: string;
      summary?: string;
      confidence?: string;
      input_refs?: string[];
      output_refs?: string[];
      tool_calls?: number;
      has_transcript?: boolean;
      consulted_sops?: { sop_id?: string; title?: string; used?: boolean }[];
    }
    const body = await this.authedGet<{ thread?: Raw[] }>(
      `/api/investigations/${encodeURIComponent(id)}/thread`,
    );
    return (body.thread ?? []).map((e) => ({
      sequenceNo: e.sequence_no ?? 0,
      occurredAt: e.occurred_at ?? "",
      actor: {
        principal: e.actor?.principal ?? "",
        kind: e.actor?.kind ?? "HUMAN",
        model: e.actor?.model,
      },
      interpretationId: e.interpretation_id ?? "",
      interpretationType: e.interpretation_type ?? "",
      summary: e.summary ?? "",
      confidence: e.confidence,
      inputRefs: e.input_refs ?? [],
      outputRefs: e.output_refs ?? [],
      toolCalls: e.tool_calls ?? 0,
      hasTranscript: e.has_transcript ?? false,
      consultedSops: (e.consulted_sops ?? []).map((c) => ({
        sopId: c.sop_id ?? "", title: c.title, used: c.used ?? false,
      })),
    }));
  }

  /**
   * GET /api/investigations/{id}/actions — the durable action queue
   * (design/13 §7 step 4). The pending flag/label mirror the Go client's
   * ActionStatus.Pending/PendingLabel so every surface speaks one vocabulary.
   */
  async actions(investigationId: string): Promise<ActionRow[]> {
    interface Raw {
      action_id?: string;
      action_type?: string;
      tier?: string;
      status?: string;
      required_mode?: string;
      expires_at?: string;
      targets?: { entity_ref?: string; resolved_identifier?: string }[];
      reversibility?: string;
      tier_escalated?: boolean;
      evidence_refs?: string[];
      retry_of?: string;
    }
    const body = await this.authedGet<{ actions?: Raw[] }>(
      `/api/investigations/${encodeURIComponent(investigationId)}/actions`,
    );
    return (body.actions ?? []).map((a) => {
      const status = a.status ?? "";
      const mode = a.required_mode ?? "";
      const pending = status === "REQUESTED" || status === "PENDING_SECONDARY"
        || status === "PENDING_MANUAL" || status === "PENDING_TWO_PARTY";
      const pendingLabel =
        status === "REQUESTED" && mode === "TWO_PARTY" ? "PENDING_TWO_PARTY"
        : status === "REQUESTED" ? "PENDING_MANUAL"
        : status === "PENDING_SECONDARY" ? "PENDING_TWO_PARTY"
        : status;
      const expiry = a.expires_at ? Date.parse(a.expires_at) : NaN;
      return {
        actionId: a.action_id ?? "",
        actionType: a.action_type ?? "",
        tier: a.tier ?? "",
        status,
        requiredMode: mode,
        targets: (a.targets ?? []).map((t) => t.resolved_identifier || t.entity_ref || ""),
        pending,
        pendingLabel,
        expired: Number.isFinite(expiry) && Date.now() > expiry,
        expiresAt: a.expires_at,
        reversibility: a.reversibility,
        tierEscalated: a.tier_escalated ?? false,
        evidenceRefs: a.evidence_refs ?? [],
        retryOf: a.retry_of,
      };
    });
  }

  /** GET /api/investigations/{id}/pins — the pinned-evidence fold. */
  async pins(id: string): Promise<PinRow[]> {
    interface Raw {
      interpretation_id?: string;
      finding?: string;
      input_refs?: string[];
      actor?: string;
      pinned_at?: string;
      superseded?: boolean;
    }
    const body = await this.authedGet<{ pins?: Raw[] }>(
      `/api/investigations/${encodeURIComponent(id)}/pins`,
    );
    return (body.pins ?? []).map((p) => ({
      interpretationId: p.interpretation_id ?? "",
      finding: p.finding ?? "",
      inputRefs: p.input_refs ?? [],
      actor: p.actor ?? "HUMAN",
      pinnedAt: p.pinned_at ?? "",
      superseded: p.superseded ?? false,
    }));
  }

  /**
   * Pin evidence: an evidence-pin interpretation on the HUMAN token — the
   * analyst's curation act (01 §Pinned evidence).
   */
  async pinEvidence(investigationId: string, finding: string, refs: string[]): Promise<void> {
    await this.authedPost("/api/interpretations", {
      investigation_ref: investigationId,
      interpretation_type: "evidence-pin",
      input_refs: refs,
      rationale: finding,
    });
  }

  /** Record/revise the verdict of record (01 §Verdict). Human token. */
  async recordVerdict(
    investigationId: string,
    disposition: string,
    rationale: string,
    refs: string[],
  ): Promise<void> {
    await this.authedPost("/api/interpretations", {
      investigation_ref: investigationId,
      interpretation_type: "verdict",
      verdict: { disposition },
      input_refs: refs,
      rationale,
    });
  }

  /** POST /api/interpretations/{id}/supersede — un-pin / retraction. */
  async supersedeInterpretation(interpretationId: string, investigationId: string, reason: string): Promise<void> {
    await this.authedPost(
      `/api/interpretations/${encodeURIComponent(interpretationId)}/supersede`,
      { investigation_ref: investigationId, reason },
    );
  }

  /**
   * GET /api/interpretations/{id}/transcript — the committed turn record
   * behind a thread step (the content-addressed side store).
   */
  async transcript(interpretationId: string): Promise<{ turnId?: string; body: string }> {
    const r = await this.authedGet<{ turn_id?: string; body?: string }>(
      `/api/interpretations/${encodeURIComponent(interpretationId)}/transcript`,
    );
    return { turnId: r.turn_id, body: r.body ?? "" };
  }

  /** GET /api/evidence/{ref} — citation-open (02 §2.8). */
  async evidence(ref: string): Promise<EvidenceDoc> {
    interface Raw {
      ref?: string; kind?: string; type?: string; payload?: unknown;
      class_uid?: number; time?: string; recorded_at?: string; source_tool?: string;
    }
    const r = await this.authedGet<Raw>(`/api/evidence/${encodeURIComponent(ref)}`);
    return {
      ref: r.ref ?? ref,
      kind: r.kind ?? "",
      type: r.type ?? "",
      payload: r.payload,
      classUid: r.class_uid,
      time: r.time,
      recordedAt: r.recorded_at,
      sourceTool: r.source_tool,
    };
  }

  /**
   * POST /api/actions/{id}/approve — the analyst's own act, always on the
   * human token (a delegate token is 403'd server-side). challengeResponse is
   * the typed challenge a T3 approval requires (04 §5.5).
   */
  async approveAction(actionId: string, challengeResponse?: string): Promise<ActionDecision> {
    const r = await this.authedPost<{ action_id?: string; status?: string; stage?: string }>(
      `/api/actions/${encodeURIComponent(actionId)}/approve`,
      challengeResponse ? { challenge_response: challengeResponse } : {},
    );
    return { actionId: r.action_id ?? actionId, status: r.status ?? "", stage: r.stage };
  }

  /**
   * POST /api/actions/{id}/rerequest — re-request an expired action (human
   * token). The backend rebuilds it from the original's frozen fields with a
   * fresh window and retry_of lineage; the analyst then approves the new one.
   */
  async rerequestAction(actionId: string, rationale: string): Promise<void> {
    await this.authedPost(`/api/actions/${encodeURIComponent(actionId)}/rerequest`, { rationale });
  }

  /** POST /api/actions/{id}/reject — ditto, human token only. */
  async rejectAction(actionId: string, reason: string): Promise<ActionDecision> {
    const r = await this.authedPost<{ action_id?: string; status?: string; stage?: string }>(
      `/api/actions/${encodeURIComponent(actionId)}/reject`,
      { reason },
    );
    return { actionId: r.action_id ?? actionId, status: r.status ?? "", stage: r.stage };
  }

  /** POST /api/investigations — seed a new investigation. Analyst role. */
  async createInvestigation(title: string, seed?: Seed): Promise<InvestigationDetail> {
    const body: Record<string, unknown> = { title };
    if (seed) {
      body.seed = {
        type: seed.type,
        alert_id: seed.alertId,
        source: seed.source,
        detection_finding_ref: seed.detectionFindingRef,
        entity_ref: seed.entityRef,
        hypothesis_statement: seed.hypothesisStatement,
      };
    }
    const r = await this.authedPost<RawInvestigation>("/api/investigations", body);
    return {
      id: r.aggregate_id,
      title: r.title || "(untitled)",
      state: r.status,
      lastEventSequence: r.last_event_sequence ?? 0,
    };
  }

  private async authedGet<T>(path: string): Promise<T> {
    return this.authed<T>("GET", path);
  }

  private async authedPost<T>(path: string, body: unknown): Promise<T> {
    return this.authed<T>("POST", path, body);
  }

  private async authed<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    if (!this.token) {
      throw new Error("no token source configured");
    }
    const bearer = await this.token();
    const res = await fetch(`${this.baseUrl()}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${bearer}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      // Surface the server's explanation when it sent one — a Gate 2 denial
      // or a guarded transition is information, not noise (approve/reject
      // rejections carry their reason in the error body).
      let detail = "";
      try {
        const body = (await res.json()) as { error?: string };
        detail = body.error ? `: ${body.error}` : "";
      } catch {
        // non-JSON error body — the status alone will have to do
      }
      throw new Error(`${method} ${path} → ${res.status}${detail}`);
    }
    return (await res.json()) as T;
  }

  /** A one-line diagnostic for an incompatible/unreachable backend, or null when compatible. */
  incompatibilityReason(status: BackendStatus): string | null {
    if (!status.reachable) {
      return "backend not reachable — run `reckon start`";
    }
    if (status.apiVersion === null) {
      return "backend predates the version handshake — upgrade the backend";
    }
    if (!status.compatible) {
      return `backend API v${status.apiVersion} unsupported (this workbench speaks v${SUPPORTED_API_VERSIONS.join(", v")}) — align versions`;
    }
    return null;
  }
}
