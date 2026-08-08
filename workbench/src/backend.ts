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
  /** Last committed event — drives the unseen-changes cue (ui/02 §2.12). */
  lastEventSequence: number;
  updatedAt?: string;
  /** Actions still awaiting a human decision (triage cue, ui/06). */
  pendingActions: number;
  /** Soonest approval-window deadline among them (ISO) — the countdown cue. */
  nearestExpiry?: string;
}

/** The investigation's root (mirrors server.SeedBody, 01 §Extension 1). */
export interface Seed {
  type: string; // alert | entity | question
  alertId?: string;
  source?: string;
  detectionFindingRef?: string;
  entityRef?: string;
  /** The human identifier an entity seed was rooted on (hostname/IP/hash). */
  entityIdentifier?: string;
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

/** One investigation a ref appears in (mirrors server.AppearanceView). */
export interface Appearance {
  investigationId: string;
  title: string;
  status: string;
  seedSummary?: string;
  firstSeen?: string;
  lastSeen?: string;
  mentions: number;
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

/** A prediction's declared falsification test (mirrors aggregate.QuerySpec). */
export interface TestQuery {
  tool?: string;
  queryText?: string;
}

/** One prediction under a hypothesis (mirrors server.PredictionView). */
export interface Prediction {
  id: string;
  statement: string;
  status: string;
  /** The declared test — "Test this" stages it in the composer, never fires it. */
  testQuery?: TestQuery;
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

/** One JSON-schema property of an adapter's config form (11 §4.3). */
export interface ConfigField {
  type?: string;
  description?: string;
  /** x-secret: the value must be a secret REFERENCE, captured out-of-band. */
  secret?: boolean;
}

/** One installed adapter instance (mirrors server.EnablementAdapterView). */
export interface EnablementAdapter {
  name: string;
  class: string;
  enabled: boolean;
  scenario?: string;
  /** Schema-derived form source; the extension renders it, never the model. */
  configFields: Record<string, ConfigField>;
  requiredFields: string[];
  /** False for classes v0 cannot spawn — no enable affordance, honestly. */
  supportable: boolean;
}

/** One verb's enablement state (mirrors server.EnablementVerbView). */
export interface EnablementVerb {
  verb: string;
  adapters: string[];
  enabled: boolean;
  /** Disabled-but-supportable adapters that would serve this verb. */
  closableBy: string[];
}

/** The operator enablement surface (11 §5.1). */
export interface Enablement {
  adapters: EnablementAdapter[];
  verbs: EnablementVerb[];
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
  superseded: boolean;
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
   * offer one. The stored status (converged by the durable expiry timer) is
   * authoritative; the deadline comparison covers the moments it lags.
   */
  expired: boolean;
  /** The approval deadline (ISO), for the live countdown. */
  expiresAt?: string;
  /** True when this action IS a reversal of another (drives the ledger marker). */
  isReversal: boolean;
  /** REVERSIBLE | BEST_EFFORT | IRREVERSIBLE — frozen at request time. */
  reversibility?: string;
  /** The blast-radius escalator raised this above the type's default tier. */
  tierEscalated: boolean;
  /** Cited evidence — each ref opens (02 §2.8). */
  evidenceRefs: string[];
  /** Lineage: the FAILED/EXPIRED action this request replaces. */
  retryOf?: string;
  /**
   * The tool that dispatched the action (write-side provenance) — which of
   * several possible adapters actually acted. Empty until dispatched.
   */
  adapter?: string;
  /**
   * The tool the resolver WOULD dispatch to if approved now — the pre-approval
   * preview so the analyst sees which system of record an external action will
   * hit before committing. Present only while pending.
   */
  plannedAdapter?: string;
  /** Why a FAILED action failed (adapter/dispatch reason). Empty on success. */
  errorDetail?: string;
  /** The operational reference the dispatch returned (e.g. the INC number). */
  resultRef?: string;
  /**
   * The request's frozen parameters (raw JSON) — the pre-send preview for
   * notify.* actions renders the exact message from here.
   */
  parameters?: Record<string, unknown>;
}

/** One comms trail entry (mirrors server.CommsTrailView). */
export interface CommsTrailEntry {
  direction: string; // outbound | inbound | note
  author: string;
  at: string;
  body: string;
}

/** One comms/external-work thread (mirrors server.CommsThreadView). */
export interface CommsThread {
  threadId: string;
  actionId: string;
  actionType: string;
  target: string;
  subject?: string;
  status: string; // awaiting_reply | replied | followed_up | closed
  followUpHours: number;
  followUps: number;
  unackedReply: boolean;
  sentAt: string;
  nextFollowUpAt?: string;
  trail: CommsTrailEntry[];
  followUpDue: boolean;
  escalationTriggered: boolean;
  escalationPolicy?: string;
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
  updated_at?: string;
  pending_actions?: number;
  nearest_expiry?: string;
  verdict?: { disposition?: string; rationale?: string; verdict_at?: string };
  seed?: {
    type?: string; alert_id?: string; source?: string;
    detection_finding_ref?: string; entity_ref?: string;
    entity_identifier?: string; hypothesis_statement?: string;
  };
  seed_summary?: string;
}

/** Map a raw seed body to the client Seed shape (shared by list/get/create). */
function mapSeed(s: RawInvestigation["seed"]): Seed | undefined {
  if (!s || !s.type) return undefined;
  return {
    type: s.type,
    alertId: s.alert_id,
    source: s.source,
    detectionFindingRef: s.detection_finding_ref,
    entityRef: s.entity_ref,
    entityIdentifier: s.entity_identifier,
    hypothesisStatement: s.hypothesis_statement,
  };
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
  test_query?: { tool?: string; query_text?: string };
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
   * GET /api/enablement — the operator view of installed adapters and the
   * gaps a disabled one could close (11 §5.1, §6.2). Analyst role.
   */
  async enablement(): Promise<Enablement> {
    interface RawAdapter {
      name?: string; class?: string; enabled?: boolean; scenario?: string;
      config_schema?: { properties?: Record<string, { type?: string; description?: string; "x-secret"?: boolean }>; required?: string[] };
      supportable?: boolean;
    }
    interface RawVerb {
      verb?: string; adapters?: string[]; enabled?: boolean; closable_by?: string[];
    }
    const body = await this.authedGet<{ adapters?: RawAdapter[]; verbs?: RawVerb[] }>("/api/enablement");
    return {
      adapters: (body.adapters ?? []).map((a) => {
        const fields: Record<string, ConfigField> = {};
        const props = a.config_schema?.properties ?? {};
        for (const [k, p] of Object.entries(props)) {
          fields[k] = { type: p.type, description: p.description, secret: p["x-secret"] === true };
        }
        return {
          name: a.name ?? "",
          class: a.class ?? "",
          enabled: a.enabled ?? false,
          scenario: a.scenario,
          configFields: fields,
          requiredFields: a.config_schema?.required ?? [],
          supportable: a.supportable ?? false,
        };
      }),
      verbs: (body.verbs ?? []).map((v) => ({
        verb: v.verb ?? "",
        adapters: v.adapters ?? [],
        enabled: v.enabled ?? false,
        closableBy: v.closable_by ?? [],
      })),
    };
  }

  /**
   * POST /api/enablement/adapters/{name} — the human-confirmed apply
   * (11 §5.1). Always the HUMAN token: the backend 403s a delegate token, and
   * no sidecar tool reaches this path — the tool gap is the guarantee.
   */
  async applyEnablement(adapter: string, enabled: boolean, config: Record<string, string>): Promise<void> {
    await this.authedPost(`/api/enablement/adapters/${encodeURIComponent(adapter)}`, { enabled, config });
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
      lastEventSequence: r.last_event_sequence ?? 0,
      updatedAt: r.updated_at,
      pendingActions: r.pending_actions ?? 0,
      nearestExpiry: r.nearest_expiry,
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
      seed: mapSeed(r.seed),
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
        testQuery: p.test_query
          ? { tool: p.test_query.tool, queryText: p.test_query.query_text }
          : undefined,
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
      superseded?: boolean;
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
      superseded: e.superseded ?? false,
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
      is_reversal?: boolean;
      reversibility?: string;
      tier_escalated?: boolean;
      evidence_refs?: string[];
      retry_of?: string;
      adapter?: string;
      planned_adapter?: string;
      error_detail?: string;
      result_ref?: string;
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
      const params = (a as { parameters?: Record<string, unknown> }).parameters;
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
        // The stored status is authoritative (the durable expiry timer owns the
        // transition); the deadline comparison covers the moments it lags.
        expired: status === "EXPIRED" || (pending && Number.isFinite(expiry) && Date.now() > expiry),
        expiresAt: a.expires_at,
        isReversal: a.is_reversal ?? false,
        reversibility: a.reversibility,
        tierEscalated: a.tier_escalated ?? false,
        evidenceRefs: a.evidence_refs ?? [],
        retryOf: a.retry_of,
        adapter: a.adapter,
        plannedAdapter: a.planned_adapter,
        errorDetail: a.error_detail,
        resultRef: a.result_ref,
        parameters: params,
      };
    });
  }

  /**
   * GET /api/investigations/{id}/comms — the external-work threads (Phase F,
   * binding §4): what was sent, who replied, what still awaits.
   */
  async comms(investigationId: string): Promise<CommsThread[]> {
    interface Raw {
      thread_id?: string; action_id?: string; action_type?: string; target?: string;
      subject?: string; status?: string; follow_up_hours?: number; follow_ups?: number;
      unacked_reply?: boolean; sent_at?: string; next_followup_at?: string;
      trail?: { direction?: string; author?: string; at?: string; body?: string }[];
      follow_up_due?: boolean; escalation_triggered?: boolean; escalation_policy?: string;
    }
    const body = await this.authedGet<{ threads?: Raw[] }>(
      `/api/investigations/${encodeURIComponent(investigationId)}/comms`,
    );
    return (body.threads ?? []).map((t) => ({
      threadId: t.thread_id ?? "",
      actionId: t.action_id ?? "",
      actionType: t.action_type ?? "",
      target: t.target ?? "",
      subject: t.subject,
      status: t.status ?? "",
      followUpHours: t.follow_up_hours ?? 0,
      followUps: t.follow_ups ?? 0,
      unackedReply: t.unacked_reply ?? false,
      sentAt: t.sent_at ?? "",
      nextFollowUpAt: t.next_followup_at,
      trail: (t.trail ?? []).map((e) => ({
        direction: e.direction ?? "", author: e.author ?? "", at: e.at ?? "", body: e.body ?? "",
      })),
      followUpDue: t.follow_up_due ?? false,
      escalationTriggered: t.escalation_triggered ?? false,
      escalationPolicy: t.escalation_policy,
    }));
  }

  /** POST /api/comms/{id}/ack|done — the analyst's act on a thread. */
  async commsAct(threadId: string, verb: "ack" | "done"): Promise<void> {
    await this.authedPost(`/api/comms/${encodeURIComponent(threadId)}/${verb}`, {});
  }

  /** POST /api/comms/{id}/snooze — push the follow-up clock. */
  async commsSnooze(threadId: string, hours: number): Promise<void> {
    await this.authedPost(`/api/comms/${encodeURIComponent(threadId)}/snooze`, { hours });
  }

  /**
   * POST /api/actions — request one action on the HUMAN token (the workbench's
   * own write path — e.g. a comms follow-up). Same endpoint the agent uses via
   * the sidecar; Gate 2 and the tiers apply identically.
   */
  async requestAction(body: {
    investigationRef: string;
    actionType: string;
    targets: { resolvedIdentifier: string; entityRef?: string }[];
    parameters?: Record<string, unknown>;
    evidenceRefs?: string[];
    rationale: string;
  }): Promise<{ actionId: string; status: string }> {
    const r = await this.authedPost<{ action_id?: string; status?: string }>("/api/actions", {
      investigation_ref: body.investigationRef,
      action_type: body.actionType,
      targets: body.targets.map((t) => ({
        resolved_identifier: t.resolvedIdentifier,
        entity_ref: t.entityRef,
      })),
      parameters: body.parameters,
      evidence_refs: body.evidenceRefs,
      rationale: body.rationale,
    });
    return { actionId: r.action_id ?? "", status: r.status ?? "" };
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

  /**
   * Record an analyst-authored hypothesis (01 §x-hypothesis): lands OPEN
   * immediately (acknowledgment is only for AI proposals). An alternate
   * explanation is simply a sibling hypothesis — the tracker scores them
   * against each other. Human token; the node id is minted server-side.
   */
  async recordHypothesis(investigationId: string, statement: string): Promise<void> {
    await this.authedPost("/api/interpretations", {
      investigation_ref: investigationId,
      interpretation_type: "hypothesis",
      hypothesis: { statement },
      rationale: statement,
    });
  }

  /**
   * Acknowledge an AI-PROPOSED hypothesis into OPEN — the human taking
   * ownership of the line of inquiry (01 §Interpretation types). The aggregate
   * refuses this from an AI delegate; always the human token.
   */
  async acknowledgeHypothesis(investigationId: string, hypothesisRef: string): Promise<void> {
    await this.authedPost("/api/interpretations", {
      investigation_ref: investigationId,
      interpretation_type: "hypothesis",
      hypothesis_ref: hypothesisRef,
      rationale: "acknowledged from the workbench — taking ownership of this line of inquiry",
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

  /**
   * GET /api/entities/{ref}/appearances — cross-investigation memory
   * (binding §6.1): every investigation whose thread cites the ref, powered by
   * deterministic identity. The entity popover's "appears in N other
   * investigations" list.
   */
  async appearances(ref: string): Promise<Appearance[]> {
    interface Raw {
      investigation_id?: string; title?: string; status?: string;
      seed_summary?: string; first_seen?: string; last_seen?: string; mentions?: number;
    }
    const body = await this.authedGet<{ appearances?: Raw[] }>(
      `/api/entities/${encodeURIComponent(ref)}/appearances`,
    );
    return (body.appearances ?? []).map((a) => ({
      investigationId: a.investigation_id ?? "",
      title: a.title ?? "",
      status: a.status ?? "",
      seedSummary: a.seed_summary,
      firstSeen: a.first_seen,
      lastSeen: a.last_seen,
      mentions: a.mentions ?? 0,
    }));
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

  /**
   * POST /api/investigations/{id}/lifecycle — the analyst-driven state machine
   * (01 §Extension 2): activate | pause | resume | conclude | reopen | archive.
   * Conclude requires report_ref (minted by the caller — the STIX Report object
   * itself is v1) and is refused by the aggregate without a verdict of record.
   * Human token only; the aggregate's actor allowlist bars an AI delegate.
   */
  async lifecycle(
    investigationId: string,
    body: { transition: string; reason?: string; reportRef?: string; summary?: string },
  ): Promise<{ status: string; exportWorkflowId?: string }> {
    const r = await this.authedPost<{ status?: string; export_workflow_id?: string }>(
      `/api/investigations/${encodeURIComponent(investigationId)}/lifecycle`,
      {
        transition: body.transition,
        reason: body.reason,
        report_ref: body.reportRef,
        summary: body.summary,
      },
    );
    return { status: r.status ?? "", exportWorkflowId: r.export_workflow_id };
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
        entity_identifier: seed.entityIdentifier,
        hypothesis_statement: seed.hypothesisStatement,
      };
    }
    return this.mapCreated(await this.authedPost<RawInvestigation>("/api/investigations", body));
  }

  /**
   * POST /api/investigations/{id}/rename — change the title (analyst). Human
   * curation; the aggregate bars an AI delegate. Returns the applied title.
   */
  async renameInvestigation(id: string, title: string): Promise<string> {
    const r = await this.authedPost<{ title?: string }>(
      `/api/investigations/${encodeURIComponent(id)}/rename`,
      { title },
    );
    return r.title ?? title;
  }

  /**
   * POST /api/investigations from a raw analyst-typed seed (design/ui/02 §2.7):
   * the value the analyst rooted on plus their confirmed kind ("entity" |
   * "question"). The server classifies, mints the STIX id for an entity, and
   * derives the title — the workbench never handles ids. Title is optional; the
   * server derives it from the seed's display line.
   */
  async createInvestigationFromInput(value: string, kind: string, title?: string): Promise<InvestigationDetail> {
    const body: Record<string, unknown> = { seed_input: { value, kind } };
    if (title) body.title = title;
    return this.mapCreated(await this.authedPost<RawInvestigation>("/api/investigations", body));
  }

  private mapCreated(r: RawInvestigation): InvestigationDetail {
    return {
      id: r.aggregate_id,
      title: r.title || "(untitled)",
      state: r.status,
      lastEventSequence: r.last_event_sequence ?? 0,
      seed: mapSeed(r.seed),
      seedSummary: r.seed_summary,
    };
  }

  /**
   * GET /api/investigations/{id}/export.md — the live markdown projection
   * (binding §6 item 10): the portable, any-time snapshot. "Paste into a
   * ticket unedited" is this call, not a file on disk.
   */
  async exportMarkdown(investigationId: string): Promise<string> {
    if (!this.token) {
      throw new Error("no token source configured");
    }
    const bearer = await this.token();
    const res = await fetch(
      `${this.baseUrl()}/api/investigations/${encodeURIComponent(investigationId)}/export.md`,
      { headers: { Authorization: `Bearer ${bearer}` }, signal: AbortSignal.timeout(15_000) },
    );
    if (!res.ok) {
      throw new Error(`export.md → ${res.status}`);
    }
    return await res.text();
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
