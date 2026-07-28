// The AgentTransport seam (implementation/agent-sidecar.md §7 step 1) and its
// sidecar implementation (§7 step 3): the extension reaches the ONE agent-loop
// implementation — the Go `agent` package — by spawning `reckon investigate
// --stdio` and speaking LSP-framed JSON-RPC over its stdio (vscode-jsonrpc).
//
// Auth stays here, on the extension side (§5): the sidecar holds no refresh
// tokens; whenever the loop needs a bearer token it calls the getToken RPC
// back into this process, which answers from auth.Session — short-lived
// access tokens, per call. The BYOK Anthropic key crosses once, at
// initialize, over the local pipe.
//
// Process lifecycle: this owns spawn/respawn. A sidecar crash never takes the
// extension down — sessions are re-created from backend state on the next
// turn (the reasoning thread is server-persisted; only in-flight turn context
// was process-local).

import { ChildProcess, spawn } from "child_process";
import * as vscode from "vscode";
import {
  createMessageConnection,
  MessageConnection,
  StreamMessageReader,
  StreamMessageWriter,
} from "vscode-jsonrpc/node";
import { TokenKind } from "./auth";

/** The stdio protocol contract version (sidecar.ProtocolVersion). */
const PROTOCOL_VERSION = 1;

/** Progress callbacks one turn renders. */
export interface TurnProgress {
  /** Round-complete text — fires only when the provider cannot stream. */
  onText(text: string): void;
  /**
   * A text fragment as the model generates it (E.4). Mutually exclusive with
   * onText per completion (enforced sidecar-side): a streamed completion's
   * text arrives ONLY as deltas. Renderers append both the same way.
   */
  onTextDelta(text: string): void;
  /** A new model↔tool round began (1-based) — the step marker. */
  onStep(round: number): void;
  onToolCall(name: string, input: unknown): void;
  /**
   * coverage/eventCount/refs are distilled sidecar-side from the FULL result
   * payload (content is clipped for transport and may not parse). Undefined
   * when the result is not a capability envelope (e.g. list_actions). refs
   * are the envelope's citation ids — what pin-from-result and citation-open
   * act on.
   */
  onToolResult(name: string, content: string, isError: boolean, coverage?: string, eventCount?: number, refs?: string[]): void;
}

/** One action awaiting the analyst (mirrors sidecar.pendingAction). */
export interface PendingAction {
  actionId: string;
  actionType: string;
  tier: string;
  status: string;
  targets: string[];
  /** Approval window elapsed — the engine refuses an approve; offer none. */
  expired: boolean;
}

/** What one turn produced (mirrors sidecar.turnResult). */
export interface TurnOutcome {
  text: string;
  interpretationId?: string;
  toolRounds: number;
  usage: { input: number; output: number; cacheRead: number; cacheWrite: number };
  pendingActions: PendingAction[];
  /** A turn that failed part-way still surfaces its partial outcome. */
  error?: string;
}

/**
 * The seam the investigation document drives. Sessions are keyed by
 * investigation id; the transport owns their lifecycle (including re-creation
 * after a sidecar respawn).
 */
export interface AgentTransport {
  turn(investigationId: string, text: string, progress: TurnProgress): Promise<TurnOutcome>;
  cancel(investigationId: string): Promise<void>;
  dispose(): void;
}

/** What the transport needs from the extension host. */
export interface SidecarDeps {
  backendUrl(): string;
  model(): string;
  /** The BYOK key from SecretStorage; undefined lets the sidecar try its own fallback (env / OS keychain). */
  apiKey(): Thenable<string | undefined>;
  /** Short-lived access tokens from the auth session — the getToken answer. */
  getToken(kind: TokenKind, force: boolean): Promise<string>;
}

/** Wire shapes (snake_case, mirroring the Go structs). */
interface WireTurnResult {
  text?: string;
  interpretation_id?: string;
  tool_rounds?: number;
  usage?: { input?: number; output?: number; cache_read?: number; cache_write?: number };
  pending_actions?: {
    action_id?: string;
    action_type?: string;
    tier?: string;
    status?: string;
    targets?: string[];
    expired?: boolean;
  }[];
  error?: string;
}

export class SidecarTransport implements AgentTransport {
  private child: ChildProcess | null = null;
  private connection: MessageConnection | null = null;
  private initializing: Promise<MessageConnection> | null = null;
  /** investigation id → live session id on the CURRENT sidecar process. */
  private readonly sessions = new Map<string, string>();
  /** session id → the in-flight turn's progress sink (for notifications). */
  private readonly inFlight = new Map<string, TurnProgress>();
  private disposed = false;

  constructor(
    private readonly deps: SidecarDeps,
    private readonly log: vscode.LogOutputChannel,
  ) {}

  async turn(investigationId: string, text: string, progress: TurnProgress): Promise<TurnOutcome> {
    const conn = await this.ensureConnection();
    const sessionId = await this.ensureSession(conn, investigationId);
    this.inFlight.set(sessionId, progress);
    try {
      const raw = await conn.sendRequest("turn", { session_id: sessionId, text }) as WireTurnResult;
      return {
        text: raw.text ?? "",
        interpretationId: raw.interpretation_id,
        toolRounds: raw.tool_rounds ?? 0,
        usage: {
          input: raw.usage?.input ?? 0,
          output: raw.usage?.output ?? 0,
          cacheRead: raw.usage?.cache_read ?? 0,
          cacheWrite: raw.usage?.cache_write ?? 0,
        },
        pendingActions: (raw.pending_actions ?? []).map((a) => ({
          actionId: a.action_id ?? "",
          actionType: a.action_type ?? "",
          tier: a.tier ?? "",
          status: a.status ?? "",
          targets: a.targets ?? [],
          expired: a.expired ?? false,
        })),
        error: raw.error,
      };
    } finally {
      this.inFlight.delete(sessionId);
    }
  }

  async cancel(investigationId: string): Promise<void> {
    const sessionId = this.sessions.get(investigationId);
    if (!sessionId || !this.connection) {
      return; // nothing in flight on this process — cancel is idempotent
    }
    await this.connection.sendRequest("cancel", { session_id: sessionId });
  }

  dispose(): void {
    this.disposed = true;
    this.teardown("dispose");
  }

  // --- internals ------------------------------------------------------------

  /** Spawn + initialize once; reuse until the process dies, then respawn lazily. */
  private ensureConnection(): Promise<MessageConnection> {
    if (this.connection) {
      return Promise.resolve(this.connection);
    }
    this.initializing ??= this.start().finally(() => {
      this.initializing = null;
    });
    return this.initializing;
  }

  private async start(): Promise<MessageConnection> {
    if (this.disposed) {
      throw new Error("transport disposed");
    }
    const command = this.sidecarCommand();
    this.log.info(`spawning agent sidecar: ${command} investigate --stdio`);
    const child = spawn(command, ["investigate", "--stdio"], { stdio: ["pipe", "pipe", "pipe"] });

    const spawned = new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", (err) =>
        reject(new Error(
          `could not start the reckon sidecar (${err.message}) — install reckon or set reckon.sidecarPath`,
        )));
    });
    await spawned;

    child.stderr?.on("data", (chunk: Buffer) => {
      this.log.debug(`sidecar: ${chunk.toString().trimEnd()}`);
    });
    child.on("exit", (code) => {
      this.log.info(`sidecar exited (code ${code ?? "signal"})`);
      if (this.child === child) {
        this.teardown(`exit ${code ?? "signal"}`);
      }
    });

    const connection = createMessageConnection(
      new StreamMessageReader(child.stdout!),
      new StreamMessageWriter(child.stdin!),
    );

    // The token handoff (§5): the loop asks, the auth session answers.
    connection.onRequest("getToken", async (params: { kind?: string; force?: boolean }) => {
      const kind: TokenKind = params?.kind === "human" ? "human" : "delegate";
      const token = await this.deps.getToken(kind, params?.force ?? false);
      return { token };
    });

    // Turn progress → the in-flight turn's sink, routed by session id.
    connection.onNotification("turn/text", (p: { session_id?: string; text?: string }) => {
      this.inFlight.get(p?.session_id ?? "")?.onText(p?.text ?? "");
    });
    connection.onNotification("turn/text_delta", (p: { session_id?: string; text?: string }) => {
      this.inFlight.get(p?.session_id ?? "")?.onTextDelta(p?.text ?? "");
    });
    connection.onNotification("turn/step", (p: { session_id?: string; round?: number }) => {
      this.inFlight.get(p?.session_id ?? "")?.onStep(p?.round ?? 0);
    });
    connection.onNotification("turn/tool_call", (p: { session_id?: string; name?: string; input?: unknown }) => {
      this.inFlight.get(p?.session_id ?? "")?.onToolCall(p?.name ?? "", p?.input);
    });
    connection.onNotification(
      "turn/tool_result",
      (p: {
        session_id?: string;
        name?: string;
        content?: string;
        is_error?: boolean;
        coverage?: string;
        event_count?: number;
        refs?: string[];
      }) => {
        this.inFlight.get(p?.session_id ?? "")?.onToolResult(
          p?.name ?? "", p?.content ?? "", p?.is_error ?? false, p?.coverage, p?.event_count, p?.refs,
        );
      },
    );
    connection.listen();

    // The stdio handshake (§4) — fail closed with the sidecar's diagnostic.
    const init = await connection.sendRequest("initialize", {
      protocol_version: PROTOCOL_VERSION,
      backend_url: this.deps.backendUrl(),
      model: this.deps.model(),
      anthropic_api_key: (await this.deps.apiKey()) ?? "",
    }) as { protocol_version?: number; backend_api_version?: number; server_version?: string };
    this.log.info(
      `sidecar ready: ${init.server_version ?? "?"} (protocol v${init.protocol_version}, backend api v${init.backend_api_version})`,
    );

    this.child = child;
    this.connection = connection;
    return connection;
  }

  private async ensureSession(conn: MessageConnection, investigationId: string): Promise<string> {
    const existing = this.sessions.get(investigationId);
    if (existing) {
      return existing;
    }
    const res = await conn.sendRequest("createSession", { investigation_id: investigationId }) as {
      session_id?: string;
      tools?: string[];
    };
    if (!res.session_id) {
      throw new Error("sidecar returned no session id");
    }
    this.log.info(`session ${res.session_id} over ${investigationId} (${res.tools?.length ?? 0} tools)`);
    this.sessions.set(investigationId, res.session_id);
    return res.session_id;
  }

  /** Drop the dead process's state; the next turn respawns and re-creates sessions. */
  private teardown(reason: string): void {
    this.connection?.dispose();
    this.connection = null;
    const child = this.child;
    this.child = null;
    this.sessions.clear();
    this.inFlight.clear();
    if (child && child.exitCode === null && !child.killed) {
      child.kill();
    }
    this.log.debug(`sidecar torn down (${reason})`);
  }

  private sidecarCommand(): string {
    const configured = vscode.workspace.getConfiguration("reckon").get<string>("sidecarPath", "");
    return configured.trim() !== "" ? configured.trim() : "reckon";
  }
}
