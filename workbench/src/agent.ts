// The interactive turn loop (design/13 §7 step 3, 05 §3.4). BYOK Anthropic call
// → tool dispatch against the backend's capability descriptors → render the
// thread → commit the turn's transcript to /api/interpretations.
//
// This is the legal-author seam (03 §1): the AI authors interpretations as the
// analyst's delegate, never as a principal. Tool dispatch is READ-only here —
// capability verbs are T0 and need no gate. State-changing actions
// (request_action → Gate 2 → inline approval) are §7 step 4, a deliberate
// separate seam; this engine never calls /api/actions.
//
// Decoupled from VS Code: the engine speaks to a BackendClient and reports
// progress through callbacks, so the webview is a thin renderer over it.

import { randomUUID } from "crypto";
import Anthropic from "@anthropic-ai/sdk";
import { BackendClient, Capability, ToolCallRecord } from "./backend";

/** Progress callbacks the UI renders. Every one is optional except onError. */
export interface TurnHandlers {
  onReasoning?(delta: string): void; // summarized thinking
  onText?(delta: string): void; // assistant visible text
  onToolUse?(name: string, input: unknown): void;
  onToolResult?(name: string, coverage: string, eventCount: number): void;
  onCommitted?(interpretationId: string): void;
  onError(message: string): void;
}

/** rationaleMaxRunes mirrors the backend cap (aggregate: rationaleMaxRunes = 500). */
const RATIONALE_MAX = 500;
/** Bound the tool-result payload fed back to the LLM so one call can't blow the context. */
const TOOL_RESULT_MAX_CHARS = 48_000;
/** Backend caps input_refs at 100 (aggregate: maxRefsPerInterpretation). */
const MAX_REFS = 100;
/** Safety valve against a runaway tool loop within a single turn. */
const MAX_ITERATIONS = 12;

const SYSTEM_PROMPT = `You are reckon, an AI investigation partner for a threat hunter or incident responder.
You reason over a two-layer graph: immutable OCSF telemetry and a STIX-shaped interpretation layer.
Use the provided read tools to gather evidence before drawing conclusions. Each tool resolves a
capability verb against the tenant's configured data sources and returns normalized observations.
Ground every claim in evidence you actually retrieved — cite what a tool returned, and say so plainly
when a tool came back empty or degraded rather than inferring. Be concise: lead with the finding.
You cannot take state-changing actions in this turn; propose them in prose for the analyst to run.`;

export class Agent {
  private readonly client: Anthropic;
  private readonly history: Anthropic.MessageParam[] = [];
  private readonly transcriptId = randomUUID();
  private tools: Anthropic.Tool[] | null = null;
  private byVerb = new Map<string, Capability>();

  constructor(
    apiKey: string,
    private readonly model: string,
    private readonly backend: BackendClient,
    private readonly investigationId: string,
  ) {
    this.client = new Anthropic({ apiKey });
  }

  /**
   * Run one analyst turn to completion: stream the model, dispatch any read
   * tools it calls against the backend, loop until it stops asking for tools,
   * then commit the turn's transcript + tool calls as one interpretation.
   */
  async send(userText: string, handlers: TurnHandlers): Promise<void> {
    try {
      await this.ensureTools();
    } catch (err) {
      handlers.onError(`could not load capabilities: ${errText(err)}`);
      return;
    }

    this.history.push({ role: "user", content: userText });

    const turnId = randomUUID();
    const toolCalls: ToolCallRecord[] = [];
    const evidenceRefs = new Set<string>();
    let finalText = "";

    for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
      let message: Anthropic.Message;
      try {
        message = await this.streamOnce(handlers);
      } catch (err) {
        handlers.onError(`model call failed: ${errText(err)}`);
        return;
      }

      // Preserve the full assistant turn (thinking + text + tool_use) in history.
      this.history.push({ role: "assistant", content: message.content });

      finalText = textOf(message) || finalText;

      if (message.stop_reason !== "tool_use") {
        break;
      }

      // Dispatch every tool_use the model asked for, return all results in one
      // user turn (parallel tool use — 05 §3.4).
      const results: Anthropic.ToolResultBlockParam[] = [];
      for (const block of message.content) {
        if (block.type !== "tool_use") {
          continue;
        }
        handlers.onToolUse?.(block.name, block.input);
        toolCalls.push({ callId: block.id, toolName: block.name, args: block.input });
        const { content, isError, coverage, eventCount, refs } = await this.dispatch(block);
        for (const ref of refs) {
          evidenceRefs.add(ref);
        }
        handlers.onToolResult?.(block.name, coverage, eventCount);
        results.push({ type: "tool_result", tool_use_id: block.id, content, is_error: isError });
      }
      this.history.push({ role: "user", content: results });
    }

    // Commit the turn: the same record the eval harness grades (10 §3).
    try {
      const { interpretationId } = await this.backend.recordInterpretation({
        investigationRef: this.investigationId,
        interpretationType: "other",
        rationale: truncateRunes(finalText.trim() || "(no summary)", RATIONALE_MAX),
        inputRefs: [...evidenceRefs].slice(0, MAX_REFS),
        transcript: {
          transcriptId: this.transcriptId,
          turnId,
          body: JSON.stringify({ user: userText, messages: this.history }, null, 2),
        },
        toolCalls,
      });
      handlers.onCommitted?.(interpretationId);
    } catch (err) {
      handlers.onError(`turn committed to the model but not to the thread: ${errText(err)}`);
    }
  }

  /** One streaming model call; renders deltas as they arrive, returns the final message. */
  private async streamOnce(handlers: TurnHandlers): Promise<Anthropic.Message> {
    const stream = this.client.messages.stream({
      model: this.model,
      max_tokens: 64_000,
      thinking: { type: "adaptive", display: "summarized" },
      system: SYSTEM_PROMPT,
      tools: this.tools ?? [],
      messages: this.history,
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta") {
        if (event.delta.type === "text_delta") {
          handlers.onText?.(event.delta.text);
        } else if (event.delta.type === "thinking_delta") {
          handlers.onReasoning?.(event.delta.thinking);
        }
      }
    }
    return stream.finalMessage();
  }

  /** Dispatch one read tool_use to the backend and shape its result for the model. */
  private async dispatch(block: Anthropic.ToolUseBlock): Promise<{
    content: string;
    isError: boolean;
    coverage: string;
    eventCount: number;
    refs: string[];
  }> {
    const cap = this.byVerb.get(block.name);
    if (!cap) {
      return { content: `unknown verb "${block.name}"`, isError: true, coverage: "ERROR", eventCount: 0, refs: [] };
    }
    const body = toInvokeBody(cap, (block.input ?? {}) as Record<string, unknown>);
    try {
      const result = await this.backend.invokeCapability(cap.verb, body);
      const refs = [...result.observedDataRefs, ...result.entityRefs, ...result.ocsfEventRefs].filter(
        (r) => r.length <= 256,
      );
      const summary = {
        coverage: result.coverage,
        degradation_notes: result.degradationNotes,
        event_count: result.events.length,
        observed_data_refs: result.observedDataRefs.slice(0, 50),
        entity_refs: result.entityRefs.slice(0, 50),
        events: result.events,
        normalized: result.normalized,
      };
      return {
        content: boundedJSON(summary),
        isError: false,
        coverage: result.coverage,
        eventCount: result.events.length,
        refs,
      };
    } catch (err) {
      return { content: `dispatch failed: ${errText(err)}`, isError: true, coverage: "ERROR", eventCount: 0, refs: [] };
    }
  }

  /** Fetch the tenant's available verbs once and turn them into tool definitions. */
  private async ensureTools(): Promise<void> {
    if (this.tools) {
      return;
    }
    const caps = (await this.backend.capabilities()).filter((c) => c.status === "available");
    this.byVerb = new Map(caps.map((c) => [c.verb, c]));
    this.tools = caps.map(toToolDefinition);
  }
}

/** Build an Anthropic tool definition from a capability descriptor. */
function toToolDefinition(cap: Capability): Anthropic.Tool {
  const properties: Record<string, unknown> = {};
  const required: string[] = [];
  for (const input of cap.inputs) {
    if (input.type === "time_window") {
      properties.window = {
        type: "object",
        description: "Optional time bound (ISO-8601). Omit to use the tenant investigation window.",
        properties: { from: { type: "string" }, to: { type: "string" } },
      };
      continue;
    }
    if (input.type === "entity") {
      properties[input.name] = {
        type: "object",
        description: `${input.desc ?? ""} — a canonical entity object, e.g. {"host":{"hostname":"..."}} or {"ip":{"value":"..."}}.`.trim(),
      };
    } else if (input.type === "int") {
      properties[input.name] = { type: "integer", description: input.desc };
    } else {
      properties[input.name] = { type: "string", description: input.desc };
    }
    if (input.required) {
      required.push(input.name);
    }
  }
  return {
    name: cap.verb,
    description: `${cap.intent}\nReturns: ${cap.output}`,
    input_schema: { type: "object", properties, required },
  };
}

/**
 * Translate a tool_use input into the capability invoke body: entity inputs
 * merge into `entity`, the window into `window`, everything else into `extra`
 * — matching the template roots the resolver resolves against (03 §3.3).
 */
function toInvokeBody(
  cap: Capability,
  input: Record<string, unknown>,
): { entity?: Record<string, unknown>; window?: { from: string; to: string }; extra?: Record<string, unknown> } {
  const entity: Record<string, unknown> = {};
  const extra: Record<string, unknown> = {};
  let window: { from: string; to: string } | undefined;

  for (const spec of cap.inputs) {
    const v = spec.type === "time_window" ? input.window : input[spec.name];
    if (v === undefined || v === null) {
      continue;
    }
    if (spec.type === "entity" && typeof v === "object") {
      Object.assign(entity, v);
    } else if (spec.type === "time_window" && typeof v === "object") {
      const w = v as { from?: string; to?: string };
      if (w.from && w.to) {
        window = { from: w.from, to: w.to };
      }
    } else {
      extra[spec.name] = v;
    }
  }

  return {
    entity: Object.keys(entity).length ? entity : undefined,
    window,
    extra: Object.keys(extra).length ? extra : undefined,
  };
}

function boundedJSON(value: unknown): string {
  const full = JSON.stringify(value);
  if (full.length <= TOOL_RESULT_MAX_CHARS) {
    return full;
  }
  // Too big to feed back whole — drop the bulky arrays, keep the classification.
  const v = value as { events?: unknown[]; normalized?: unknown[] };
  return JSON.stringify({
    ...(value as object),
    events: `[${v.events?.length ?? 0} events omitted — result exceeded ${TOOL_RESULT_MAX_CHARS} chars]`,
    normalized: `[${v.normalized?.length ?? 0} normalized objects omitted]`,
  });
}

function textOf(message: Anthropic.Message): string {
  return message.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");
}

function truncateRunes(s: string, max: number): string {
  const runes = [...s];
  return runes.length <= max ? s : runes.slice(0, max - 1).join("") + "…";
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
