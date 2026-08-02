// Citation-open, rendered (design/ui 02 §2.8, design/13 §5). Clicking a cited
// ref used to dump raw JSON into an editor tab. This renders the same record as
// a titled card — human title, provenance, structured fields, and the
// cross-investigation memory (who else has seen this entity) — in a single
// reused webview beside the document. The raw JSON stays one click away
// ("editor-in-reach"): analysts who want to pipe into jq still can.

import * as vscode from "vscode";
import { Appearance, BackendClient, EvidenceDoc } from "./backend";
import { openEvidence } from "./evidenceProvider";

export class EvidenceView {
  private panel?: vscode.WebviewPanel;
  // Monotonic request token: the panel is reused across clicks, so a slower
  // fetch for an EARLIER click must never clobber the card the analyst asked
  // for last. Only the newest request's result renders.
  private openSeq = 0;

  constructor(private readonly client: BackendClient) {}

  /**
   * Open (or reveal) the evidence card for one ref. currentInvestigationId,
   * when known (a click inside an investigation document), is filtered out of
   * the cross-investigation appearances — "also seen in" means OTHER
   * investigations, and without the filter a ref cited only here would claim
   * one phantom sighting.
   */
  async open(ref: string, currentInvestigationId?: string): Promise<void> {
    if (!this.panel) {
      this.panel = vscode.window.createWebviewPanel(
        "reckon.evidence",
        "Evidence",
        { viewColumn: vscode.ViewColumn.Beside, preserveFocus: false },
        { enableScripts: true, retainContextWhenHidden: true },
      );
      this.panel.webview.html = this.html(this.panel.webview);
      this.panel.webview.onDidReceiveMessage((m: { type?: string; ref?: string }) => {
        if (m?.type === "openRaw" && typeof m.ref === "string") {
          void openEvidence(m.ref);
        }
      });
      this.panel.onDidDispose(() => {
        this.panel = undefined;
      });
    }
    const panel = this.panel;
    const seq = ++this.openSeq;
    // Stale = a newer click superseded this request, or the panel was closed
    // mid-fetch (this.panel cleared by onDidDispose) — in both cases the
    // result must be dropped, never rendered into the wrong (or dead) panel.
    const stale = () => this.panel !== panel || this.openSeq !== seq;
    panel.reveal(vscode.ViewColumn.Beside, false);
    void panel.webview.postMessage({ type: "loading", ref });

    try {
      // The record is load-bearing; appearances are best-effort colour.
      const [doc, appearances] = await Promise.all([
        this.client.evidence(ref),
        this.client.appearances(ref).catch(() => [] as Appearance[]),
      ]);
      if (stale()) {
        return;
      }
      const others = currentInvestigationId
        ? appearances.filter((a) => a.investigationId !== currentInvestigationId)
        : appearances;
      panel.title = shortTitle(doc);
      void panel.webview.postMessage({ type: "evidence", doc, appearances: others, raw: rawJSON(doc) });
    } catch (err) {
      if (stale()) {
        return;
      }
      void panel.webview.postMessage({
        type: "error",
        ref,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

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
    :root {
      --fg: var(--vscode-foreground);
      --bg: var(--vscode-editor-background);
      --mono: var(--vscode-editor-font-family, ui-monospace, monospace);
      --border: var(--vscode-panel-border, color-mix(in srgb, var(--fg) 16%, transparent));
      --muted: color-mix(in srgb, var(--fg) 55%, transparent);
      --fill: color-mix(in srgb, var(--fg) 5%, transparent);
      --accent: var(--vscode-textLink-foreground, #4aa8ff);
    }
    * { box-sizing: border-box; }
    body { color: var(--fg); background: var(--bg); font-family: var(--vscode-font-family); font-size: 13px; padding: 14px 18px 40px; line-height: 1.5; }
    .kicker { font-size: 10px; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase; color: var(--muted); }
    h1 { font-size: 19px; margin: 2px 0 4px; font-weight: 600; word-break: break-word; }
    .sub { color: var(--muted); font-size: 12px; margin-bottom: 10px; }
    .badge { display: inline-block; font-family: var(--mono); font-size: 10.5px; padding: 1px 6px; border: 1px solid var(--border); border-radius: 4px; background: var(--fill); vertical-align: middle; }
    .toolbar { display: flex; gap: 8px; align-items: center; margin: 8px 0 14px; flex-wrap: wrap; }
    .ref { font-family: var(--mono); font-size: 11px; color: var(--muted); background: var(--fill); border: 1px solid var(--border); border-radius: 4px; padding: 2px 7px; word-break: break-all; }
    button { font: inherit; font-size: 11.5px; color: var(--accent); background: none; border: 1px solid var(--border); border-radius: 4px; padding: 3px 9px; cursor: pointer; }
    button:hover { background: var(--fill); }
    .prov { border: 1px solid var(--border); border-left: 2px solid var(--accent); border-radius: 4px; background: var(--fill); padding: 7px 11px; font-size: 12px; margin: 0 0 16px; }
    .prov .lbl { color: var(--muted); }
    section { margin: 0 0 18px; }
    section > .kicker { display: block; margin-bottom: 7px; }
    dl { margin: 0; display: grid; grid-template-columns: minmax(120px, 34%) 1fr; gap: 3px 14px; }
    dt { font-family: var(--mono); font-size: 11.5px; color: var(--muted); word-break: break-word; }
    dd { margin: 0; word-break: break-word; }
    dd.mono { font-family: var(--mono); font-size: 11.5px; }
    .nest { grid-column: 1 / -1; margin: 3px 0 3px 2px; padding-left: 10px; border-left: 1px solid var(--border); }
    .nest > .nlabel { font-family: var(--mono); font-size: 11px; color: var(--muted); margin-bottom: 3px; }
    .appear { border: 1px solid var(--border); border-radius: 5px; padding: 8px 11px; margin-bottom: 6px; }
    .appear .at { font-weight: 600; }
    .appear .meta { color: var(--muted); font-size: 11.5px; margin-top: 2px; }
    details { margin-top: 10px; border-top: 1px solid var(--border); padding-top: 10px; }
    summary { cursor: pointer; color: var(--muted); font-size: 12px; }
    pre { font-family: var(--mono); font-size: 11.5px; background: var(--fill); border: 1px solid var(--border); border-radius: 5px; padding: 10px; overflow-x: auto; margin-top: 8px; }
    .empty { color: var(--muted); font-style: italic; }
    .err { border: 1px solid color-mix(in srgb, #e5534b 45%, var(--border)); border-radius: 5px; padding: 12px; background: color-mix(in srgb, #e5534b 8%, transparent); }
  </style>
</head>
<body>
  <div id="root"><p class="empty">Loading…</p></div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const root = document.getElementById("root");

    function el(tag, cls, text) {
      const e = document.createElement(tag);
      if (cls) e.className = cls;
      if (text !== undefined) e.textContent = text;
      return e;
    }
    function human(k) { return String(k).replace(/[_.]/g, " "); }
    function looksMono(v) {
      const s = String(v);
      return /--|[0-9a-f]{16,}|^\\d+$|:|\\\\|\\//.test(s) && !/\\s/.test(s.trim()) || s.length > 40;
    }

    function stixTitle(type, p) {
      p = p || {};
      switch (type) {
        case "x-host": return p.hostname || p.name || type;
        case "ipv4-addr": case "ipv6-addr": case "domain-name": case "url": case "email-addr": return p.value || type;
        case "user-account": return p.display_name || p.user_id || p.account_login || type;
        case "file": return p.name || (p.hashes && Object.values(p.hashes)[0]) || type;
        case "process": return p.command_line || (p.pid !== undefined ? "pid " + p.pid : type);
        case "x-hypothesis": return p.statement || p.text || "Hypothesis";
        case "x-prediction": return p.statement || p.text || "Prediction";
        case "observed-data": return "Observation" + (p.number_observed ? " ×" + p.number_observed : "");
        default: return p.name || p.value || type;
      }
    }

    // A generic, depth-limited field renderer — informative for any record
    // without per-type code. Primitives become dt/dd; nested objects recurse.
    function renderFields(dl, obj, depth) {
      const entries = Object.entries(obj || {}).filter(([, v]) => v !== null && v !== undefined && v !== "");
      if (!entries.length) { dl.appendChild(el("dd", "empty", "—")); return; }
      for (const [k, v] of entries) {
        if (Array.isArray(v)) {
          if (v.every((x) => typeof x !== "object")) {
            dl.appendChild(el("dt", null, human(k)));
            dl.appendChild(el("dd", "mono", v.join(", ")));
          } else {
            const nest = el("div", "nest");
            nest.appendChild(el("div", "nlabel", human(k) + " (" + v.length + ")"));
            v.forEach((x, i) => {
              const sub = el("dl");
              renderFields(sub, typeof x === "object" ? x : { ["#" + i]: x }, depth + 1);
              nest.appendChild(sub);
            });
            dl.appendChild(nest);
          }
        } else if (typeof v === "object") {
          if (depth >= 2) {
            dl.appendChild(el("dt", null, human(k)));
            dl.appendChild(el("dd", "mono", JSON.stringify(v)));
          } else {
            const nest = el("div", "nest");
            nest.appendChild(el("div", "nlabel", human(k)));
            const sub = el("dl");
            renderFields(sub, v, depth + 1);
            nest.appendChild(sub);
            dl.appendChild(nest);
          }
        } else {
          dl.appendChild(el("dt", null, human(k)));
          dl.appendChild(el("dd", looksMono(v) ? "mono" : null, String(v)));
        }
      }
    }

    function section(title, buildBody) {
      const s = el("section");
      s.appendChild(el("div", "kicker", title));
      buildBody(s);
      return s;
    }

    function renderEvidence(m) {
      const doc = m.doc, isOcsf = doc.kind === "ocsf";
      const object = (doc.payload && typeof doc.payload === "object") ? doc.payload : {};
      const props = isOcsf ? object : (object.properties || {});
      const type = isOcsf ? doc.type : (object.type || doc.type);
      const title = isOcsf ? human(doc.type) : stixTitle(type, props);

      root.textContent = "";

      root.appendChild(el("div", "kicker", isOcsf ? "Telemetry · OCSF event" : "Interpretation · STIX object"));
      root.appendChild(el("h1", null, title));
      const sub = el("div", "sub");
      sub.appendChild(el("span", "badge", type));
      if (isOcsf && doc.classUid) sub.appendChild(document.createTextNode("  class " + doc.classUid));
      if (isOcsf && doc.time) sub.appendChild(document.createTextNode("  ·  " + doc.time));
      if (!isOcsf && props.domain) sub.appendChild(document.createTextNode("  ·  " + props.domain));
      root.appendChild(sub);

      const bar = el("div", "toolbar");
      bar.appendChild(el("span", "ref", doc.ref));
      const raw = el("button", null, "Open raw JSON tab");
      raw.addEventListener("click", () => vscode.postMessage({ type: "openRaw", ref: doc.ref }));
      bar.appendChild(raw);
      root.appendChild(bar);

      // Provenance: STIX carries it inline; OCSF carries the source tool.
      const prov = object.provenance;
      if (!isOcsf && prov && typeof prov === "object") {
        const p = el("div", "prov");
        const bits = [];
        if (prov.tool) bits.push("observed via " + prov.tool);
        if (prov.normalizer) bits.push("normalized by " + prov.normalizer + (prov.normalizer_version ? " v" + prov.normalizer_version : ""));
        if (prov.observed_at) bits.push("at " + prov.observed_at);
        if (prov.derivation_mode) bits.push(prov.derivation_mode);
        p.appendChild(el("span", "lbl", "Provenance — "));
        p.appendChild(document.createTextNode(bits.join(" · ")));
        root.appendChild(p);
      } else if (isOcsf && (doc.sourceTool || doc.recordedAt)) {
        const p = el("div", "prov");
        p.appendChild(el("span", "lbl", "Provenance — "));
        p.appendChild(document.createTextNode(
          [doc.sourceTool && "from " + doc.sourceTool, doc.recordedAt && "recorded " + doc.recordedAt].filter(Boolean).join(" · ")));
        root.appendChild(p);
      }

      root.appendChild(section(isOcsf ? "Event fields" : "Properties", (s) => {
        const dl = el("dl");
        renderFields(dl, props, 0);
        s.appendChild(dl);
      }));

      const ap = m.appearances || [];
      root.appendChild(section("Cross-investigation memory", (s) => {
        if (!ap.length) { s.appendChild(el("p", "empty", "First seen here — no other investigation has cited this.")); return; }
        s.querySelector(".kicker").textContent = "Also seen in " + ap.length + " other investigation" + (ap.length === 1 ? "" : "s");
        for (const a of ap) {
          const row = el("div", "appear");
          row.appendChild(el("div", "at", a.title || a.investigationId));
          const meta = [];
          if (a.status) meta.push(a.status);
          meta.push(a.mentions + (a.mentions === 1 ? " mention" : " mentions"));
          if (a.lastSeen) meta.push("last " + a.lastSeen);
          row.appendChild(el("div", "meta", meta.join("  ·  ")));
          s.appendChild(row);
        }
      }));

      const det = el("details");
      det.appendChild(el("summary", null, "Raw JSON"));
      det.appendChild(el("pre", null, m.raw));
      root.appendChild(det);
    }

    window.addEventListener("message", (ev) => {
      const m = ev.data;
      if (m.type === "loading") {
        root.textContent = ""; root.appendChild(el("p", "empty", "Loading " + m.ref + " …"));
      } else if (m.type === "evidence") {
        renderEvidence(m);
      } else if (m.type === "error") {
        root.textContent = "";
        const box = el("div", "err");
        box.appendChild(el("div", "kicker", "Could not open evidence"));
        box.appendChild(el("p", null, m.message));
        box.appendChild(el("p", "empty", "The ref may predate telemetry persistence, or the backend is unreachable."));
        root.appendChild(box);
      }
    });
  </script>
</body>
</html>`;
  }
}

/** The exact JSON the raw tab shows, so the card and the tab never disagree. */
function rawJSON(doc: EvidenceDoc): string {
  return JSON.stringify(
    doc.kind === "ocsf"
      ? {
          ref: doc.ref, kind: doc.kind, class_uid: doc.classUid, class_name: doc.type,
          time: doc.time, recorded_at: doc.recordedAt, source_tool: doc.sourceTool,
          payload: doc.payload,
        }
      : { ref: doc.ref, kind: doc.kind, type: doc.type, object: doc.payload },
    null, 2,
  );
}

/** Tab title: the human-facing name, falling back to the type. */
function shortTitle(doc: EvidenceDoc): string {
  const object = (doc.payload && typeof doc.payload === "object") ? (doc.payload as Record<string, unknown>) : {};
  if (doc.kind === "ocsf") return doc.type || "OCSF event";
  const props = (object.properties && typeof object.properties === "object")
    ? (object.properties as Record<string, unknown>) : {};
  const s = props.hostname ?? props.value ?? props.name ?? props.user_id ?? props.display_name;
  return (typeof s === "string" && s) ? s : (doc.type || "STIX object");
}

function makeNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < 32; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}
