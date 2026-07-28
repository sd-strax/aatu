// Citation-open (design/ui 02 §2.8): any cited ref opens the underlying
// record — a raw OCSF telemetry event or a STIX object — read-only in a real
// editor tab, via a virtual document. "Editor-in-reach" (design/13 §5): raw
// evidence as real JSON, never a workspace file.

import * as vscode from "vscode";
import { BackendClient } from "./backend";

export const EVIDENCE_SCHEME = "reckon-evidence";

/** Serves reckon-evidence:/<ref>.json documents from GET /api/evidence. */
export class EvidenceProvider implements vscode.TextDocumentContentProvider {
  constructor(private readonly client: BackendClient) {}

  async provideTextDocumentContent(uri: vscode.Uri): Promise<string> {
    const ref = decodeURIComponent(uri.path.replace(/^\//, "").replace(/\.json$/, ""));
    try {
      const doc = await this.client.evidence(ref);
      // The payload is the record; the metadata rides alongside so the tab is
      // self-describing. Valid JSON — analysts pipe these into jq.
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
    } catch (err) {
      return JSON.stringify({
        ref,
        error: err instanceof Error ? err.message : String(err),
        note: "the ref could not be opened — it may predate telemetry persistence, or the backend is unreachable",
      }, null, 2);
    }
  }
}

/** Open one citation in a read-only editor tab beside the document. */
export async function openEvidence(ref: string): Promise<void> {
  const uri = vscode.Uri.from({
    scheme: EVIDENCE_SCHEME,
    path: "/" + encodeURIComponent(ref) + ".json",
  });
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.languages.setTextDocumentLanguage(doc, "json");
  await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
}
