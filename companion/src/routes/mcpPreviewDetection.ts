import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";

export { logSiemFallback } from "./importDebugEmit.js";
export { siemFallbackWarning } from "./importNotes.js";

/**
 * The detection decision a staged MCP preview keeps until the analyst approves it (#1824).
 *
 * Detection runs when the tool's output arrives; approval runs later, in another request, with a
 * fresh recorder. Without the stored decision the approval cannot tell a guessed SIEM kind from a
 * confident one, so the #1795 warning never reached an approved preview.
 */
export interface PreviewDetection {
  detection?: { confident: boolean; decision: string };
}

/** The part of the preview metadata to stage: the recorder's detection decision, if it has one. */
export function stagedDetection(debug: ImportDebugRecorder): PreviewDetection {
  const detection = debug.summary().detection;
  return detection ? { detection: { confident: detection.confident, decision: detection.decision } } : {};
}

/**
 * The approval's own recorder (#1736), seeded with the staged decision. The metadata file is read
 * back from disk, so a malformed `detection` is ignored rather than trusted.
 */
export function approvalRecorder(p: PreviewDetection & { kind: string }): ImportDebugRecorder {
  const debug = createImportDebugRecorder();
  const d = p.detection;
  if (d && typeof d.confident === "boolean" && typeof d.decision === "string")
    debug.detected(p.kind, { confident: d.confident, decision: d.decision });
  return debug;
}
