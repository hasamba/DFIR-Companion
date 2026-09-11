import type { Severity } from "./stateTypes.js";
import type { ControlDisposition } from "./stateTypes.js";

// Microsoft Defender Antivirus Operational events (#930 item 1, part A). A detection (1116/1006/1015)
// and the action taken on it (1117/1007), or the action's failure (1118/1008/1119), arrive as ordinary
// Windows events; before this module they graded Info with the rendered message's first line as their
// label — threat, path, action and result unread — and Info never reaches the forensic timeline, so
// the model never saw that Defender had found anything.
//
// WHAT THE DISPOSITION MEANS. The first token of the label is `[control: <disposition>]`, spelled
// from the outcome vocabulary (#943), and it comes from the ACTION and its RESULT, never from the
// event id: a 1117 "action taken" event whose action is Allow is `allowed`, not a cleanup; one whose
// action is NoAction is `none-observed` (no control action seen), not an allow; one whose Error Code is
// not zero is `remediation-failed`, whatever the action name promised. A detection alone is `unknown`
// — the action is a later event.
//
// WHAT IT DOES NOT MEAN. Every Defender event is Medium: a detection is the scanner's claim and a
// disposition is not a verdict — `allowed` is not a compromise, `remediated` is not proof the
// payload never ran. No second AV alert is not evidence that execution succeeded. The scanner runs
// as SYSTEM, so its identity is never the person who launched the file (the process event's own
// account is). A drive letter is not removable media. Linking a detection to a later start of the
// same file is #964, and it reads the typed fields this module fills, not this label.
//
// THE PATH FIELD is structured: `file:_C:\a\x.exe`; `containerfile:_C:\a.zip; file:_C:\a.zip->x.exe`
// (a member inside its container — the member is the file, the container is where it sat);
// `process:_pid:1234,ProcessStart:…`. One row per record: the PRIMARY file (the first archive
// member, else the first file) becomes the event's path; the container and every further resource
// are listed in the label, bounded — this module matches nothing, so listing loses nothing here.

export type DefenderControl = ControlDisposition;

export interface DefenderEventDef {
  label: string;
  severity: Severity;
  mitre?: string[];
  kind?: "file";
}

export interface DecodedDefenderEvent {
  def: DefenderEventDef;
  /** The Defender identity for the aggregation key: two actions on one file are two rows. */
  identity: string;
  /** The primary file path — what the event's `path` becomes. Undefined for a process-only detection. */
  image: string | undefined;
  /** For the canonical envelope: `event.outcome` keeps the success/failed/unknown hunt contract. */
  event: { action: string; outcome: "success" | "failed" | "unknown" };
  eventType: "detection" | "action";
  object: { kind: "file"; id?: string; name: string };
  disposition: DefenderControl;
}

export interface DefenderPath {
  primary: string | undefined;
  container: string | undefined;
  /** Every file resource, in order, bounded. */
  resources: string[];
  processes: string[];
}

const DEFENDER_CHANNEL = /windows defender/i;
const DETECTED = new Set([1116, 1006, 1015]);
const ACTION_TAKEN = new Set([1117, 1007]);
const ACTION_FAILED = new Set([1118, 1008, 1119]);
const MAX_RESOURCES = 8;
const THREAT_MAX = 120;
const PATH_MAX = 300;
const ERROR_MAX = 160;
const LABEL_MAX = 600;

// Field lookup that survives the renderer's spelling: the EVTX renderer keeps the spaces ("Threat
// Name"), some exporters drop them ("ThreatName") or underscore them ("threat_name").
function field(ed: Record<string, unknown>, name: string): string {
  const want = name.toLowerCase().replace(/[\s_]/g, "");
  for (const [k, v] of Object.entries(ed)) {
    if (k.toLowerCase().replace(/[\s_]/g, "") !== want) continue;
    if (v === null || v === undefined) return "";
    return typeof v === "object"
      ? String((v as { "#text"?: unknown })["#text"] ?? "").trim()
      : String(v).trim();
  }
  return "";
}

/** Parse Defender's `Path` field into its resources. Pure; never throws. */
export function parseDefenderPath(raw: string): DefenderPath {
  const resources: string[] = [];
  const processes: string[] = [];
  let container: string | undefined;
  let firstMember: string | undefined;
  for (const part of raw.split(";")) {
    const m =
      /^\s*(file|containerfile|process|regkey|regkeyvalue|webfile|behavior|service|internalbehavior|amsi)\s*:_?(.*)$/i.exec(
        part,
      );
    if (!m) continue;
    const kind = m[1].toLowerCase();
    const value = m[2].trim().slice(0, PATH_MAX);
    if (!value) continue;
    if (kind === "process") processes.push(value);
    else if (kind === "containerfile") container ??= value;
    else if (kind === "file" || kind === "webfile") {
      if (resources.length < MAX_RESOURCES) resources.push(value);
      if (value.includes("->")) firstMember ??= value;
    }
  }
  // A container named with no member listed is itself the file that was flagged.
  if (!resources.length && container) resources.push(container);
  const primary = firstMember ?? resources[0];
  return {
    primary,
    container: container && container !== primary ? container : undefined,
    resources,
    processes,
  };
}

function disposition(
  eid: number,
  action: string,
  errorCode: string,
): { control: DefenderControl; outcome: "success" | "failed" | "unknown" } {
  if (DETECTED.has(eid)) return { control: "unknown", outcome: "unknown" };
  const failedCode = errorCode !== "" && !/^(?:0x)?0+$/i.test(errorCode);
  if (ACTION_FAILED.has(eid) || failedCode) return { control: "remediation-failed", outcome: "failed" };
  const a = action.toLowerCase();
  if (/^(?:allow|allowandclean|allowed)$/.test(a)) return { control: "allowed", outcome: "success" };
  if (/^(?:noaction|none|no action)$/.test(a) || a === "")
    return { control: "none-observed", outcome: "unknown" };
  if (a === "block") return { control: "blocked", outcome: "success" };
  return { control: "remediated", outcome: "success" }; // Quarantine, Remove, Clean, and the rest
}

/**
 * Decode one Defender Operational event, or null when the channel or the event id is not one this
 * module knows. `eventData` is the record's event_data object under any of the renderers' spellings.
 */
export function decodeDefenderEvent(
  channel: string,
  eid: number,
  eventData: Record<string, unknown>,
): DecodedDefenderEvent | null {
  if (!DEFENDER_CHANNEL.test(channel)) return null;
  if (!DETECTED.has(eid) && !ACTION_TAKEN.has(eid) && !ACTION_FAILED.has(eid)) return null;
  const threat = field(eventData, "Threat Name").slice(0, THREAT_MAX) || "(unknown threat)";
  const severityName = field(eventData, "Severity Name").slice(0, 40);
  const action = field(eventData, "Action Name").slice(0, 40);
  const errorCode = field(eventData, "Error Code").slice(0, 20);
  const errorText = field(eventData, "Error Description").slice(0, ERROR_MAX);
  const detectionId = field(eventData, "Detection ID").slice(0, 80);
  const path = parseDefenderPath(field(eventData, "Path"));
  const { control, outcome } = disposition(eid, action, errorCode);

  const verb = DETECTED.has(eid)
    ? eid === 1015
      ? "detected suspicious behaviour"
      : "detected"
    : action || "action";
  const extras = path.resources.filter((r) => r !== path.primary);
  const parts = [
    `[control: ${control}]`,
    `${verb} ${threat}${severityName ? ` [${severityName}]` : ""}`,
    path.primary ? `— ${path.primary}` : "",
    path.container ? `(in ${path.container})` : "",
    extras.length ? `(+${extras.length} more: ${extras.join(", ")})` : "",
    path.processes.length ? `process ${path.processes.join(", ")}` : "",
    control === "remediation-failed" && (errorCode || errorText)
      ? `error ${errorCode} ${errorText}`.trim()
      : "",
  ].filter(Boolean);
  const label = parts.join(" ").slice(0, LABEL_MAX);

  return {
    def: { label, severity: "Medium", kind: "file" },
    identity: `defender|${detectionId || threat}|${control}|${action}|${errorCode}|${(path.primary ?? "").toLowerCase()}`,
    image: path.primary,
    eventType: DETECTED.has(eid) ? "detection" : "action",
    event: { action: DETECTED.has(eid) ? "detected" : action || "action", outcome },
    object: { kind: "file", ...(detectionId ? { id: detectionId } : {}), name: threat },
    disposition: control,
  };
}
