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
  /** The detection as a canonical entity — a file when one was flagged, else the first other resource's kind. */
  object: { kind: "file" | "registry" | "service" | "other"; id?: string; name: string };
  disposition: DefenderControl;
}

export interface DefenderPath {
  primary: string | undefined;
  container: string | undefined;
  /** Every file resource, in order, bounded. */
  resources: string[];
  processes: string[];
  /** Registry keys, services, behaviours, AMSI content — `kind:value`, bounded. Never silently dropped. */
  others: string[];
}

const DEFENDER_CHANNEL = /windows defender/i;
const DETECTED = new Set([1116, 1006, 1015]);
const ACTION_TAKEN = new Set([1117, 1007]);
const ACTION_FAILED = new Set([1118, 1008, 1119]);
const MAX_RESOURCES = 8;
const THREAT_MAX = 120;
const PATH_MAX = 300;
const ERROR_MAX = 160;
// mapWindows appends `(EID …, Microsoft Defender)`, the account, the subject and the host after this
// label and clips the whole description at 600; the label leaves that room so the tail survives.
const LABEL_MAX = 460;

// Defender's action vocabulary (Action ID → name): 1 Clean, 2 Quarantine, 3 Remove, 6 Allow,
// 8 UserDefined, 9 NoAction, 10 Block. A name outside this table is NOT guessed at.
const REMEDIATING_ACTIONS = new Set(["clean", "quarantine", "remove"]);
const ALLOW_ACTIONS = new Set(["allow", "allowandclean", "allowed"]);
const NO_ACTIONS = new Set(["noaction", "none", "no action"]);
// UserDefined (8) is deliberately absent: the user decides, and the log does not say what.

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
  const others: string[] = [];
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
    } else if (others.length < MAX_RESOURCES) others.push(`${kind}:${value}`);
  }
  // A container named with no member listed is itself the file that was flagged.
  if (!resources.length && container) resources.push(container);
  const primary = firstMember ?? resources[0];
  return {
    primary,
    container: container && container !== primary ? container : undefined,
    resources,
    processes,
    others,
  };
}

// A Defender Error Code is an HRESULT, written `0x80508023` or as a decimal; anything else is not a
// result at all and must not be read as one.
function errorOutcome(errorCode: string): "success" | "failed" | "unknown" {
  if (errorCode === "") return "success";
  if (/^(?:0x)?0+$/i.test(errorCode)) return "success";
  if (/^0x[0-9a-f]{1,8}$/i.test(errorCode) || /^\d{1,10}$/.test(errorCode)) return "failed";
  return "unknown";
}

// The disposition from the ACTION and its RESULT, never the event id. Only a known action with a
// parseable result earns a definite word; an action outside Defender's table, a user-defined
// action, or a malformed error code is `unknown` — a confident wrong outcome is worse than none.
function disposition(
  eid: number,
  action: string,
  errorCode: string,
): { control: DefenderControl; outcome: "success" | "failed" | "unknown" } {
  const unknown = { control: "unknown" as const, outcome: "unknown" as const };
  if (DETECTED.has(eid)) return unknown;
  // The ACTION is validated first: a result can only qualify an action Defender itself names.
  // UserDefined means the user decides and the log does not say what; an action outside the
  // table is not guessed at — with any result, even a failure code or a failed-action event id.
  const a = action.toLowerCase();
  const known = REMEDIATING_ACTIONS.has(a) || ALLOW_ACTIONS.has(a) || NO_ACTIONS.has(a) || a === "block";
  if (!known) return unknown;
  const result = errorOutcome(errorCode);
  if (ACTION_FAILED.has(eid)) return { control: "remediation-failed", outcome: "failed" };
  if (result === "failed") return { control: "remediation-failed", outcome: "failed" };
  if (result === "unknown") return unknown;
  if (ALLOW_ACTIONS.has(a)) return { control: "allowed", outcome: "success" };
  if (NO_ACTIONS.has(a)) return { control: "none-observed", outcome: "unknown" };
  if (a === "block") return { control: "blocked", outcome: "success" };
  return { control: "remediated", outcome: "success" };
}

// Where a Defender detection lives as a canonical entity: the flagged file, else the kind of the
// first non-file resource — a registry-only detection is a registry object, never a file.
function objectKind(path: DefenderPath): "file" | "registry" | "service" | "other" {
  if (path.primary) return "file";
  const first = path.others[0]?.split(":")[0] ?? "";
  if (first === "regkey" || first === "regkeyvalue") return "registry";
  if (first === "service") return "service";
  return "other";
}

/**
 * The full description of a Defender event, composed so the invariant tail — the event id and
 * tool, the account, the subject, the host — always survives the 600-character clip: every part is
 * bounded on its own and the attacker-shaped label yields first. mapWindows calls this instead of
 * its generic label-then-append-then-clip composition.
 */
export function defenderDescription(
  label: string,
  eid: number,
  accounts: readonly string[],
  subject: string,
  host: string,
): string {
  const tail =
    ` (EID ${eid}, Microsoft Defender)` +
    (accounts.length ? ` - ${accounts.join(", ").slice(0, 80)}` : "") +
    (subject ? ` - ${subject.slice(0, 150)}` : "") +
    (host ? ` @ ${host.slice(0, 80)}` : "");
  return `${label.slice(0, Math.max(120, 600 - tail.length))}${tail}`.slice(0, 600);
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
    path.others.length ? path.others.join(", ") : "",
    control === "remediation-failed" && (errorCode || errorText)
      ? `error ${errorCode} ${errorText}`.trim()
      : "",
  ].filter(Boolean);
  const label = parts.join(" ").slice(0, LABEL_MAX);

  return {
    // `kind: "file"` only when a file was flagged: a registry- or service-only detection is not a file event.
    def: { label, severity: "Medium", ...(path.primary ? { kind: "file" as const } : {}) },
    identity: `defender|${detectionId || threat}|${control}|${action}|${errorCode}|${(path.primary ?? "").toLowerCase()}|${path.others.join(",").toLowerCase()}`,
    image: path.primary,
    eventType: DETECTED.has(eid) ? "detection" : "action",
    event: { action: DETECTED.has(eid) ? "detected" : action || "action", outcome },
    object: { kind: objectKind(path), ...(detectionId ? { id: detectionId } : {}), name: threat },
    disposition: control,
  };
}
