import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { tradecraftSignal } from "./tradecraftRules.js";
import { secretSpillSignal } from "./secretSpillRules.js";
import { reconTechniques } from "./reconTechniques.js";
import { escapeControlChars } from "./webRequestDecode.js";

// AWS Systems Manager remote execution (#931 item 7). SendCommand runs a document on managed
// instances; StartSession opens an interactive shell or a tunnel to one. Both arrive in CloudTrail
// as ordinary `ssm.amazonaws.com` calls and, before this module, graded Low with the description
// `AWS SendCommand (ssm) by <who>` — the target, the document, the command payload, the command or
// session id and the request-time status unread. Remote execution on a specific machine by a cloud
// identity was invisible as such.
//
// THE PHASES STAY DISTINCT. Listing what could be run (ListDocuments, DescribeInstanceInformation,
// GetCommandInvocation …) is discovery, not execution — Info. A SendCommand is a REQUEST: CloudTrail
// records it with the status Pending and never records the result, so the description says
// "requested" and the note says where the result is not. A StartSession is a CONNECTION whose
// content is not in CloudTrail (Session Manager logging to S3/CloudWatch holds it, when enabled);
// a ResumeSession re-establishes that access and is a connection too — the only evidence when the
// StartSession lies outside the collected interval. TerminateSession is lifecycle.
//
// WHAT IS NOT CLAIMED. A request is not "it ran". No "as root/administrator": the SSM agent runs
// the command as its configured user, and guest evidence decides. A fleet-management document is
// Low ONLY when every parameter passes a fail-closed schema — an unknown key, a downgrade, an
// override list is High with the reason, because a routine document name can carry consequential
// content. A custom document is arbitrary content and is High.
//
// IDENTITY. Every request and session is its own row: the command or session id (the join key
// GetCommandInvocation, Resume/Terminate and execution output use) is in the aggregation key, with
// the resolved document version, a digest of the COMPLETE target set and a digest of the COMPLETE
// parameter map — display truncates, the key never does. A denied call has no service id and keys
// on its CloudTrail eventID, so two denied attempts stay two rows while a duplicate delivery folds.
//
// THE PAYLOAD. `AWS-RunShellScript` / `AWS-RunPowerShellScript` carry the commands in the request
// parameters (CloudTrail keeps up to 100 KB of them, in plaintext). EVERY command value is graded
// in full by the shared tables — tradecraft, secret spills, recon — before any storage or display
// limit, exactly as a shell-history line is; only what is STORED is bounded.

export const SSM_SOURCE = "ssm.amazonaws.com";
export type SsmPhase = "discovery" | "request" | "connection" | "lifecycle";

export interface SsmDecoded {
  phase: SsmPhase;
  severity: Severity;
  mitre: string[];
  /** `→ <target> [<document>@<version>] <id> <status>` — the evidence, fixed order, bounded. */
  summary: string;
  /** What the analyst must know about the limits of this record. */
  note: string;
  target: string;
  document: string;
  id: string;
  /** Display form of the command payload (head + tail, control chars escaped); "" when none. */
  payloadExcerpt: string;
  /** The joined payload for the canonical process.commandLine, bounded; "" when none. */
  commandLine: string;
  /** The aggregation-key segment — identities and whole-set digests. */
  keySegment: string;
}

const DISCOVERY = new Set([
  "listdocuments",
  "describedocument",
  "describeinstanceinformation",
  "listcommands",
  "listcommandinvocations",
  "getcommandinvocation",
  "describesessions",
  "getconnectionstatus",
  "listassociations",
  "describeinstanceassociationsstatus",
]);
const TUNNEL_DOCUMENTS = new Set([
  "aws-startportforwardingsession",
  "aws-startportforwardingsessiontoremotehost",
  "aws-startsshsession",
]);
const SHELL_DOCUMENTS = new Set(["aws-runshellscript", "aws-runpowershellscript"]);
const DEFAULT_SESSION_DOCUMENT = "SSM-SessionManagerRunShell";
const TARGETS_SHOWN = 8;
const TARGET_DISPLAY_MAX = 120; // the display; the key digests the complete set
const ID_DISPLAY_MAX = 100; // an SSM session id may be 96 characters; the key keeps it whole
const EXCERPT_HEAD = 200;
const EXCERPT_TAIL = 60;
const COMMAND_LINE_MAX = 65_536;
const DIGEST_HEX = 16;

// Fleet-management documents that are Low with ROUTINE parameters. Fail-closed: a key outside the
// list, or a value the predicate rejects, is High with the reason. `AWS-RefreshAssociation` is
// deliberately absent — the record does not carry the referenced associations' documents.
type ParamCheck = (values: string[]) => string | null; // a reason to grade High, or null
const anyValue: ParamCheck = () => null;
const FLEET_DOCUMENTS: Record<string, Record<string, ParamCheck>> = {
  "aws-updatessmagent": {
    allowdowngrade: (v) => (v.some((x) => /^true$/i.test(x)) ? "agent downgrade allowed" : null),
    version: (v) =>
      v.some((x) => x.trim() !== "" && x.trim().toLowerCase() !== "latest")
        ? "agent pinned to a version"
        : null,
  },
  "aws-runpatchbaseline": {
    operation: (v) => (v.every((x) => /^(?:scan|install)$/i.test(x)) ? null : "unknown patch operation"),
    rebootoption: anyValue,
    snapshotid: anyValue,
    associationid: anyValue,
    installoverridelist: () => "patch content overridden — custom install list",
    baselineoverride: () => "patch content overridden — custom baseline",
  },
  "aws-applypatchbaseline": {
    operation: (v) => (v.every((x) => /^(?:scan|install)$/i.test(x)) ? null : "unknown patch operation"),
    snapshotid: anyValue,
  },
  "aws-installwindowsupdates": {
    action: (v) => (v.every((x) => /^(?:scan|install)$/i.test(x)) ? null : "unknown update action"),
    allowreboot: anyValue,
    categories: anyValue,
    severitylevels: anyValue,
    includekbs: anyValue,
    excludekbs: anyValue,
    publisheddaysold: anyValue,
    publisheddateafter: anyValue,
    publisheddatebefore: anyValue,
  },
  "aws-gathersoftwareinventory": Object.fromEntries(
    [
      "applications",
      "awscomponents",
      "networkconfig",
      "windowsupdates",
      "instancedetailedinformation",
      "services",
      "windowsregistry",
      "windowsroles",
      "custominventory",
      "billinginfo",
      "files",
    ].map((k) => [k, anyValue]),
  ),
};

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 200): string =>
  typeof v === "string" || typeof v === "number" ? String(v).trim().slice(0, max) : "";
// A parameter value in CloudTrail is a string array; a scalar is tolerated. RAW — no bound: these
// feed grading and the key digests; every display and stored copy bounds itself.
const raw = (v: unknown): string => (typeof v === "string" || typeof v === "number" ? String(v) : "");
const values = (v: unknown): string[] =>
  Array.isArray(v) ? v.map(raw).filter(Boolean) : raw(v) ? [raw(v)] : [];
const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, DIGEST_HEX);

// The parameter map as a stable, complete string for the key — every key, every value, sorted.
function parameterDigest(params: unknown): string {
  if (!isObj(params)) return "";
  const parts = Object.keys(params)
    .sort()
    .map((k) => `${k.toLowerCase()}=${values(params[k]).join("")}`);
  return parts.length ? digest(parts.join("")) : "";
}

function renderTargets(request: Obj): { display: string; all: string[] } {
  const all: string[] = [];
  for (const id of values(request.instanceIds)) all.push(id);
  if (Array.isArray(request.targets)) {
    for (const t of request.targets) {
      if (!isObj(t)) continue;
      const key = text(t.Key ?? t.key, 80);
      const vals = values(t.Values ?? t.values);
      if (key) all.push(`${key}=${vals.join(",")}`);
    }
  }
  const shown = all.slice(0, TARGETS_SHOWN).map((t) => t.slice(0, 60));
  let display = shown.join(", ");
  if (display.length > TARGET_DISPLAY_MAX) display = `${display.slice(0, TARGET_DISPLAY_MAX)}…`;
  if (all.length > TARGETS_SHOWN) display += ` (+${all.length - TARGETS_SHOWN} more)`;
  return { display: display || "(no target)", all };
}

// Grade the fleet document's parameters against its schema; the first reason wins.
function fleetReason(documentLower: string, params: unknown): string | null {
  const schema = FLEET_DOCUMENTS[documentLower];
  if (!schema) return "not a fleet-management document";
  if (params === undefined || params === null) return null;
  if (!isObj(params)) return "unreadable parameters";
  for (const [k, v] of Object.entries(params)) {
    const check = schema[k.toLowerCase()];
    if (!check) return `parameter ${k} is not part of the routine document`;
    const reason = check(values(v));
    if (reason) return reason;
  }
  return null;
}

function excerpt(payload: string): string {
  const safe = escapeControlChars(payload);
  if (safe.length <= EXCERPT_HEAD + EXCERPT_TAIL + 3) return safe;
  return `${safe.slice(0, EXCERPT_HEAD)} … ${safe.slice(-EXCERPT_TAIL)}`;
}

/**
 * The description of an SSM row, composed so the evidence survives the 600-character clip: the
 * principal and origin (bounded), then the summary — document, id, status, target — then the
 * payload excerpt, then the note, then the client and the error code. Each slot bounded on its own,
 * the attacker-shaped ones (principal, target, payload) yielding first.
 */
export function renderSsmDescription(
  ssm: SsmDecoded,
  parts: {
    name: string;
    source: string;
    who: string;
    from: string;
    region: string;
    client: string;
    root: boolean;
    errorCode: string;
    /** The caller's identity words (#931 item 5); bounded to its own slot, after the head. */
    identity?: string;
  },
): string {
  const head = `AWS ${parts.name} (${parts.source})${parts.who ? ` by ${parts.who.slice(0, 60)}` : ""}${parts.from ? ` from ${parts.from}` : ""}${parts.region ? ` in ${parts.region}` : ""}`;
  const tail = `${parts.client ? ` [ua: ${parts.client.slice(0, 40)}]` : ""}${parts.root ? " [root]" : ""}${parts.errorCode ? ` [${parts.errorCode.slice(0, 40)}]` : ""}`;
  const summary = ` ${ssm.summary.slice(0, 260)}`;
  const payload = ssm.payloadExcerpt ? ` cmd: "${ssm.payloadExcerpt.slice(0, 150)}"` : "";
  const note = ` — ${ssm.note}`;
  // The caller's identity words (#931 item 5) take only what the SSM evidence AND a bounded note
  // leave — up to 150 characters, down to nothing — so the document, id, status, target, payload,
  // error detail and the execution caveat ("the result is not in CloudTrail") are never displaced.
  const NOTE_RESERVE = 120;
  const evidence = `${head}${summary}${payload}${tail}`;
  const identityRaw = (parts.identity ?? "").trim();
  const budget = Math.min(150, 600 - evidence.length - Math.min(note.length, NOTE_RESERVE) - 1);
  const identity =
    identityRaw && budget >= 12
      ? ` ${identityRaw.length > budget ? `${identityRaw.slice(0, budget - 1)}…` : identityRaw}`
      : "";
  const fixed = `${head}${identity}${summary}${payload}${tail}`;
  return `${fixed}${note.slice(0, Math.max(0, 600 - fixed.length))}`.slice(0, 600);
}

/**
 * Decode one SSM CloudTrail call, or null when the source is not SSM or the call is not one this
 * module grades. `request`/`response` are the record's requestParameters/responseElements (any
 * shape tolerated); `eventId` is the CloudTrail eventID, the key's fallback identity.
 */
export function decodeSsmCall(
  source: string,
  name: string,
  request: unknown,
  response: unknown,
  errorCode: string,
  eventId: string,
): SsmDecoded | null {
  if (source.toLowerCase() !== SSM_SOURCE) return null;
  const lower = name.toLowerCase();
  const req: Obj = isObj(request) ? request : {};
  const res: Obj = isObj(response) ? response : {};
  const denied = errorCode.trim() !== "";
  const deniedNote = denied
    ? ` denied [${errorCode.trim().slice(0, 60)}] — the request did not execute.`
    : "";

  if (DISCOVERY.has(lower)) {
    return {
      phase: "discovery",
      severity: "Info",
      mitre: ["T1526"],
      summary: "discovery — lists or reads, does not run",
      note: `Discovery of what could be run, not execution.${deniedNote}`.trim(),
      target: "",
      document: "",
      id: eventId,
      payloadExcerpt: "",
      commandLine: "",
      keySegment: `|ssm:discovery|${eventId}`,
    };
  }

  if (lower === "sendcommand") {
    const documentName = text(req.documentName, 120) || "(unknown document)";
    const command: Obj = isObj(res.command) ? res.command : {};
    const version = text(command.documentVersion, 20);
    const document = version ? `${documentName}@${version}` : documentName;
    const id = raw(command.commandId) || eventId;
    // A denied request never echoes a response status ("Pending") as if the request stood.
    const status = denied ? "attempted, denied" : text(command.status, 30) || "unknown";
    const { display: target, all } = renderTargets(req);
    const params = req.parameters;
    let severity: Severity = "High";
    const mitre = ["T1651"];
    let note = "";
    const docLower = documentName.toLowerCase();
    let payloadExcerpt = "";
    let commandLine = "";
    if (SHELL_DOCUMENTS.has(docLower)) {
      const commands = isObj(params) ? values(params.commands) : [];
      // Graded one by one, in full, BEFORE any bound: the tables are linear and CloudTrail's 100 KB
      // is the ceiling that matters.
      const joined = commands.join("\n");
      // Each entry and the whole script, in both joinings: a construct split across two entries
      // (`curl …` then `| sh`) is visible only in a joined reading, and the tables' patterns do
      // not all span a newline.
      for (const cmd of [...commands, joined, commands.join(" ")]) {
        const tc = tradecraftSignal("", cmd);
        if (tc) for (const t of tc.mitre) if (!mitre.includes(t)) mitre.push(t);
        const spill = secretSpillSignal(cmd);
        if (spill) for (const t of spill.mitre) if (!mitre.includes(t)) mitre.push(t);
        for (const t of reconTechniques("", cmd)) if (!mitre.includes(t)) mitre.push(t);
      }
      commandLine = joined.slice(0, COMMAND_LINE_MAX);
      if (joined.length > COMMAND_LINE_MAX)
        note += ` payload clipped to ${COMMAND_LINE_MAX} characters in the stored command line (${joined.length} recorded).`;
      payloadExcerpt = commands.length ? excerpt(joined) : "";
    } else {
      const reason = fleetReason(docLower, params);
      if (reason === null) {
        severity = "Low";
        note += " fleet-management document with routine parameters.";
      } else if (docLower === "aws-refreshassociation") {
        note += " refreshes associations whose documents are not in this record.";
      } else if (reason !== "not a fleet-management document") {
        note += ` ${reason}.`;
      }
    }
    // A denied request did not execute: an attempt, graded Medium whatever the document — the target
    // and payload are still the evidence; the effect is not there to grade.
    if (denied) severity = "Medium";
    const targetsDigest = digest(
      all
        .map((t) => t.toLowerCase())
        .sort()
        .join(""),
    );
    return {
      phase: "request",
      severity,
      mitre,
      summary: `[${document}] ${id.slice(0, ID_DISPLAY_MAX)} ${status}${denied ? "" : ": requested"} → ${target}`,
      note: `${denied ? deniedNote.trim() : "The result is not in CloudTrail (Pending at the call); runs as the SSM agent's configured user — guest evidence decides."}${note}`.trim(),
      target,
      document,
      id,
      payloadExcerpt,
      commandLine,
      keySegment: `|ssm:request|${document.toLowerCase()}|${id}|${targetsDigest}|${parameterDigest(params)}`,
    };
  }

  if (lower === "startsession" || lower === "resumesession") {
    const resumed = lower === "resumesession";
    const documentName = resumed ? "" : text(req.documentName, 120) || DEFAULT_SESSION_DOCUMENT;
    const docLower = documentName.toLowerCase();
    const id = raw(res.sessionId) || raw(req.sessionId) || eventId;
    const shownId = id.slice(0, ID_DISPLAY_MAX);
    const params = isObj(req.parameters) ? req.parameters : {};
    const host = values(params.host)[0] ?? "";
    const port = values(params.portNumber)[0] ?? "";
    const tunnel = TUNNEL_DOCUMENTS.has(docLower);
    const mitre = tunnel ? ["T1651", "T1572"] : ["T1651"];
    let target = text(req.target, 120) || (resumed ? "" : "(no target)");
    if (tunnel && (host || port)) target += ` → ${host || "(node)"}${port ? `:${port}` : ""}`;
    // A denied call never gets a completed-state verb: "resume attempted, denied", not "resumed".
    const summary = resumed
      ? `${shownId} ${denied ? "resume attempted, denied" : "resumed"}`
      : `[${documentName}] ${shownId}${denied ? " start attempted, denied" : ": started"} → ${target}`;
    const note = resumed
      ? `${denied ? "" : "Resumed: re-established access to a live session; "}the target and document are on the StartSession record for this session id.${deniedNote} The session's commands are not in CloudTrail.`
      : `${tunnel ? "Tunnel: session content is not logged. " : ""}The session's commands are not in CloudTrail (Session Manager logging to S3/CloudWatch, if enabled, holds them); runs as the SSM agent's configured user.${deniedNote}`;
    return {
      phase: "connection",
      severity: denied ? "Medium" : "High",
      mitre,
      summary,
      note: note.trim(),
      target,
      document: documentName,
      id,
      payloadExcerpt: "",
      commandLine: "",
      keySegment: `|ssm:connection|${docLower}|${id}|${digest(target.toLowerCase())}|${parameterDigest(req.parameters)}`,
    };
  }

  if (lower === "terminatesession") {
    const id = raw(req.sessionId) || raw(res.sessionId) || eventId;
    return {
      phase: "lifecycle",
      severity: denied ? "Medium" : "Info",
      mitre: [],
      summary: `${id.slice(0, ID_DISPLAY_MAX)} ${denied ? "termination attempted, denied" : "terminated"}`,
      note: `Session lifecycle.${deniedNote}`.trim(),
      target: "",
      document: "",
      id,
      payloadExcerpt: "",
      commandLine: "",
      keySegment: `|ssm:lifecycle|${id}`,
    };
  }

  return null;
}
