// Explaining a certutil transfer, rather than just flagging one (#908 item 4).
//
// The command rules already recognise `certutil -urlcache -split -f http://…`. What they cannot say
// is what actually happened: whether the download reached the network, and what landed on disk. An
// analyst reading "suspicious certutil command" still has to go and find those out.
//
// This pass stitches the three records together on HOST, PROCESS IDENTITY and TIME:
//
//   the command  →  an outbound connection  →  a file written
//
// and puts the answer on the event: where it went, and what it wrote.
//
// ─────────────────────────── MISSING TELEMETRY IS STATED, NOT ASSUMED ───────────────────────────
//
// Most collections have some of those three and not all. A triage package with process creation but
// no network telemetry cannot show the connection, and that is a fact about the COLLECTION, not
// about the transfer. So each leg is reported as found, or explicitly as not collected — never
// silently omitted, and never read as evidence the transfer did not happen.
//
// ─────────────────────────── CERTIFICATE ADMINISTRATION IS NOT A TRANSFER ───────────────────────
//
// certutil's actual job is certificates. `-store`, `-verify`, `-dump`, `-addstore`, `-repairstore`
// and the CA verbs are what it is for, and none of them downloads anything. Only the transfer and
// decode verbs are considered here, so a certificate estate does not fill the timeline.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { commandCandidates } from "./commandNormalize.js";
import { shortHost } from "./correlate.js";

/** The marker this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const CERTUTIL_MARKER = "[certutil transfer:";

/** How far from the command an outbound connection or a file write may sit and still be linked. */
export const DEFAULT_WINDOW_MS = 5 * 60 * 1000;

// The verbs that move or decode data. `-urlcache` fetches, `-decode`/`-encode` convert a payload to
// and from base64, and `-verifyctl` will fetch a CTL from a URL.
const TRANSFER_VERB = /-urlcache\b|-verifyctl\b|-decode(?:hex)?\b|-encode(?:hex)?\b|-split\b/i;

// What certutil is actually for. Present WITHOUT a transfer verb, these are certificate work.
const CERT_ADMIN_VERB =
  /-store\b|-addstore\b|-delstore\b|-repairstore\b|-verify\b|-dump\b|-viewstore\b|-ca\b|-template\b|-csp\b|-getreg\b/i;

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

/** True when this event is a certutil invocation that moves or decodes data. */
export function isCertutilTransfer(image: string, cmd: string): boolean {
  // The same candidates the detection rules use, so an escaped spelling reaches this too.
  return commandCandidates(image, cmd).some((c) => {
    if (!/\bcertutil(?:\.exe)?\b/i.test(c)) return false;
    if (!TRANSFER_VERB.test(c)) return false;
    // A transfer verb wins over an administration verb — `-urlcache` with `-store` is still a fetch.
    return true;
  });
}

/** True when this is certificate administration and nothing more. */
export function isCertificateAdmin(image: string, cmd: string): boolean {
  return commandCandidates(image, cmd).some(
    (c) => /\bcertutil(?:\.exe)?\b/i.test(c) && CERT_ADMIN_VERB.test(c) && !TRANSFER_VERB.test(c),
  );
}

export interface TransferLegs {
  /** The URL or host the command itself names, when it names one. */
  commandTarget: string;
  /** A connection recorded from the same process, or "" when none was found. */
  connection: string;
  /** A file written by the same process, or "" when none was found. */
  fileWritten: string;
  /** Whether the collection contained any network telemetry for this host at all. */
  networkCollected: boolean;
  /** Whether the collection contained any file-write telemetry for this host at all. */
  fileActivityCollected: boolean;
}

const URL_IN_CMD = /\bhttps?:\/\/[^\s"'<>|]+/i;

function sameProcess(a: ForensicEvent, b: ForensicEvent): boolean {
  // PID when both carry one; otherwise the image name. PID alone across a long collection can be
  // reused, so the name has to agree too.
  const an = (a.processName ?? "").toLowerCase();
  const bn = (b.processName ?? "").toLowerCase();
  if (a.pid !== undefined && b.pid !== undefined && a.pid === b.pid) return !an || !bn || an === bn;
  return !!an && an === bn;
}

/**
 * Find what else the same certutil process did, close to the command.
 *
 * Returns the legs it could establish AND what the collection contained, so the caller can say
 * "no connection was recorded" separately from "no network telemetry was collected".
 */
export function transferLegs(
  command: ForensicEvent,
  events: readonly ForensicEvent[],
  opts: { windowMs?: number } = {},
): TransferLegs {
  const windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS;
  const host = shortHost(command.asset) || command.asset || "";
  const t = Date.parse(command.timestamp ?? "");

  let connection = "";
  let fileWritten = "";
  let networkCollected = false;
  let fileActivityCollected = false;

  for (const e of events) {
    if (e.id === command.id) continue;
    const eHost = shortHost(e.asset) || e.asset || "";
    if (host && eHost && host !== eHost) continue;

    const isNetwork = !!e.dstIp || /\bconnection\b|\bnetwork\b|netscan|netstat/i.test(e.description ?? "");
    const isFileWrite = e.action === "write" || /file (?:created|written)/i.test(e.description ?? "");
    if (isNetwork) networkCollected = true;
    if (isFileWrite) fileActivityCollected = true;

    if (!Number.isFinite(t)) continue;
    const et = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(et) || Math.abs(et - t) > windowMs) continue;
    if (!sameProcess(command, e)) continue;

    if (isNetwork && !connection) connection = e.dstIp || (e.description ?? "").slice(0, 120);
    if (isFileWrite && !fileWritten) fileWritten = e.path || (e.description ?? "").slice(0, 120);
  }

  return {
    commandTarget: URL_IN_CMD.exec(command.commandLine ?? command.description ?? "")?.[0] ?? "",
    connection,
    fileWritten,
    networkCollected,
    fileActivityCollected,
  };
}

/** The sentence a set of legs becomes. */
export function explainTransfer(legs: TransferLegs): string {
  const parts: string[] = [];
  parts.push(
    legs.commandTarget
      ? `the command names ${legs.commandTarget}`
      : "the command names no URL that could be read from it",
  );
  parts.push(
    legs.connection
      ? `an outbound connection from the same process was recorded (${legs.connection})`
      : legs.networkCollected
        ? "no outbound connection from this process was recorded, though network telemetry was collected"
        : "no network telemetry was collected for this host, so the connection cannot be confirmed either way",
  );
  parts.push(
    legs.fileWritten
      ? `it wrote ${legs.fileWritten}`
      : legs.fileActivityCollected
        ? "no file write by this process was recorded, though file activity was collected"
        : "no file-activity telemetry was collected for this host, so what it wrote is unknown",
  );
  return `${parts.join("; ")}.`;
}

/**
 * Attach the explanation to every certutil transfer command in the timeline.
 *
 * Only ever raises, and only when a leg was actually established — an explanation that says
 * "nothing was collected" is worth attaching, but it is not grounds to raise a severity.
 */
export function explainCertutilTransfers(events: readonly ForensicEvent[]): ForensicEvent[] {
  const commands = events.filter(
    (e) =>
      !(e.description ?? "").includes(CERTUTIL_MARKER) &&
      isCertutilTransfer(e.processName ?? "", e.commandLine ?? e.description ?? ""),
  );
  if (commands.length === 0) return events as ForensicEvent[];

  const byId = new Map<string, string>();
  const raise = new Set<string>();
  for (const c of commands) {
    const legs = transferLegs(c, events);
    byId.set(c.id, explainTransfer(legs));
    // A corroborated leg is what turns "a suspicious command" into "a transfer that happened".
    if (legs.connection || legs.fileWritten) raise.add(c.id);
  }

  return events.map((e) => {
    const note = byId.get(e.id);
    if (!note) return e;
    const severity: Severity = raise.has(e.id) && RANK["High"] > RANK[e.severity] ? "High" : e.severity;
    const base = (e.description ?? "").slice(0, 700);
    return { ...e, severity, description: `${base} ${CERTUTIL_MARKER} ${note}]`.trim() };
  });
}
