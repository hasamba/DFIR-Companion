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
import { appendDerivedNote } from "./derivedNote.js";

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
  /** The destination file the command names, which is the write leg's identity. */
  destination: string;
  /** False when the command's own timestamp could not be read, so nothing could be correlated. */
  commandTimeUsable: boolean;
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

/**
 * The file the command itself names as its destination.
 *
 * This is the strongest identity available for the write leg, and the reason it matters is that
 * Sysmon's file-create rows and ECAR's file rows carry NO process name or PID. Requiring process
 * identity meant the write leg could essentially never be established from real telemetry. A file
 * event for the path the command asked for is better evidence than a name match anyway.
 */
export function destinationFromCommand(cmd: string): string {
  const text = String(cmd ?? "");
  // `-urlcache -split -f <url> <destination>` and `-decode <in> <out>`: the destination is the last
  // path-shaped argument, and it must not be the URL.
  const args = text.match(/(?:"[^"]+"|\S+)/g) ?? [];
  for (let i = args.length - 1; i >= 0; i--) {
    const a = args[i].replace(/^"|"$/g, "");
    if (/^https?:\/\//i.test(a)) continue;
    if (a.startsWith("-") || a.startsWith("/")) continue;
    if (/[\\/]/.test(a) || /\.[A-Za-z0-9]{1,6}$/.test(a)) return a;
  }
  return "";
}

function sameProcess(a: ForensicEvent, b: ForensicEvent): boolean {
  const an = (a.processName ?? "").toLowerCase();
  const bn = (b.processName ?? "").toLowerCase();
  // TWO PIDs THAT DISAGREE ARE TWO PROCESSES. The first version fell through to the name when they
  // conflicted, so certutil.exe PID 100 and PID 200 matched — and two invocations minutes apart
  // could borrow each other's connection, giving the wrong destination AND a false escalation.
  if (a.pid !== undefined && b.pid !== undefined) {
    if (a.pid !== b.pid) return false;
    return !an || !bn || an === bn;
  }
  // Only one side records a PID: the name is all there is, and it is a weak match by itself. The
  // caller pairs it with the causal-order and destination checks rather than trusting it alone.
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
  const commandText = command.commandLine ?? command.description ?? "";
  const destination = destinationFromCommand(commandText);
  const destKey = destination.toLowerCase().replace(/\//g, "\\");

  let connection = "";
  let fileWritten = "";
  let networkCollected = false;
  let fileActivityCollected = false;
  // The CLOSEST leg after the command, not the first one encountered in array order.
  let bestConn = Infinity;
  let bestFile = Infinity;

  for (const e of events) {
    if (e.id === command.id) continue;
    const eHost = shortHost(e.asset) || e.asset || "";
    if (host && eHost && host !== eHost) continue;

    // An outbound connection needs a DESTINATION ADDRESS. Matching the words "connection" or
    // "network" in prose swept in share access, type-3 logons, promiscuous-mode notices and SRUM
    // byte-accounting rows — and a SRUM row carries a process name, so it could become the leg and
    // escalate the command while naming no destination at all.
    const isNetwork = !!e.dstIp;
    const isFileWrite =
      e.action === "write" || /\bfile (?:created|written|write)\b/i.test(e.description ?? "");
    if (isNetwork) networkCollected = true;
    if (isFileWrite) fileActivityCollected = true;

    if (!Number.isFinite(t)) continue;
    const et = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(et)) continue;
    // CAUSAL ORDER. A connection or a write BEFORE the command did not result from it, and
    // accepting one let a later invocation borrow an earlier one's evidence.
    const delta = et - t;
    if (delta < 0 || delta > windowMs) continue;

    if (isNetwork && sameProcess(command, e) && delta < bestConn) {
      bestConn = delta;
      connection = e.dstIp || (e.description ?? "").slice(0, 120);
    }
    if (isFileWrite && delta < bestFile) {
      // The destination the COMMAND named is the identity here, because the file telemetry that
      // matters carries no process of its own. A process match is accepted as a fallback.
      const path = (e.path ?? "").toLowerCase().replace(/\//g, "\\");
      const matchesDestination = !!destKey && !!path && path.endsWith(destKey);
      if (matchesDestination || sameProcess(command, e)) {
        bestFile = delta;
        fileWritten = e.path || (e.description ?? "").slice(0, 120);
      }
    }
  }

  return {
    commandTarget: URL_IN_CMD.exec(commandText)?.[0] ?? "",
    destination,
    connection,
    fileWritten,
    networkCollected,
    fileActivityCollected,
    // Stated separately, because "we could not correlate" and "nothing was there" are different
    // facts and the note has to be able to tell them apart.
    commandTimeUsable: Number.isFinite(t),
  };
}

/** The sentence a set of legs becomes. */
export function explainTransfer(legs: TransferLegs): string {
  if (!legs.commandTimeUsable) {
    return (
      `the command names ${legs.commandTarget || "no readable URL"}` +
      (legs.destination ? ` and a destination of ${legs.destination}` : "") +
      ". Its own timestamp could not be read, so nothing could be correlated to it — this says " +
      "nothing about whether the transfer happened."
    );
  }
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
  if (legs.destination) parts.push(`its destination argument is ${legs.destination}`);
  parts.push(
    legs.fileWritten
      ? `a write of ${legs.fileWritten} was recorded`
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
  const commands = events.filter((e) => {
    const text = e.commandLine ?? e.description ?? "";
    if (!isCertutilTransfer(e.processName ?? "", text)) return false;
    // Certificate administration is excluded EXPLICITLY rather than only implicitly, so widening
    // the transfer verbs later cannot quietly start calling `-store` work a download.
    if (isCertificateAdmin(e.processName ?? "", text)) return false;
    const existing = e.description ?? "";
    if (!existing.includes(CERTUTIL_MARKER)) return true;
    // ALREADY EXPLAINED — but only left alone if that explanation established something. A note
    // written before the network or file evidence was imported would otherwise be frozen as "not
    // collected" forever, and no later import could correct it.
    return /no network telemetry|no file-activity telemetry|could not be read/.test(existing);
  });
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
    // Replace any earlier explanation rather than appending a second one.
    const base = (e.description ?? "").replace(/\s*\[certutil transfer:[\s\S]*?\]\s*$/u, "");
    return { ...e, severity, description: appendDerivedNote(base, CERTUTIL_MARKER, note) };
  });
}
