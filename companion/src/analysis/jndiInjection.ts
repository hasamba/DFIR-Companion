// JNDI injection — the Log4Shell shape (#2099).
//
// A JNDI-injection exploit (CVE-2021-44228 and its kin) leaves a two-step trail in process and network
// telemetry: the JVM makes an outbound LDAP/RMI lookup to the attacker's server, then — once the
// served class runs — the same JVM spawns a shell or a downloader. Neither half is a finding alone.
// A JVM talks to directory servers all day, and a JVM that runs scripts is a build server. The pair,
// on one host, with the shell inside a minute of the lookup, is the exploit.
//
// The tagger cannot see this: it grades one event at a time. So this is a merge-time join pass on the
// forensic timeline, alongside injectionSequence.ts and containerEscape.ts. It only raises, never
// lowers, and is idempotent. It does not read the super-timeline. Info-graded rows never reach the
// forensic timeline, so the network leg must be graded above Info by its importer (Sysmon EID 3 and
// VMConnection rows are Low) for this pass to find it.
//
// ─────────────────────────── WHICH DESTINATIONS COUNT ───────────────────────────
//
// 389 and 636 are the ordinary LDAP ports: every domain-joined JVM binds to a domain controller on
// them. For those, the destination must be a PUBLIC address — an internal bind is the normal case.
// 1389, 1099 and 1098 are not ordinary directory ports (1389 is the marshalsec/JNDIExploit default,
// 1099/1098 RMI), so ANY non-loopback destination counts. Requiring a public address there would miss
// lab and insider cases: the OTRF Log4Shell dataset's attacker LDAP server is 10.66.0.6:1389.
// Loopback is excluded everywhere — a local RMI registry on 1099 is how JMX works.
//
// The shell child is the strong signal, so the join tolerates a child whose image the sensor could not
// resolve: Linux Sysmon reports `Image=<unknown process>` with `ParentImage=…/java` for a `bash -c`
// child, and the child's name is then read from the first token of its command line.
//
// ForensicEvent carries no parent pid, so the join is host + JVM name + time window. The pid is not
// compared; a host running two JVMs where one did the lookup and the other spawned a shell inside a
// minute is the residual false positive, and the note says it is a shape, not proof.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";
import { addressReach } from "./publicAddress.js";
import { shortHost } from "./correlate.js";

/** The marker this pass appends. Stripped by correlate.ts (via the derivedNote.ts registry). */
export const JNDI_INJECTION_MARKER = "[jndi injection:";
/** The shell must follow the lookup within this window, on the same host. */
export const JNDI_WINDOW_MS = 60_000;

const STANDARD_LDAP_PORTS = new Set([389, 636]);
const NONSTANDARD_LOOKUP_PORTS = new Set([1389, 1099, 1098]);
const JVM_RE = /^(?:java|javaw|tomcat\d*w?|catalina)$/i;
const SHELL_RE = /^(?:bash|sh|dash|zsh|ksh|cmd|powershell|pwsh|curl|wget|python[\d.]*|perl|nc|ncat)$/i;
const UNKNOWN_IMAGE_RE = /^<?unknown/i;
const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const DESCRIPTION_MAX = 1600;
const MAX_FIELD = 4096;
const OWN_NOTE = /\[jndi injection: JVM [\s\S]{0,1200}?Log4Shell shape/;

/** Basename without directories or `.exe`. */
function baseName(path: string | undefined): string {
  const tail = (path ?? "").trim().split(/[\\/]/).pop() ?? "";
  return tail.replace(/\.exe$/i, "");
}

function descField(e: ForensicEvent, name: string): string | undefined {
  const m = new RegExp(`\\b${name}=([^\\s]+)`).exec((e.description ?? "").slice(0, MAX_FIELD));
  return m?.[1];
}

function jvmName(e: ForensicEvent): string | undefined {
  const name = baseName(e.processName) || baseName(descField(e, "Image"));
  return JVM_RE.test(name) ? name : undefined;
}

interface Lookup {
  event: ForensicEvent;
  host: string;
  time: number;
  jvm: string;
  dstIp: string;
  port: number;
}

function asLookup(e: ForensicEvent): Lookup | undefined {
  const jvm = jvmName(e);
  if (!jvm) return undefined;
  const port = e.port ?? Number(descField(e, "DestinationPort"));
  const dstIp = e.dstIp ?? descField(e, "DestinationIp") ?? "";
  if (!dstIp || /^(?:127\.|::1$|localhost)/i.test(dstIp)) return undefined;
  const qualifies =
    NONSTANDARD_LOOKUP_PORTS.has(port) || (STANDARD_LDAP_PORTS.has(port) && addressReach(dstIp) === "public");
  const time = Date.parse(e.timestamp);
  if (!qualifies || Number.isNaN(time)) return undefined;
  return { event: e, host: shortHost(e.asset), time, jvm, dstIp, port };
}

/** The child's name: its image, or the first command-line token when the sensor could not resolve it. */
function childName(e: ForensicEvent): string {
  const image = baseName(e.processName);
  if (image && !UNKNOWN_IMAGE_RE.test(e.processName ?? "")) return image;
  const first = (e.commandLine ?? "").trim().slice(0, MAX_FIELD).split(/\s+/)[0];
  return baseName(first?.replace(/^["']|["']$/g, ""));
}

interface Child {
  event: ForensicEvent;
  host: string;
  time: number;
  name: string;
}

function asChild(e: ForensicEvent): Child | undefined {
  if (!JVM_RE.test(baseName(e.parentName))) return undefined;
  const name = childName(e);
  const time = Date.parse(e.timestamp);
  if (!SHELL_RE.test(name) || Number.isNaN(time)) return undefined;
  return { event: e, host: shortHost(e.asset), time, name };
}

function noteFor(l: Lookup, c: Child, fetches: readonly string[]): string {
  const delta = ((c.time - l.time) / 1000).toFixed(1);
  const fetch = fetches.length
    ? ` The JVM also connected to ${fetches.join(", ")} — the class fetch that usually follows the lookup.`
    : "";
  return (
    `JVM ${l.jvm} looked up ${l.dstIp}:${l.port} then spawned ${c.name} ${delta}s later on ${l.host} — ` +
    `Log4Shell shape (CVE-2021-44228); not proof the payload was a JNDI string.${fetch}`
  );
}

/** Other ports the same JVM reached on the lookup's destination, inside the window. */
function classFetches(l: Lookup, events: readonly ForensicEvent[]): string[] {
  const out = new Set<string>();
  for (const e of events) {
    if (e === l.event || !jvmName(e) || shortHost(e.asset) !== l.host) continue;
    const ip = e.dstIp ?? descField(e, "DestinationIp");
    const port = e.port ?? Number(descField(e, "DestinationPort"));
    const dt = Date.parse(e.timestamp) - l.time;
    if (ip === l.dstIp && port && port !== l.port && dt >= 0 && dt <= JNDI_WINDOW_MS)
      out.add(`${ip}:${port}`);
  }
  return [...out].slice(0, 5);
}

function raise(e: ForensicEvent, note: string): ForensicEvent {
  return {
    ...e,
    severity: RANK.High > RANK[e.severity] ? "High" : e.severity,
    mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), "T1190", "T1203"])],
    description: appendDerivedNote(e.description, JNDI_INJECTION_MARKER, note, DESCRIPTION_MAX),
  };
}

/**
 * Grade the JNDI-injection shape: a JVM's LDAP/RMI lookup followed within JNDI_WINDOW_MS, on the same
 * host, by that JVM spawning a shell or downloader. Raises both legs to at least High. Only raises.
 */
export function markJndiInjection(events: readonly ForensicEvent[]): ForensicEvent[] {
  const lookups = events.map(asLookup).filter((l): l is Lookup => l !== undefined);
  if (lookups.length === 0) return events as ForensicEvent[];
  const children = events.map(asChild).filter((c): c is Child => c !== undefined);
  const notes = new Map<ForensicEvent, string>();
  for (const c of children) {
    const prior = lookups
      .filter((l) => l.host === c.host && c.time >= l.time && c.time - l.time <= JNDI_WINDOW_MS)
      .sort((a, b) => b.time - a.time);
    for (const [i, l] of prior.entries()) {
      const note = noteFor(l, c, classFetches(l, events));
      if (!notes.has(l.event)) notes.set(l.event, note);
      if (i === 0 && !notes.has(c.event)) notes.set(c.event, note);
    }
  }
  let changed = false;
  const out = events.map((e) => {
    const note = notes.get(e);
    if (!note || OWN_NOTE.test(e.description ?? "")) return e;
    changed = true;
    return raise(e, note);
  });
  return changed ? out : (events as ForensicEvent[]);
}
