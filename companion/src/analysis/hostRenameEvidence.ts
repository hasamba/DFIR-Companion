// A renamed machine, seen through a log export that names no collector (#1489).
//
// hostIdentity.ts folds a record's old Computer name into the collector's identity when a row
// carries one (Fqdn / Hostname / the flow's client). A file downloaded from the Velociraptor GUI, a
// notebook export or a triage ZIP carries none, so every name the machine ever had became its own
// host: INC-2026-032 — the same machine as 031 — came out as three hosts, and synthesis read the
// Vagrant provisioning under the old names as a backdoor account plus lateral movement.
//
// The files still hold facts the machine wrote ABOUT ITSELF, and each one is read here as a per-record
// claim about that record's writer (its Computer). None is free text an intruder types:
//
//   a. System 6011 (provider EventLog): "The NetBIOS name and DNS host name of this machine have
//      been changed from X to Y" — the two names are the event's own structured parameters; the
//      rendered Message is never read.
//   b. The machine's OWN account under the SYSTEM logon session: a record whose SUBJECT is `X$` with
//      logon id 0x3e7 — LocalSystem's token, which is always the computer account (`WORKGROUP\X$` off
//      a domain, `DOMAIN\X$` on one) — written by a machine now called Y. The session id is the
//      control, and it is mandatory: a failed or explicit logon with a chosen `X$` account carries the
//      caller's logon id, never 0x3e7, and the TARGET account is never read (a 4648 to another
//      machine's account is lateral movement, the very thing this must not fold).
//   c. The SAM domain of a LOCAL account: a user-account or local-group event (4720/4722/4724/4726/
//      4738/4767/4732) whose TargetDomainName X is not the record's Computer Y — the SAM names the
//      machine as it was called when the account was made. Bounded twice: the acting account must be
//      SYSTEM or local to Y (WORKGROUP / NT AUTHORITY / Y — a `CONTOSO\admin` on a domain controller
//      never qualifies), and X must also have been seen as a record's Computer in the same import, so a
//      domain NetBIOS name is never mistaken for a former host name. Domain-group and account-rename
//      events (4728/4756/4781) are not read at all.
//
// The map built from these edges FAILS CLOSED: a former name with two different current names yields
// no alias, a cycle yields none for any name on it, and an alias applies only to a record dated at or
// before the evidence — a later machine that reuses the old name stays its own host. A record with
// no timestamp is not aliased. Names compare by shortHostName, as hostIdentity does. Pure.

import { getCI, getPath, isObject, str } from "./siemImport.js";
import { recordCollector, recordComputer, shortHostName } from "./hostIdentity.js";
import type { HostRenameRecord, RenameBasis } from "./hostRenameRecord.js";
import { vrTime } from "./veloRowTime.js";

type Row = Record<string, unknown>;

export type { HostRenameRecord, RenameBasis } from "./hostRenameRecord.js";

export interface RenameEvidence {
  formerName: string;
  currentName: string;
  timestamp: string; // UTC ISO; "" when the record carries no time (the edge is then never applied)
  rule: RenameBasis;
  // Rule c: honoured only once `formerName` was seen as a record's Computer.
  needsFormerSeen?: true;
}

const RENAME_EID = 6011;
const SAM_LOCAL_EIDS = new Set([4720, 4722, 4724, 4726, 4738, 4767, 4732]);
// The SYSTEM logon session, as Windows renders it (hex) and as CondensedAccountUsage renders it.
const SYSTEM_LOGON_ID = /^(?:0x3e7|999)$/i;
// Account domains that are never a machine's name.
const WELL_KNOWN_DOMAIN =
  /^(?:BUILTIN|NT AUTHORITY|NT SERVICE|WORKGROUP|NT VIRTUAL MACHINE|WINDOW MANAGER|FONT DRIVER HOST|IIS APPPOOL|-|)$/i;
const LOCAL_ACTOR_DOMAIN = /^(?:WORKGROUP|NT AUTHORITY)$/i;
// A NetBIOS / DNS label as Windows accepts it for a computer name.
const HOST_LABEL = /^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/;
const EVENT_WRAPPERS = ["", "Event", "_Event"] as const;

// ───────────────────────────── row readers ─────────────────────────────

function toEventId(value: unknown): number {
  if (typeof value === "number") return value;
  if (isObject(value)) return toEventId(getCI(value, "Value") ?? getCI(value, "#text"));
  const n = Number(str(value).trim());
  return Number.isInteger(n) ? n : 0;
}

// The System block in each shape: Chainsaw's flat `SystemData`, native `System`, or under a wrapper.
function systemBlock(row: Row): Row | null {
  const flat = getCI(row, "SystemData");
  if (isObject(flat)) return flat;
  for (const w of EVENT_WRAPPERS) {
    const sys = getPath(row, w ? `${w}.System` : "System");
    if (isObject(sys)) return sys;
  }
  return null;
}

function eventId(row: Row): number {
  const flat = toEventId(getCI(row, "EventID") ?? getCI(row, "EID"));
  if (flat) return flat;
  const sys = systemBlock(row);
  return sys ? toEventId(getCI(sys, "EventID")) : 0;
}

// EventData in each shape, the `Data: [{ "@Name", "#text" }]` form flattened. A flat artifact row
// (CondensedAccountUsage) carries its fields at the top level, so the row itself is the fallback.
function eventData(row: Row): Row {
  for (const w of EVENT_WRAPPERS) {
    const ed = getPath(row, w ? `${w}.EventData` : "EventData");
    if (!isObject(ed)) continue;
    const data = getCI(ed, "Data");
    if (!Array.isArray(data) || !data.every(isObject)) return ed;
    const out: Row = { ...ed };
    for (const item of data as Row[]) {
      const name = str(getCI(item, "@Name") ?? getCI(item, "Name")).trim();
      if (name) out[name] = getCI(item, "#text") ?? getCI(item, "text") ?? "";
    }
    return out;
  }
  return row;
}

function field(ed: Row, key: string): string {
  return str(getCI(ed, key)).trim();
}

function channelOf(row: Row, sys: Row | null): string {
  return field(row, "Channel") || (sys ? field(sys, "Channel") : "");
}

function providerOf(sys: Row | null): string {
  if (!sys) return "";
  return (
    str(getPath(sys, "Provider.Name")) ||
    str(getPath(sys, "Provider.#attributes.Name")) ||
    str(getPath(sys, "Provider_attributes.Name"))
  ).trim();
}

/** When the record was written, UTC ISO, across the shapes above; "" when it names no time. */
export function recordTime(row: Row): string {
  const sys = systemBlock(row);
  const candidates = [
    sys ? getCI(sys, "TimeCreated") : undefined,
    sys ? getPath(sys, "TimeCreated_attributes.SystemTime") : undefined,
    getCI(row, "EventTime"),
    getCI(row, "TimeCreated"),
    getCI(row, "Timestamp"),
    getCI(row, "timestamp"),
  ];
  for (const c of candidates) {
    const t = vrTime(c);
    if (t) return t;
  }
  return "";
}

const sameHost = (a: string, b: string): boolean => shortHostName(a) === shortHostName(b);

// ───────────────────────────── the three rules ─────────────────────────────

function renameEvent(row: Row, sys: Row | null, ed: Row): RenameEvidence | null {
  if (!/^System$/i.test(channelOf(row, sys)) && !/^EventLog$/i.test(providerOf(sys))) return null;
  const data = getCI(ed, "Data");
  const [former, current] = Array.isArray(data)
    ? data.map((v) => str(v).trim())
    : [field(ed, "param1"), field(ed, "param2")];
  if (!former || !current || !HOST_LABEL.test(former) || !HOST_LABEL.test(current)) return null;
  if (sameHost(former, current)) return null;
  return { formerName: former, currentName: current, timestamp: recordTime(row), rule: "6011" };
}

function machineAccount(row: Row, ed: Row, computer: string): RenameEvidence | null {
  // The SUBJECT only. CondensedAccountUsage collapses the subject of a 4648 into UserName/LogonId.
  const name = field(ed, "SubjectUserName") || field(ed, "UserName");
  const logonId = field(ed, "SubjectLogonId") || field(ed, "LogonId");
  if (!name.endsWith("$") || !SYSTEM_LOGON_ID.test(logonId)) return null;
  const former = name.slice(0, -1);
  if (!computer || !HOST_LABEL.test(former) || sameHost(former, computer)) return null;
  return { formerName: former, currentName: computer, timestamp: recordTime(row), rule: "machine-account" };
}

function samDomain(row: Row, ed: Row, computer: string): RenameEvidence | null {
  const former = field(ed, "TargetDomainName");
  if (!computer || !former || WELL_KNOWN_DOMAIN.test(former) || !HOST_LABEL.test(former)) return null;
  if (sameHost(former, computer)) return null;
  // The acting account must be local to the writer: SYSTEM (WORKGROUP / NT AUTHORITY) or an account
  // of the machine under its CURRENT name. `CONTOSO\admin` creating `CONTOSO\user` on a DC has the
  // same shape as a lagging SAM name and is refused here, before the seen-as-Computer bound.
  const actor = field(ed, "SubjectDomainName");
  if (!actor || !(LOCAL_ACTOR_DOMAIN.test(actor) || sameHost(actor, computer))) return null;
  return {
    formerName: former,
    currentName: computer,
    timestamp: recordTime(row),
    rule: "sam-domain",
    needsFormerSeen: true,
  };
}

/** The rename claim ONE raw row makes about its own writer, or null. */
export function renameEvidence(row: Row): RenameEvidence | null {
  const eid = eventId(row);
  if (!eid) return null;
  const sys = systemBlock(row);
  const ed = eventData(row);
  if (eid === RENAME_EID) return renameEvent(row, sys, ed);
  const computer = recordComputer(row);
  if (SAM_LOCAL_EIDS.has(eid)) return samDomain(row, ed, computer);
  return machineAccount(row, ed, computer);
}

// ───────────────────────────── the alias map ─────────────────────────────

interface Edge {
  former: string; // as written in the evidence
  current: string;
  key: string; // shortHostName(former)
  currentKey: string;
  ts: number; // epoch ms of the evidence; NaN when the record carried no time
  needsFormerSeen: boolean;
  rule: RenameBasis;
}

interface Hop {
  current: string;
  currentKey: string;
  ts: number; // the EARLIEST evidence time for this edge — see resolve()
}

/**
 * Former name → current name, learned from any number of rows (incrementally, in any order) and
 * resolved on demand. `currentNameOf` returns the name unchanged whenever the map cannot vouch for
 * a rename: no edge, an ambiguous edge, a cycle, a record dated after the evidence, or no date.
 */
export class HostRenameMap {
  private readonly seen = new Set<string>();
  private readonly collectors = new Set<string>();
  private readonly edges: Edge[] = [];
  private hops: Map<string, Hop> | null = null;

  /**
   * A map seeded with what the case already knows (#1495): every persisted record is one more
   * edge, dated by its bound, and every collector identity the case has seen is a name this map
   * will never treat as a former one. A file's own evidence is then learned on top.
   */
  static from(
    records: readonly HostRenameRecord[] = [],
    collectorHostnames: readonly string[] = [],
    importCollector = "", // the import's own client (a flow export's hostFallback): a collector too
  ): HostRenameMap {
    const m = new HostRenameMap();
    for (const r of records)
      m.add({ formerName: r.formerName, currentName: r.currentName, timestamp: r.until, rule: r.basis });
    for (const h of [...collectorHostnames, importCollector]) if (h.trim()) m.markCollector(h);
    return m;
  }

  /**
   * A live collector identity (an Fqdn / Hostname / flow client the case collected from) is never a
   * former name: two machines that genuinely share a name — a base-image clone next to the original,
   * a re-imaged host — must stay two hosts. Refused at resolve time, so it also covers edges learned
   * before the name was marked.
   */
  markCollector(name: string): void {
    const key = shortHostName(name);
    if (key) {
      this.collectors.add(key);
      this.hops = null;
    }
  }

  learn(rows: Iterable<Row>): void {
    for (const row of rows) {
      const computer = recordComputer(row);
      if (computer) this.seen.add(shortHostName(computer));
      // A collector this FILE names is marked before any row is resolved (Codex, review of #1495):
      // in a multi-host export a live client's own name must not fold into a rename another row
      // supplies, and the map cannot wait for the ledger to learn it after the fact.
      const collector = recordCollector(row);
      if (collector) this.markCollector(collector);
      const ev = renameEvidence(row);
      if (ev) this.add(ev);
    }
  }

  add(ev: RenameEvidence): void {
    this.edges.push({
      former: ev.formerName,
      current: ev.currentName,
      key: shortHostName(ev.formerName),
      currentKey: shortHostName(ev.currentName),
      ts: ev.timestamp ? Date.parse(ev.timestamp) : NaN,
      needsFormerSeen: ev.needsFormerSeen === true,
      rule: ev.rule,
    });
    this.hops = null;
  }

  /** The current name of `name` for a record written at `at` (UTC ISO), else `name` itself. */
  currentNameOf(name: string, at: string): string {
    const when = Date.parse(at);
    if (!name.trim() || Number.isNaN(when)) return name;
    const hops = this.resolve();
    const visited = new Set<string>();
    let key = shortHostName(name);
    let out = name;
    while (hops.has(key)) {
      if (visited.has(key)) return name; // a cycle: vouch for nothing
      visited.add(key);
      const hop = hops.get(key)!;
      if (Number.isNaN(hop.ts) || when > hop.ts) return name; // after the rename, or undated evidence
      out = hop.current;
      key = hop.currentKey;
    }
    return out;
  }

  /**
   * The bound a record dated `at` folded under: the EARLIEST evidence time along the chain from
   * `name` to its current name (each hop is an upper bound on its own rename; the chain holds only
   * while every hop does). "" when the map vouches for nothing at `at`.
   */
  boundFor(name: string, at: string): string {
    if (this.currentNameOf(name, at) === name) return "";
    const hops = this.resolve();
    let key = shortHostName(name);
    let bound = Infinity;
    const visited = new Set<string>();
    while (hops.has(key) && !visited.has(key)) {
      visited.add(key);
      const hop = hops.get(key)!;
      bound = Math.min(bound, hop.ts);
      key = hop.currentKey;
    }
    return Number.isFinite(bound) ? new Date(bound).toISOString() : "";
  }

  /**
   * Every dated edge this map learned that passed its own validity bound (rule c's "former name
   * seen"), one per (former, current) pair at the earliest time — RAW, not resolved: a conflicting
   * pair is handed out with both sides, so the case that stores them fails it closed too (#1495).
   */
  records(): HostRenameRecord[] {
    const out = new Map<string, HostRenameRecord>();
    for (const e of this.edges) {
      if (Number.isNaN(e.ts) || (e.needsFormerSeen && !this.seen.has(e.key))) continue;
      const key = `${e.key}|${e.currentKey}`;
      const cur = out.get(key);
      const until = new Date(e.ts).toISOString();
      if (!cur) out.set(key, { formerName: e.former, currentName: e.current, until, basis: e.rule });
      else if (e.ts < Date.parse(cur.until)) out.set(key, { ...cur, until, basis: e.rule });
    }
    return [...out.values()];
  }

  /** `currentNameOf` for a raw row: the name it wrote, dated by the row itself. */
  currentNameForRow(name: string, row: Row): string {
    return this.currentNameOf(name, recordTime(row));
  }

  /** `boundFor` for a raw row, dated by the row itself. */
  boundForRow(name: string, row: Row): string {
    return this.boundFor(name, recordTime(row));
  }

  /** Every (former → current) pair the map will honour, for tests and diagnostics. */
  formerNames(): { formerName: string; currentName: string }[] {
    const hops = this.resolve();
    const out: { formerName: string; currentName: string }[] = [];
    for (const [key, hop] of hops) {
      const former = this.edges.find((e) => e.key === key)!.former;
      const current = this.currentNameOf(former, new Date(hop.ts).toISOString());
      if (current !== former) out.push({ formerName: former, currentName: current });
    }
    return out;
  }

  private resolve(): Map<string, Hop> {
    if (this.hops) return this.hops;
    const byFormer = new Map<string, Map<string, Hop>>();
    for (const e of this.edges) {
      if (e.needsFormerSeen && !this.seen.has(e.key)) continue;
      if (this.collectors.has(e.key)) continue; // a live collector identity is nobody's former name
      const targets = byFormer.get(e.key) ?? new Map<string, Hop>();
      // Every rule observes the machine AFTER it was renamed (the 6011 is logged under the new name;
      // the account and SAM names lag until a reboot), so each observation is an upper bound on the
      // rename and the EARLIEST one is the tightest. A later observation must never widen it: a real
      // machine that reused the old name between two observations would otherwise be folded in.
      const cur = targets.get(e.currentKey);
      if (!cur) targets.set(e.currentKey, { current: e.current, currentKey: e.currentKey, ts: e.ts });
      else if (!Number.isNaN(e.ts) && (Number.isNaN(cur.ts) || e.ts < cur.ts)) cur.ts = e.ts;
      byFormer.set(e.key, targets);
    }
    const hops = new Map<string, Hop>();
    for (const [key, targets] of byFormer) {
      if (targets.size !== 1) continue; // two different current names: vouch for neither
      hops.set(key, [...targets.values()][0]);
    }
    this.hops = hops;
    return hops;
  }
}
