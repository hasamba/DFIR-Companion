// Which machine does an event belong to, when the row names two?
//
// A Velociraptor hunt row carries the COLLECTOR's identity (`Fqdn`, beside `ClientId`/`FlowId`:
// the client the file was read from) and, for a Windows event, the name written INTO the record
// (`Computer`, `System.Computer`, Chainsaw's `SystemData.Computer`). They agree on almost every row.
// They disagree when the machine was renamed: its own event logs keep the OLD name on every record
// written before the rename. A Vagrant-built Windows box ships as WIN-UK1GV882OK6 and is renamed by
// the provisioner, so every lab built from it logs its own provisioning under that name (#1417).
//
// The collector identity is the asset. The record's name, when it differs, is a former name and
// rides along in the description so the analyst can see the rename — it never becomes a second
// host. One exception: a ForwardedEvents record names another machine on purpose (Windows Event
// Forwarding), and there the record's Computer IS the asset.
//
// The sample-host demotion (veloDetectionNoise) fires only when a row has NO collector identity.
// A hunt row that says Fqdn=DESKTOP-X and Computer=WIN-UK1GV882OK6 is DESKTOP-X's own history, not
// a foreign sample corpus; a bare Chainsaw/Hayabusa file that names only WIN-UK1GV882OK6 keeps the
// demotion, because nothing else says which machine the file came from.
//
// A file with NO collector identity can still say so itself (#1489): the System 6011 rename event,
// the machine's own account under the SYSTEM session, and the SAM domain of a local account are
// facts the machine wrote about its own former names (hostRenameEvidence.ts). An importer learns
// them in a pre-pass over the file and hands the map in; a record under a former name then lands on
// the current name exactly as a hunt row does, and is not a sample corpus either.

import { getCI, getPath, str } from "./siemImport.js";
import type { MappedEvent } from "./siemImport.js";
import { isDetectionSampleHost } from "./veloDetectionNoise.js";
import type { HostRenameMap } from "./hostRenameEvidence.js";
import type { HostRenameRecord, RenameBasis } from "./hostRenameRecord.js";

type Row = Record<string, unknown>;

export interface RowHost {
  // The machine the event belongs to ("" when the row names none).
  asset: string;
  // The name the record itself carries, when it is not the collector's — a former hostname.
  formerName?: string;
  // True when `asset` came from the collector (Fqdn/Hostname or the import's client), not from the record.
  collectorIdentity: boolean;
  // True when `asset` is the record's own name resolved through the file's rename evidence (#1489):
  // not a collector identity, but a claim the machine made about itself, and no sample corpus.
  viaRenameEvidence?: true;
  // The name the record wrote, kept as durable provenance on a row that named NO collector and is
  // not a forwarded event — the only rows a later rename the case learns may re-home (#1495). Absent
  // on a collector-identified or ForwardedEvents row, which no ledger ever touches.
  assetRecord?: string;
  // With `viaRenameEvidence`: the bound the fold rests on (the earliest evidence along the chain).
  renameBound?: string;
  // With `collectorIdentity` from the IMPORT's fallback: who asserted it — the collector (a flow's
  // client, #1458) or the analyst (#1496). Absent when a per-row key named the collector.
  fallbackBasis?: "collector" | "analyst";
}

// The collector's identity, in order of trust. `Hostname` is Velociraptor's client hostname (and
// THOR's `hostname`). NOT `ClientName`: on a Windows logon record (4624/4778, CondensedAccountUsage)
// that is the RDP client's workstation — the REMOTE machine — so reading it as the collector made
// the remote name the asset and the host's own name a "former name".
const COLLECTOR_KEYS = ["Fqdn", "Hostname"];
// The name inside the record, across every Windows-event shape the importers accept.
const RECORD_KEYS = [
  "Computer",
  "ComputerName",
  "System.Computer",
  "Event.System.Computer",
  "_Event.System.Computer",
  "SystemData.Computer",
  "Host",
];
const FORWARDED_CHANNEL = /^ForwardedEvents$/i;

// Velociraptor artifacts write "-" for a field the event did not carry; it is an absent value.
const ABSENT = new Set(["-", "n/a"]);
const readKey = (row: Row, k: string): string => {
  const v = str(k.includes(".") ? getPath(row, k) : getCI(row, k)).trim();
  return ABSENT.has(v.toLowerCase()) ? "" : v;
};

function firstKey(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = readKey(row, k);
    if (v) return v;
  }
  return "";
}

// The first DNS label, upper-cased — the form both names share once the suffix is gone.
export function shortHostName(name: string): string {
  return name.trim().split(".")[0].toUpperCase();
}

/** The name written INTO the record (its Computer), in any shape the importers accept; "" if none. */
export function recordComputer(row: Row): string {
  return firstKey(row, RECORD_KEYS);
}

/** The collector identity a row names (Fqdn / Hostname), "" when it names none. */
export function recordCollector(row: Row): string {
  return firstKey(row, COLLECTOR_KEYS);
}

// Every spelling of the channel across the shapes RECORD_KEYS covers. A ForwardedEvents test must
// see the EMBEDDED event's channel too: an outer detection wrapper may carry its own Channel while the
// record inside came through Windows Event Forwarding.
const CHANNEL_KEYS = [
  "Channel",
  "System.Channel",
  "Event.System.Channel",
  "_Event.System.Channel",
  "SystemData.Channel",
];
function isForwarded(row: Row): boolean {
  return CHANNEL_KEYS.some((k) => FORWARDED_CHANNEL.test(readKey(row, k)));
}

// `recordName` lets a caller that already unwrapped the event (Chainsaw's `document.data.Event`)
// hand in the name it found there; otherwise the record keys above are read from `row` itself.
// `collectorFallback` is the IMPORT's client — a Velociraptor flow export carries no Fqdn per row,
// but a flow is one client by definition and the route knows its hostname (#1458). A per-row
// collector key still wins; the fallback only stands in when the row names none.
// `aliases` is the file's own rename evidence (#1489), consulted only when nothing names a
// collector: a record dated before the rename lands on the current name with the old one as its
// former name. A ForwardedEvents record names another machine on purpose and is never re-resolved.
// `fallbackBasis` says who supplied `collectorFallback` (#1496): the ledger keeps an analyst's
// declaration apart from a collector's own identity.
export function resolveRowHost(
  row: Row,
  recordName?: string,
  collectorFallback = "",
  aliases?: HostRenameMap,
  fallbackBasis: "collector" | "analyst" = "collector",
): RowHost {
  const fromRow = firstKey(row, COLLECTOR_KEYS);
  const collector = fromRow || collectorFallback.trim();
  const basis = fromRow ? {} : { fallbackBasis };
  const record = (recordName ?? "").trim() || firstKey(row, RECORD_KEYS);
  if (!collector) {
    if (!record) return { asset: record, collectorIdentity: false };
    if (isForwarded(row)) return { asset: record, collectorIdentity: false };
    const bare: RowHost = { asset: record, collectorIdentity: false, assetRecord: record };
    if (!aliases) return bare;
    const current = aliases.currentNameForRow(record, row);
    if (shortHostName(current) === shortHostName(record)) return bare;
    return {
      ...bare,
      asset: current,
      formerName: record,
      viaRenameEvidence: true,
      renameBound: aliases.boundForRow(record, row),
    };
  }
  if (!record || shortHostName(record) === shortHostName(collector))
    return { asset: collector, collectorIdentity: true, ...basis };
  if (isForwarded(row)) return { asset: record, collectorIdentity: true, ...basis };
  return { asset: collector, formerName: record, collectorIdentity: true, ...basis };
}

export function withFormerHostSuffix(description: string, formerName?: string): string {
  if (!formerName) return description;
  return `${description} [logged under former hostname ${formerName}]`.slice(0, 600);
}

// Demote a detection that fired on a public sample corpus's host — only when the row names no
// collector and no rename evidence resolved it, so a renamed host's own history is never mistaken
// for that corpus. Mutates in place, as the importers' other overlays do.
export function demoteSampleHost(ev: MappedEvent, host: RowHost): void {
  if (host.collectorIdentity || host.viaRenameEvidence) return;
  if (ev.severity === "Info" || !isDetectionSampleHost(ev.asset ?? "")) return;
  ev.severity = "Info";
  ev.description =
    `${ev.description} [detection sample corpus — ${ev.asset} is not a host in this collection]`.slice(
      0,
      600,
    );
}

// Per-import ledger of renames: one Info marker per (asset, former name) pair, stamped with the last
// time the old name was seen, so the analyst reads the rename once instead of inferring it. It also
// keeps what the CASE must remember (#1495): the collector-identified renames as records, with the
// bound each rests on, and every collector identity seen — the names no later import may fold.
export class HostRenameLedger {
  private readonly seen = new Map<
    string,
    { asset: string; formerName: string; last: string; bound: string; evidence: boolean; basis: RenameBasis }
  >();
  private readonly collectors = new Set<string>();

  note(host: RowHost, timestamp: string): void {
    if (host.collectorIdentity && host.asset) this.collectors.add(host.asset);
    if (!host.formerName) return;
    const key = `${host.asset}|${host.formerName}`.toLowerCase();
    const cur = this.seen.get(key);
    if (!cur)
      this.seen.set(key, {
        asset: host.asset,
        formerName: host.formerName,
        last: timestamp,
        bound: host.renameBound ?? "",
        evidence: host.viaRenameEvidence === true,
        basis: host.fallbackBasis ?? "collector",
      });
    else if (timestamp > cur.last) cur.last = timestamp;
  }

  /** Every collector identity this import attributed rows to, as written (deduped case-insensitively). */
  collectorHostnames(): string[] {
    const out = new Map<string, string>();
    for (const h of this.collectors) if (!out.has(h.toLowerCase())) out.set(h.toLowerCase(), h);
    return [...out.values()];
  }

  /**
   * The COLLECTOR renames this import saw (Fqdn ≠ Computer, #1417), for the case's ledger. Bounded
   * by the last record seen under the old name — the machine was still called that then, so a
   * record after it is never folded on this evidence. Evidence renames are not repeated here: the
   * map that found them hands out its own raw edges (HostRenameMap.records()).
   */
  records(): HostRenameRecord[] {
    return [...this.seen.values()]
      .filter((r) => !r.evidence && r.last && !Number.isNaN(Date.parse(r.last)))
      .map((r) => ({
        formerName: r.formerName,
        currentName: r.asset,
        until: new Date(Date.parse(r.last)).toISOString(),
        basis: r.basis,
      }));
  }

  events(): MappedEvent[] {
    return [...this.seen.values()].map((r) => ({
      timestamp: r.last,
      description: `Host ${r.asset} was named ${r.formerName} until ${r.last || "an unknown time"} (its older records carry that name)`,
      severity: "Info",
      mitre: [],
      aggKey: `host-rename|${r.asset}|${r.formerName}`.toLowerCase(),
      asset: r.asset,
    }));
  }
}
