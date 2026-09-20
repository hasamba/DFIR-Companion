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

import { getCI, getPath, str } from "./siemImport.js";
import type { MappedEvent } from "./siemImport.js";
import { isDetectionSampleHost } from "./veloDetectionNoise.js";

type Row = Record<string, unknown>;

export interface RowHost {
  // The machine the event belongs to ("" when the row names none).
  asset: string;
  // The name the record itself carries, when it is not the collector's — a former hostname.
  formerName?: string;
  // True when `asset` came from the collector (Fqdn/Hostname), not from the record.
  collectorIdentity: boolean;
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

function channelOf(row: Row): string {
  return readKey(row, "Channel") || readKey(row, "System.Channel") || readKey(row, "Event.System.Channel");
}

// `recordName` lets a caller that already unwrapped the event (Chainsaw's `document.data.Event`)
// hand in the name it found there; otherwise the record keys above are read from `row` itself.
// `collectorFallback` is the IMPORT's client — a Velociraptor flow export carries no Fqdn per row,
// but a flow is one client by definition and the route knows its hostname (#1458). A per-row
// collector key still wins; the fallback only stands in when the row names none.
export function resolveRowHost(row: Row, recordName?: string, collectorFallback = ""): RowHost {
  const collector = firstKey(row, COLLECTOR_KEYS) || collectorFallback.trim();
  const record = (recordName ?? "").trim() || firstKey(row, RECORD_KEYS);
  if (!collector) return { asset: record, collectorIdentity: false };
  if (!record || shortHostName(record) === shortHostName(collector))
    return { asset: collector, collectorIdentity: true };
  if (FORWARDED_CHANNEL.test(channelOf(row))) return { asset: record, collectorIdentity: true };
  return { asset: collector, formerName: record, collectorIdentity: true };
}

export function withFormerHostSuffix(description: string, formerName?: string): string {
  if (!formerName) return description;
  return `${description} [logged under former hostname ${formerName}]`.slice(0, 600);
}

// Demote a detection that fired on a public sample corpus's host — only when the row names no
// collector, so a renamed host's own history is never mistaken for that corpus. Mutates in place,
// as the importers' other overlays do.
export function demoteSampleHost(ev: MappedEvent, host: RowHost): void {
  if (host.collectorIdentity || ev.severity === "Info" || !isDetectionSampleHost(ev.asset ?? "")) return;
  ev.severity = "Info";
  ev.description =
    `${ev.description} [detection sample corpus — ${ev.asset} is not a host in this collection]`.slice(
      0,
      600,
    );
}

// Per-import ledger of renames: one Info marker per (asset, former name) pair, stamped with the last
// time the old name was seen, so the analyst reads the rename once instead of inferring it.
export class HostRenameLedger {
  private readonly seen = new Map<string, { asset: string; formerName: string; last: string }>();

  note(host: RowHost, timestamp: string): void {
    if (!host.formerName) return;
    const key = `${host.asset}|${host.formerName}`.toLowerCase();
    const cur = this.seen.get(key);
    if (!cur) this.seen.set(key, { asset: host.asset, formerName: host.formerName, last: timestamp });
    else if (timestamp > cur.last) cur.last = timestamp;
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
