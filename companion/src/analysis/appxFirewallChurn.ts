// Firewall rule churn by an AppX package update (#1593).
//
// EID 2052/2006 delete and 2097/2004 add. When a Store package updates, the firewall service
// (MpsSvc, running in svchost.exe) deletes the capability rules of the old version and adds the same
// rules for the new one. The rule ID is the version-free package family
// (`Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-Out-Allow-…`); the rule name carries the full
// package name with its version (`@{Microsoft.DesktopAppInstaller_1.29.289.0_x64__8wekyb3d8bbwe?ms-resource://…}`).
// On INC-2026-005 one App Installer update became a Medium "rule deleted and replaced" finding.
//
// EVERY CLAIM HERE LOWERS A GRADE. A row is claimed only as one half of a PAIR on the same host: a
// delete and an add of the same rule ID, both made by \Windows\System32\svchost.exe under MpsSvc's
// own service SID, whose package names agree on package name and publisher and differ in version,
// within UPDATE_WINDOW_MS. A lone add (a first install), a lone delete (an uninstall), a same-version
// pair, or a rule changed by netsh / WmiPrvSE / a user account keeps its grade. The rule identity
// lives only in the raw EventData (the mapper renders `Protocol=` alone), so this runs in the
// collector ledger's seam, which holds the raw record (collectorChildren.ts), and the bulk driver
// primes every such row so a pair split across batches still meets.

import type { MappedEvent } from "./siemImport.js";
import { getCI, str } from "./siemImport.js";
import { eventData, eventId } from "./veloDetectionNoise.js";
import { anchored, gradeBenign } from "./benignOsActivity.js";

type Row = Record<string, unknown>;

export const APPX_FIREWALL_NOTE =
  "firewall rule replaced by an AppX package update — the firewall service swapped the old version's rule for the new";

/** The longest a package update's delete and add may sit apart and still be one update. */
export const UPDATE_WINDOW_MS = 10 * 60 * 1000;

const FIREWALL_DELETE = new Set([2006, 2052]);
const FIREWALL_ADD = new Set([2004, 2097]);
const SYSTEM_SVCHOST = /^[a-z]:[\\/]windows[\\/]system32[\\/]svchost\.exe$/i;
// The service SID of MpsSvc (Windows Defender Firewall): S-1-5-80- + SHA-1 of the UTF-16LE "MPSSVC".
const MPSSVC_SID = "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052";
// A package full name inside a resource reference: @{Name_Version_Arch_ResourceId_PublisherId?ms-resource://…}
const PACKAGE_RESOURCE =
  /^@\{([a-z0-9][a-z0-9.-]*)_(\d{1,5}\.\d{1,5}\.\d{1,5}\.\d{1,5})_([a-z0-9]+)_([^_?\s]*)_([a-z0-9]{13})\?ms-resource:\/\//i;
// The version-free rule ID: <Name>_<PublisherId>-<rest>.
const PACKAGE_RULE_ID = /^([a-z0-9][a-z0-9.-]*)_([a-z0-9]{13})-\S+$/i;

interface FirewallChange {
  op: "add" | "delete";
  ruleId: string; // lower-cased
  family: string; // name|publisher, lower-cased
  version: string;
  at: number;
}

interface FirewallCandidate extends FirewallChange {
  m: MappedEvent;
  hosts: readonly string[];
}

/** The package-update fact a firewall record carries, or null when it is not an MpsSvc AppX rule change. */
export function appxFirewallChange(raw: Row, timestamp: string): FirewallChange | null {
  const eid = eventId(raw);
  const op = FIREWALL_DELETE.has(eid) ? "delete" : FIREWALL_ADD.has(eid) ? "add" : null;
  const ed = op ? eventData(raw) : null;
  if (!op || !ed) return null;
  const get = (k: string): string => str(getCI(ed, k)).trim();
  if (!anchored(get("ModifyingApplication"), SYSTEM_SVCHOST)) return null;
  if (get("ModifyingUser").toUpperCase() !== MPSSVC_SID) return null;
  const id = PACKAGE_RULE_ID.exec(get("RuleId"));
  const pkg = PACKAGE_RESOURCE.exec(get("RuleName")) ?? PACKAGE_RESOURCE.exec(get("EmbeddedContext"));
  const at = Date.parse(timestamp ?? "");
  if (!id || !pkg || !Number.isFinite(at)) return null;
  const family = `${id[1]}|${id[2]}`.toLowerCase();
  if (`${pkg[1]}|${pkg[5]}`.toLowerCase() !== family) return null;
  return { op, ruleId: get("RuleId").toLowerCase(), family, version: pkg[2], at };
}

/** Is this raw record an AppX firewall change the ledger must see before any batch resolves? */
export function isAppxFirewallRow(raw: Row): boolean {
  return appxFirewallChange(raw, "1970-01-01T00:00:00Z") !== null;
}

export class AppxFirewallChurnLedger {
  // host|ruleId → every change seen.
  private readonly changes = new Map<string, FirewallChange[]>();
  private pending: FirewallCandidate[] = [];

  note(raw: Row, m: MappedEvent, hosts: readonly string[]): void {
    const c = appxFirewallChange(raw, m.timestamp);
    if (!c) return;
    for (const h of hosts) {
      const key = `${h}|${c.ruleId}`;
      const list = this.changes.get(key);
      if (list) list.push(c);
      else this.changes.set(key, [c]);
    }
  }

  offer(raw: Row, m: MappedEvent, hosts: readonly string[]): void {
    const c = appxFirewallChange(raw, m.timestamp);
    if (c && hosts.length > 0) this.pending.push({ ...c, m, hosts });
  }

  resolve(): void {
    const pending = this.pending;
    this.pending = [];
    for (const c of pending)
      if (c.m.severity !== "Critical" && this.hasUpdatePartner(c)) gradeBenign(c.m, APPX_FIREWALL_NOTE);
  }

  private hasUpdatePartner(c: FirewallCandidate): boolean {
    return c.hosts.some((h) =>
      (this.changes.get(`${h}|${c.ruleId}`) ?? []).some(
        (o) =>
          o.op !== c.op &&
          o.family === c.family &&
          o.version !== c.version &&
          Math.abs(o.at - c.at) <= UPDATE_WINDOW_MS,
      ),
    );
  }
}
