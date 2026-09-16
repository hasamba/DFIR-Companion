import { isIPv6 } from "node:net";
import type { ForensicEvent } from "./stateTypes.js";
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";

// End-to-end host identity for a NETWORK-side spelling — an IP address or an authenticated
// username — that never appears as a short name/FQDN/client id and so `hostAlias.ts` cannot
// resolve it. A proxy or SMB server log names its client this way; an endpoint's own logs (Sysmon,
// Security event log) name the same machine by hostname. This module bridges that gap with the
// only evidence this codebase actually has for it today: a successful Windows logon (Security
// 4624), which carries the source IP/account AND the target host on one record.
//
// Every binding here comes from a single record that itself states both sides of the pairing —
// never inferred from two records merely being close in time or shape (#993, #1156's own
// guardrail). Pure — no I/O, no AI call, deterministic — same contract as hostAlias.ts and
// clockSkew.ts.
//
// NOT covered (deliberately, see PLAN-1156.md "What this issue does NOT do"): DHCP lease evidence
// (no importer for it exists anywhere in this codebase), an analyst-declared override, and clock-
// skew alignment of the events fed in (a caller wanting aligned bindings passes already-aligned
// events; this module reads whatever `event.timestamp` says).

export type HostBindingSourceKind = "logon-sample";

export interface HostBinding {
  host: string; // canonical host name — resolved through HostAliasIndex when one is supplied
  sampleTime: string; // the ONE instant this binding is evidence for; not a window
  sourceKind: HostBindingSourceKind;
  evidenceEventId: string; // the ForensicEvent this binding was built from — provenance
}

export interface HostBindingIndex {
  byIp: Map<string, HostBinding[]>; // key: canonicalIp(); each list sorted by sampleTime
  byAccount: Map<string, HostBinding[]>; // key: canonicalAccount(); each list sorted by sampleTime
}

// A logon whose IP is empty, a placeholder, or loopback is not a real network-identity source —
// every host on the fleet logs these the same way, so admitting them would make an IP "match"
// every host in the case.
const NON_IDENTIFYING_IPS = new Set(["", "-", "0.0.0.0", "::", "::1", "127.0.0.1"]);

// A computer account or a well-known non-human principal appears on essentially every host's own
// local logons and corroborates nothing about which machine a HUMAN was using.
const NON_HUMAN_ACCOUNTS = new Set(["system", "local service", "network service", "anonymous logon"]);

function isLoopbackV4(ip: string): boolean {
  return /^127\./.test(ip);
}

export function canonicalIp(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  if (isIPv6(trimmed)) {
    // Fold to a stable form so "::1" and "0:0:0:0:0:0:0:1" collide: expand every group, then
    // re-compress via the URL host-parsing normalization node already implements internally.
    try {
      return new URL(`http://[${trimmed}]`).hostname.replace(/^\[|\]$/g, "");
    } catch {
      return trimmed;
    }
  }
  return trimmed;
}

export function canonicalAccount(domain: string | undefined, name: string): string {
  const n = name.trim().toLowerCase();
  const d = domain?.trim().toLowerCase();
  return d ? `${d}\\${n}` : n;
}

function isIdentifyingIp(raw: string): boolean {
  const ip = canonicalIp(raw);
  if (NON_IDENTIFYING_IPS.has(ip)) return false;
  if (isLoopbackV4(ip)) return false;
  return true;
}

function isHumanAccount(name: string): boolean {
  const n = name.trim().toLowerCase();
  if (!n) return false;
  if (n.endsWith("$")) return false; // computer account
  if (NON_HUMAN_ACCOUNTS.has(n)) return false;
  return true;
}

function push(map: Map<string, HostBinding[]>, key: string, binding: HostBinding): void {
  const list = map.get(key) ?? [];
  list.push(binding);
  map.set(key, list);
}

export function buildHostBindingIndex(
  events: readonly ForensicEvent[],
  aliasIndex?: HostAliasIndex,
): HostBindingIndex {
  const index: HostBindingIndex = { byIp: new Map(), byAccount: new Map() };

  for (const event of events) {
    const c = event.canonical;
    if (!c || c.event.type !== "logon" || c.event.outcome !== "success") continue;
    const rawHost = c.target?.name ?? event.asset;
    if (!rawHost) continue;
    const host = aliasIndex ? resolveHost(aliasIndex, rawHost) : rawHost;
    const sampleTime = event.timestamp;
    if (!sampleTime) continue;

    const ip = c.network?.source?.address;
    if (ip && isIdentifyingIp(ip)) {
      push(index.byIp, canonicalIp(ip), {
        host,
        sampleTime,
        sourceKind: "logon-sample",
        evidenceEventId: event.id,
      });
    }

    const accountName = c.account?.name;
    if (accountName && isHumanAccount(accountName)) {
      push(index.byAccount, canonicalAccount(c.account?.domain, accountName), {
        host,
        sampleTime,
        sourceKind: "logon-sample",
        evidenceEventId: event.id,
      });
    }
  }

  for (const list of index.byIp.values()) list.sort((a, b) => a.sampleTime.localeCompare(b.sampleTime));
  for (const list of index.byAccount.values()) list.sort((a, b) => a.sampleTime.localeCompare(b.sampleTime));

  return index;
}

function resolveAtTime(
  list: readonly HostBinding[] | undefined,
  atTime: string,
  toleranceMs: number,
): HostBinding[] {
  if (!list) return [];
  const at = Date.parse(atTime);
  if (!Number.isFinite(at)) return [];
  return list.filter((b) => {
    const t = Date.parse(b.sampleTime);
    return Number.isFinite(t) && Math.abs(t - at) <= toleranceMs;
  });
}

export function resolveIpAtTime(
  index: HostBindingIndex,
  ip: string,
  atTime: string,
  toleranceMs: number,
): HostBinding[] {
  return resolveAtTime(index.byIp.get(canonicalIp(ip)), atTime, toleranceMs);
}

export function resolveAccountAtTime(
  index: HostBindingIndex,
  account: string,
  atTime: string,
  toleranceMs: number,
): HostBinding[] {
  // `account` arrives as one string (e.g. "CORP\\alice" or "alice"); split on the first backslash
  // to match how canonicalAccount composes the key, rather than requiring callers to pre-split.
  const sep = account.indexOf("\\");
  const key =
    sep === -1
      ? canonicalAccount(undefined, account)
      : canonicalAccount(account.slice(0, sep), account.slice(sep + 1));
  return resolveAtTime(index.byAccount.get(key), atTime, toleranceMs);
}
