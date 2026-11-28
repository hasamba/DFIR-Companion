import type { ForensicEvent } from "./stateTypes.js";
import { canonicalFile } from "./canonicalEvent.js";

// Field readers shared by the evidence graph (evidenceGraph.ts), the directed lateral-movement hops
// (lateralDirection.ts) and the shared-binary/shared-account host links (sharedHostLinks.ts). Kept in
// one module so the three read a host, a hash or an account the same way, without an import cycle.

export type Confidence = "high" | "medium" | "low";

export const hostNodeId = (name: string): string => `host:${name.toLowerCase()}`;

export function shortHash(h: string): string {
  return h.length > 14 ? `${h.slice(0, 12)}…` : h;
}

// Windows virtual/service principals that are NOT users — every host has a DWM/UMFD/MSI
// session object, so their appearance on many hosts is NOT lateral movement. Dropped from the
// account rules so they don't manufacture host↔host links from machine noise. (The regex captures
// the truncated tail of spaced namespaces like "Window Manager\DWM-1" as "Manager\DWM-1", so match
// on the user part too.)
// Both sides must also list the TRUNCATED form of every spaced name. extractAccounts' DOMAIN\user
// regex starts matching at the last space, so "NT AUTHORITY\LOCAL SERVICE" arrives as
// "AUTHORITY\LOCAL" — neither side matching its untruncated spelling. That leak chained every
// Windows host in a case into one confident-looking path (LOCAL/NETWORK/ANONYMOUS run everywhere).
// Anchored full-token matches, so real accounts that merely start with these words (CORP\network.admin)
// are unaffected.
const PSEUDO_ACCT_DOMAIN =
  /^(global|local|session|nt authority|authority|nt service|service|window manager|font driver host|iis apppool|apppool)$/i;
const PSEUDO_ACCT_USER =
  /^(dwm-\d+|umfd-\d+|msi[0-9a-f]+|system|local service|network service|anonymous logon|local|network|anonymous)$/i;
export function isPseudoAccount(acct: string): boolean {
  const i = acct.indexOf("\\");
  const domain = i >= 0 ? acct.slice(0, i) : "";
  const user = i >= 0 ? acct.slice(i + 1) : acct;
  return PSEUDO_ACCT_DOMAIN.test(domain.trim()) || PSEUDO_ACCT_USER.test(user.trim());
}

export function eventAsset(event: ForensicEvent): string {
  const target = event.canonical?.target;
  return ((target?.kind === "host" ? target.name : undefined) ?? event.asset ?? "").trim();
}

export function eventHash(event: ForensicEvent): string {
  const file = canonicalFile(event);
  return (file?.sha256 ?? file?.md5 ?? "").trim().toLowerCase();
}

export function eventPath(event: ForensicEvent): string {
  return (canonicalFile(event)?.path ?? "").trim();
}

// Unparseable/absent timestamps sort as epoch (0) rather than poisoning comparisons with NaN —
// mirrors how the time-window filter treats an unparseable timestamp as in-range.
export function timeOf(ts: string): number {
  const t = Date.parse(ts);
  return Number.isFinite(t) ? t : 0;
}
