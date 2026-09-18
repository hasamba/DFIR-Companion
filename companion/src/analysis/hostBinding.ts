import { isIPv6 } from "node:net";
import type { ForensicEvent } from "./stateTypes.js";
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";

// End-to-end host identity for a NETWORK-side spelling — an IP address or an authenticated
// username — that never appears as a short name/FQDN/client id and so `hostAlias.ts` cannot
// resolve it. A proxy or SMB server log names its client this way; an endpoint's own logs (Sysmon,
// Security event log) name the same machine by hostname. This module bridges that gap with the
// only evidence this codebase actually has for it today: a successful Windows logon (Security
// 4624), read carefully for WHICH host each field actually names.
//
// DIRECTIONALITY. A 4624 is recorded ON the host receiving the logon (`canonical.target.name` /
// `event.asset` — call it the SESSION host). Its `network.source.address` is the REMOTE peer that
// initiated the logon — for a network logon (e.g. an SMB client authenticating to a file server)
// that is the CLIENT's IP, not the session host's. The session host can never appear as its own
// source IP (a self-sourced logon has no routable address — see NON_IDENTIFYING_IPS below), so
// pairing `source.address` with the session host would name every IP binding after the wrong
// machine (the server, not the client at that IP) — every single time. The one field that actually
// names the CLIENT machine is `session.terminal` (Workstation Name): populated by the client on a
// network/remote-interactive logon, this is standard DFIR tradecraft for pairing an IP with the
// machine that used it (lateral-movement hunting over 4624 does exactly this). So:
//   - IP -> host binds `network.source.address` to `session.terminal` (the CLIENT name) — NEVER to
//     target/asset. An event with a meaningful source IP but no Workstation Name contributes no IP
//     binding; falling back to target/asset would silently mislabel the client as the server.
//   - account -> host binds the logged-on account to the SESSION host (target/asset) — that
//     reading is correct only when the logon means "the account is present at/using this host,"
//     which holds for the interactive-family logon types (Interactive, Unlock, RemoteInteractive/
//     RDP, CachedInteractive) and not for a network logon (LogonType 3), NetworkCleartext,
//     NewCredentials, Batch or Service, where the account merely authenticated ACROSS the network
//     TO the session host without ever "using" it. Mirrors `siemImport.ts`'s own `LOGON_TYPES`
//     table (2/7/10/11) rather than redefining it.
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

// Interactive-family LogonType codes where the account is actually present at/using the session
// host, not merely authenticating to it across the network. Mirrors siemImport.ts's LOGON_TYPES:
// 2 Interactive, 7 Unlock, 10 RemoteInteractive/RDP, 11 CachedInteractive.
const ACCOUNT_PRESENCE_LOGON_TYPES = new Set([2, 7, 10, 11]);

// Exported so any other module deriving something from "would this event be indexed here"
// shares the SAME predicate rather than re-deriving it — proxyWorkstationChain.ts's own
// isIndexedLogon used to be a private copy of exactly this check (#1188).
export function isIndexableLogon(e: ForensicEvent): boolean {
  return e.canonical?.event?.type === "logon" && e.canonical?.event?.outcome === "success";
}

// A logon whose IP is empty, a placeholder, or loopback is not a real network-identity source —
// every host on the fleet logs these the same way, so admitting them would make an IP "match"
// every host in the case.
const NON_IDENTIFYING_IPS = new Set(["", "-", "0.0.0.0", "::", "::1", "127.0.0.1"]);

// Windows commonly records Workstation Name as "-" (or "*") when the field is unpopulated —
// the same placeholder convention this module already applies to IPs above. Binding an IP to a
// host literally named "-" would be a junk binding, not an absent one.
const NON_IDENTIFYING_CLIENT_NAMES = new Set(["-", "*"]);

// Exported so any other module reading session.terminal / Workstation Name applies the SAME
// placeholder rejection rather than re-deriving its own — hostScopeAggregate.ts (#1231) and
// loginGraph.ts (#1232) both had their own gap here until they started sharing this.
export function isIdentifyingClientName(name: string): boolean {
  const trimmed = name.trim();
  return trimmed.length > 0 && !NON_IDENTIFYING_CLIENT_NAMES.has(trimmed);
}

// A computer account or a well-known non-human principal appears on essentially every host's own
// local logons and corroborates nothing about which machine a HUMAN was using.
const NON_HUMAN_ACCOUNTS = new Set(["system", "local service", "network service", "anonymous logon"]);

// Built-in local accounts (Administrator RID 500, Guest RID 501, plus the fixed RID 503/504
// DefaultAccount/WDAGUtilityAccount) live in every Windows host's own local SAM under that name —
// an un-domained "administrator" logon on host A and on host B are two different local principals
// that merely share a name, the same "matches every host" failure the module already guards
// against for IPs. Excluded ONLY when no domain is present: a domained "CORP\Administrator" is a
// specific, identifying domain account, not a local built-in.
//
// Administrator/Guest are localized on non-English Windows installs (the SAM display name, not the
// RID, is what 4624 records) — DefaultAccount and WDAGUtilityAccount are not localized by Microsoft
// and appear under the same English name on every locale.
const NON_HUMAN_LOCAL_ACCOUNTS_NO_DOMAIN = new Set([
  // English
  "administrator",
  "guest",
  // French
  "administrateur",
  "invité",
  // German
  "administrator",
  "gast",
  // Spanish
  "administrador",
  "invitado",
  // Portuguese
  "administrador",
  "convidado",
  // Italian
  "amministratore",
  "ospite",
  // Dutch
  "beheerder",
  "gast",
  // Non-localized fixed built-ins (RID 503 / RID 504)
  "defaultaccount",
  "wdagutilityaccount",
]);

function isLoopbackV4(ip: string): boolean {
  return /^127\./.test(ip);
}

// IPv4 link-local / APIPA (169.254.0.0/16): the exact IPv4 analog of IPv6 link-local below —
// auto-assigned when DHCP fails, valid only on its own segment, so the same textual address can
// legitimately name two unrelated hosts. Excluding IPv6 link-local while admitting its IPv4
// counterpart would be an inconsistent standard the module doesn't otherwise apply (Ollama review
// finding on #1160).
function isLinkLocalV4(ip: string): boolean {
  return /^169\.254\./.test(ip);
}

// IPv6 link-local (fe80::/10): auto-configured per-interface, valid only on its own link, and
// this module already strips the "%zone" suffix that would disambiguate it (see canonicalIp) —
// without that scope, the same textual "fe80::..." address can legitimately name two unrelated
// hosts on two different links within the same case. Matches the module's own stated intent at
// canonicalIp's own comment, which describes this exclusion but never implemented it.
//
// ULA (fc00::/7) is deliberately NOT excluded here: unlike link-local, a ULA address's /48 prefix
// is meant to be effectively globally unique (RFC 4193), the same functional role RFC1918 IPv4
// plays for a fleet — and this module already treats RFC1918 as identifying (it is not in
// NON_IDENTIFYING_IPS). Excluding ULA but not RFC1918 would apply an inconsistent standard to the
// two address families for no evidenced reason.
function isLinkLocalV6(ip: string): boolean {
  return /^fe[89ab][0-9a-f]:/.test(ip);
}

// IPv4-mapped IPv6 ("::ffff:10.0.0.5") folds to the dotted-quad form so a source that logs one
// form and a source that logs the other still collide on the same key. Matched on the ORIGINAL
// textual form: the generic IPv6 normalization below rewrites the trailing dotted-quad into hex
// groups ("::ffff:a00:5"), which would need un-parsing to recover "10.0.0.5" — matching before
// that rewrite is simpler and exact.
const IPV4_MAPPED_RE = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/;

export function canonicalIp(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  // A zone-scoped link-local address ("fe80::1%eth0") is only unique per-link, and node's IPv6
  // parser rejects the "%zone" suffix outright — treat it as non-identifying rather than let it
  // silently bypass normalization and fragment across differently-zoned spellings.
  const withoutZone = trimmed.split("%")[0];
  const mappedV4 = IPV4_MAPPED_RE.exec(withoutZone);
  if (mappedV4) return mappedV4[1];
  if (isIPv6(withoutZone)) {
    try {
      return new URL(`http://[${withoutZone}]`).hostname.replace(/^\[|\]$/g, "");
    } catch {
      return withoutZone;
    }
  }
  return withoutZone;
}

export function canonicalAccount(domain: string | undefined, name: string): string {
  const n = name.trim().toLowerCase();
  // A placeholder domain ('-'/'*') must fold the same way here as it does for the admission gate
  // (hasNoDomain, below) — otherwise a domain that GATES as "absent" but still spells its way into
  // the index KEY makes the binding unreachable: resolveAccountAtTime looks up the bare name, never
  // "-\name" (#1246). No current importer produces this shape (winAccountRoles.ts's entity()
  // already collapses "-" before this module sees it) — defense-in-depth, not a live bug.
  return hasNoDomain(domain) ? n : `${domain!.trim().toLowerCase()}\\${n}`;
}

export type IpExclusionReason = "placeholder" | "loopback-v4" | "link-local-v4" | "link-local-v6";

/** Why `isIdentifyingIp` would reject this address, or `null` when it would not (#1236) — exported
 * so a caller wanting exclusion observability (buildHostBindingIndex's own `excluded` sink below)
 * can count by reason without duplicating these checks. */
export function ipExclusionReason(raw: string): IpExclusionReason | null {
  const ip = canonicalIp(raw);
  if (NON_IDENTIFYING_IPS.has(ip)) return "placeholder";
  if (isLoopbackV4(ip)) return "loopback-v4";
  if (isLinkLocalV4(ip)) return "link-local-v4";
  if (isLinkLocalV6(ip)) return "link-local-v6";
  return null;
}

/** Not a real, per-machine address — a placeholder, loopback or link-local. Reused by dnsCrossUploadConnJoin.ts (#996): a match on one of these is noise, not identity, on the connection side too. */
export function isIdentifyingIp(raw: string): boolean {
  return ipExclusionReason(raw) === null;
}

// The real Windows-logon importer (winAccountRoles.ts's own entity()) already collapses a "-" or
// empty TargetDomainName to an omitted domain before this module ever sees it, so `domain` here
// should normally arrive as undefined for a local-SAM logon — but this check folds "-"/"*"
// defensively too, matching this module's own established placeholder-rejection convention
// (NON_IDENTIFYING_IPS, NON_IDENTIFYING_CLIENT_NAMES) rather than trusting every present or future
// caller to have already normalized it (Ollama review finding on #1161).
function hasNoDomain(domain: string | undefined): boolean {
  const d = domain?.trim();
  return !d || d === "-" || d === "*";
}

// Two real producers of a canonical account block that ALSO carry a domain field
// (winAccountRoles.ts's own entity(), and this module's own legacy-prose upgrade in
// canonicalEvent.ts) both put the FULL "domain\name" string into account.name and repeat the
// domain separately in account.domain — composing a key from both naively would double the
// domain prefix ("corp\corp\jdoe"), a key no real caller would ever query, and would also make
// every human/non-human name check below compare against a domain-qualified string instead of a
// bare name (a pre-existing bug found while adding #1162's own end-to-end legacy-path test).
// Strip the prefix ONLY when a domain is independently present: a producer that qualifies
// account.name WITHOUT setting account.domain (e.g. ecarImport.ts's raw, unprocessed `principal`
// field) has no separate domain to reconstruct from, and stripping there would silently discard
// the only copy of that information and risk colliding with an unrelated un-domained local
// account of the same bare name (Ollama review finding on #1162).
function bareAccountName(name: string, domain: string | undefined): string {
  if (hasNoDomain(domain)) return name;
  const sep = name.lastIndexOf("\\");
  if (sep !== -1) return name.slice(sep + 1);
  // A UPN (jdoe@corp.com) with a real domain SEPARATELY recorded (winAccountRoles.ts's entity()
  // now prefers that domain over the UPN's own realm, #1253) carries no backslash for the check
  // above to find — without this, the key became "corp\jdoe@corp.com" (both the resolved domain
  // AND the UPN's own realm baked into one key), unreachable by the domain\user spelling a same
  // session's 4624 binding elsewhere would produce.
  const at = name.lastIndexOf("@");
  return at === -1 ? name : name.slice(0, at);
}

function isHumanAccount(name: string, domain: string | undefined): boolean {
  const n = name.trim().toLowerCase();
  if (!n) return false;
  if (n.endsWith("$")) return false; // computer account
  if (NON_HUMAN_ACCOUNTS.has(n)) return false;
  if (hasNoDomain(domain) && NON_HUMAN_LOCAL_ACCOUNTS_NO_DOMAIN.has(n)) return false;
  return true;
}

function push(map: Map<string, HostBinding[]>, key: string, binding: HostBinding): void {
  const list = map.get(key) ?? [];
  list.push(binding);
  map.set(key, list);
}

/**
 * @param excluded Optional sink (#1236): when given, `buildHostBindingIndex` increments a count
 * per `IpExclusionReason` for every logon sample whose own source IP was policy-excluded (a
 * placeholder, loopback, or link-local address never contributed to `byIp`) — the only way to
 * distinguish "no logon evidence existed" from "evidence existed but was excluded" without this.
 * The module stays pure: nothing is read from or written to any shared/global state, only this
 * caller-owned object.
 */
export function buildHostBindingIndex(
  events: readonly ForensicEvent[],
  aliasIndex?: HostAliasIndex,
  excluded?: Map<IpExclusionReason, number>,
): HostBindingIndex {
  const index: HostBindingIndex = { byIp: new Map(), byAccount: new Map() };

  for (const event of events) {
    const c = event.canonical;
    if (!c || !isIndexableLogon(event)) continue;
    const sampleTime = event.timestamp;
    if (!sampleTime) continue;

    // IP -> host: the CLIENT's own name (Workstation Name), never the session host that recorded
    // the logon — see the DIRECTIONALITY note at the top of this file.
    const ip = c.network?.source?.address;
    const clientName = c.session?.terminal?.trim();
    if (excluded && ip) {
      const reason = ipExclusionReason(ip);
      if (reason) excluded.set(reason, (excluded.get(reason) ?? 0) + 1);
    }
    if (ip && isIdentifyingIp(ip) && clientName && isIdentifyingClientName(clientName)) {
      const host = aliasIndex ? resolveHost(aliasIndex, clientName) : clientName;
      push(index.byIp, canonicalIp(ip), {
        host,
        sampleTime,
        sourceKind: "logon-sample",
        evidenceEventId: event.id,
      });
    }

    // account -> host: the SESSION host, only for logon types where the account is actually
    // present at/using that host (not a network logon merely authenticating across to it).
    const accountName = c.account?.name ? bareAccountName(c.account.name, c.account.domain) : undefined;
    const logonType = c.authentication?.logonType;
    if (
      accountName &&
      isHumanAccount(accountName, c.account?.domain) &&
      logonType !== undefined &&
      ACCOUNT_PRESENCE_LOGON_TYPES.has(logonType) &&
      c.target?.kind === "host" &&
      c.target.name
    ) {
      const host = aliasIndex ? resolveHost(aliasIndex, c.target.name) : c.target.name;
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
