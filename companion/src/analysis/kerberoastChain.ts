import type { ForensicEvent, InvestigationState } from "./stateTypes.js";

// Suspected Kerberoasting → service-account use (#930 item 6). A 4769 names the service account a
// ticket was issued for; a later row where that EXACT account acts is a use; the baseline is what
// the case holds about the account and the host before the earliest RC4 request. Every stage is
// judged over a complete read or says what was not read. Nothing here says a password was
// cracked, that the ticket was used, or that the requester and the later user are one person —
// none of that is in any row.

export const ACCOUNTS_MAX = 200;
export const TICKET_ROWS_PER_ACCOUNT_MAX = 500;
export const USE_ROWS_PER_ACCOUNT_MAX = 5_000;
export const NAMED_MAX = 20;
const RC4 = new Set(["0x17", "0x18"]);
const ROAST_TECHNIQUE = "T1558.003";
export const RC4_WORDS =
  "the KDC issued a ticket encrypted with RC4 (0x17 / 0x18), an offline-cracking-compatible type; the record does not say who chose the type";
const ACQUISITION_WORDS =
  "a ticket for this account was issued to the requester; whether it was cracked is not observable in any row. A later use of the account does not prove cracking — the account may be in normal operation or have been compromised another way";

export type Stage = "ticket-requested" | "account-used-after" | "first-seen-host-use";
export type UseKind =
  "logon" | "explicit-credential-logon" | "process-start" | "service-install" | "share-access";
export type ExclusionReason =
  | "machine account"
  | "krbtgt (TGT service)"
  | "SPN form — owner not established from the record"
  | "UPN form — owner not established from the record"
  | "AES only";

export interface TicketRequest {
  eventId: string;
  at: string;
  dc: string;
  requester?: string;
  clientAddress?: string;
  encType?: string;
  rc4: boolean;
  outcome: "success" | "failed";
}

export interface AccountUse {
  eventId: string;
  at: string;
  host: string;
  kind: UseKind;
  account: string;
  sid?: string;
  initiator?: string;
  logonType?: number;
  sourceAddress?: string;
  detail?: string;
  realmState: "matched" | "not-established";
  placement: "before" | "after" | "undetermined";
  firstSeenHost: boolean;
  hostBaseline: "available" | "unavailable";
  sameObservedAddress?: {
    requestEventId: string;
    requestObserver: string;
    requestAddress: string;
    useAddress: string;
  };
}

export interface ServiceAccountChain {
  service: string;
  realm?: string;
  realmSource: "dc-fqdn" | "not-established";
  listedBecause: "rc4-request" | "aes-request-by-an-rc4-requester";
  requests: TicketRequest[];
  requestsTotal: number;
  rc4Count: number;
  aesCount: number;
  refusedCount: number;
  rc4Words: string;
  acquisition: string;
  t0?: string;
  t0Anchors: boolean;
  baseline: { hostsBefore: { host: string; count: number; first: string; last: string }[]; note: string };
  uses: AccountUse[];
  usesTotal: number;
  candidates: AccountUse[];
  candidatesTotal: number;
  failedLogonsAfter: number;
  hostsWithoutBaseline: string[];
  sameObservedAddressCount: number;
  toolEvidence: string[];
  stage: Stage;
  stageReason: string;
  evidence: Record<Stage, string[]>;
  read: {
    ticketRows: number;
    ticketRowsUnread: number;
    useRows: number;
    useRowsUnread: number;
    undated: number;
  };
}

export interface ToolLead {
  eventId: string;
  host: string;
  account?: string;
  at: string;
  detail?: string;
}

export interface KerberoastChain {
  accounts: ServiceAccountChain[];
  accountsNotShown: number;
  excluded: Partial<Record<ExclusionReason, number>>;
  toolLeads: ToolLead[];
  gaps: string[];
  generated: string;
}

/** `DOMAIN\user` / `user@realm` / bare name → the short name and the realm the string carries. */
export function splitAccount(raw: string): { name: string; realm?: string } {
  const s = raw.trim();
  if (s.includes("\\")) {
    const i = s.indexOf("\\");
    return { name: s.slice(i + 1), ...(s.slice(0, i) ? { realm: s.slice(0, i) } : {}) };
  }
  if (s.includes("@")) {
    const i = s.lastIndexOf("@");
    return { name: s.slice(0, i), ...(s.slice(i + 1) ? { realm: s.slice(i + 1) } : {}) };
  }
  return { name: s };
}

/** Both realms carried, and equal — a NetBIOS name equals a DNS domain only by its first label. */
export function realmCompatible(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  const x = a.trim().toLowerCase();
  const y = b.trim().toLowerCase();
  if (!x || !y) return false;
  if (x === y) return true;
  const xs = x.split(".")[0];
  const ys = y.split(".")[0];
  return (x.includes(".") !== y.includes(".") && xs === ys) || (x.includes(".") && y.includes(".") && false);
}

/** An address that can be compared: IPv4-mapped IPv6 unwrapped; placeholders refused. */
export function normaliseAddress(raw: string | undefined): string | null {
  const s = (raw ?? "").trim().toLowerCase();
  if (!s || s === "-") return null;
  const v4 = s.startsWith("::ffff:") ? s.slice(7) : s;
  if (v4 === "::1" || v4 === "::" || v4 === "127.0.0.1" || v4 === "0.0.0.0") return null;
  if (/^127\./.test(v4) || /^169\.254\./.test(v4) || /^fe80:/.test(v4)) return null;
  return v4;
}

const hostKey = (h: string | undefined): string => (h ?? "").trim().toLowerCase();
const ms = (ts: string | undefined): number | null => {
  const n = Date.parse(ts ?? "");
  return Number.isFinite(n) ? n : null;
};
const realmOfDc = (asset: string | undefined): string | undefined => {
  const a = (asset ?? "").trim();
  const i = a.indexOf(".");
  return i > 0 && i < a.length - 1 ? a.slice(i + 1) : undefined;
};

function readTicket(e: ForensicEvent): { service: string; request: TicketRequest } | null {
  const c = e.canonical;
  if (c?.event?.category !== "authentication" || c.event.type !== "ticket-request") return null;
  const service = c.object?.kind === "account" ? (c.object.name ?? "").trim() : "";
  if (!service) return null;
  const enc = c.authentication?.mechanism?.toLowerCase();
  return {
    service,
    request: {
      eventId: e.id,
      at: e.timestamp,
      dc: e.asset ?? "",
      ...(c.actor?.kind === "account" && c.actor.name ? { requester: c.actor.name } : {}),
      ...(c.network?.source?.address
        ? { clientAddress: normaliseAddress(c.network.source.address) ?? c.network.source.address }
        : {}),
      ...(enc ? { encType: enc } : {}),
      rc4: !!enc && RC4.has(enc),
      outcome: c.event.outcome === "failed" ? "failed" : "success",
    },
  };
}

function exclusionOf(service: string): ExclusionReason | null {
  if (service.endsWith("$")) return "machine account";
  if (/^krbtgt(\/|@|$)/i.test(service)) return "krbtgt (TGT service)";
  if (service.includes("/")) return "SPN form — owner not established from the record";
  if (service.includes("@")) return "UPN form — owner not established from the record";
  return null;
}

type UseReading = Omit<
  AccountUse,
  "realmState" | "placement" | "firstSeenHost" | "hostBaseline" | "sameObservedAddress"
> & {
  realm?: string;
  short: string;
  failed: boolean;
};

function readUse(e: ForensicEvent): UseReading | null {
  const c = e.canonical;
  const ev = c?.event;
  if (!c || !ev || c.actor?.kind !== "account" || !c.actor.name || !e.asset) return null;
  let kind: UseKind | null = null;
  let detail: string | undefined;
  if (ev.category === "authentication" && ev.type === "logon") kind = "logon";
  else if (ev.category === "authentication" && ev.type === "explicit-credential-logon")
    kind = "explicit-credential-logon";
  else if (ev.category === "process" && ev.type === "start") {
    kind = "process-start";
    detail = c.process?.executable ?? c.process?.name;
  } else if (ev.category === "service") {
    kind = "service-install";
    detail = c.service?.name;
  } else if (ev.category === "network" && ev.type === "share-access") kind = "share-access";
  if (!kind) return null;
  const { name, realm } = splitAccount(c.actor.name);
  return {
    eventId: e.id,
    at: e.timestamp,
    host: e.asset,
    kind,
    account: c.actor.name,
    short: name,
    ...((realm ?? c.actor.domain) ? { realm: realm ?? c.actor.domain } : {}),
    ...(c.account?.id ? { sid: c.account.id } : {}),
    ...(c.subject?.kind === "account" && c.subject.name ? { initiator: c.subject.name } : {}),
    ...(c.authentication?.logonType !== undefined ? { logonType: c.authentication.logonType } : {}),
    ...(c.network?.source?.address ? { sourceAddress: c.network.source.address } : {}),
    ...(detail ? { detail } : {}),
    failed: ev.outcome === "failed",
  };
}

function isToolRow(e: ForensicEvent): boolean {
  const ev = e.canonical?.event;
  return (
    (e.mitreTechniques ?? []).includes(ROAST_TECHNIQUE) &&
    !(ev?.category === "authentication" && ev.type === "ticket-request")
  );
}

interface Bucket {
  service: string;
  realm?: string;
  requests: TicketRequest[];
  total: number;
  unread: number;
}

function collectTickets(events: readonly ForensicEvent[]): {
  buckets: Map<string, Bucket>;
  excluded: Partial<Record<ExclusionReason, number>>;
  undated: number;
} {
  const buckets = new Map<string, Bucket>();
  const excluded: Partial<Record<ExclusionReason, number>> = {};
  let undated = 0;
  for (const e of events) {
    const t = readTicket(e);
    if (!t) continue;
    const why = exclusionOf(t.service);
    if (why) {
      excluded[why] = (excluded[why] ?? 0) + 1;
      continue;
    }
    if (ms(e.timestamp) === null) {
      undated += 1;
      continue;
    }
    const k = t.service.toLowerCase();
    const b =
      buckets.get(k) ?? buckets.set(k, { service: t.service, requests: [], total: 0, unread: 0 }).get(k)!;
    b.total += 1;
    if (b.requests.length >= TICKET_ROWS_PER_ACCOUNT_MAX) {
      b.unread += 1;
      continue;
    }
    b.requests.push(t.request);
    const realm = realmOfDc(e.asset);
    if (realm && !b.realm) b.realm = realm;
  }
  return { buckets, excluded, undated };
}

/** The earliest dated row on each host, folded by name — a host's own reach into the past. */
function earliestByHost(events: readonly ForensicEvent[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const e of events) {
    const t = ms(e.timestamp);
    if (t === null || !e.asset) continue;
    const k = hostKey(e.asset);
    const cur = out.get(k);
    if (cur === undefined || t < cur) out.set(k, t);
  }
  return out;
}

function chainFor(
  b: Bucket,
  listedBecause: ServiceAccountChain["listedBecause"],
  events: readonly ForensicEvent[],
  hostFloor: ReadonlyMap<string, number>,
  toolRows: readonly { id: string; account?: string }[],
): ServiceAccountChain {
  const short = b.service.toLowerCase();
  const rc4 = b.requests.filter((r) => r.rc4 && r.outcome === "success");
  const t0Ms = rc4.length ? Math.min(...rc4.map((r) => ms(r.at)!)) : null;
  const t0Anchors = t0Ms !== null && b.unread === 0;
  const read = {
    ticketRows: b.requests.length,
    ticketRowsUnread: b.unread,
    useRows: 0,
    useRowsUnread: 0,
    undated: 0,
  };
  const requestAddresses = new Map<string, TicketRequest>();
  for (const r of b.requests) {
    const a = normaliseAddress(r.clientAddress);
    if (a && !requestAddresses.has(a)) requestAddresses.set(a, r);
  }
  const uses: AccountUse[] = [];
  const candidates: AccountUse[] = [];
  const before = new Map<string, { host: string; count: number; first: string; last: string }>();
  let failedLogonsAfter = 0;
  const hostsWithoutBaseline = new Set<string>();
  const readings: UseReading[] = [];
  for (const e of events) {
    const u = readUse(e);
    if (!u || u.short.toLowerCase() !== short) continue;
    if (read.useRows >= USE_ROWS_PER_ACCOUNT_MAX) {
      read.useRowsUnread += 1;
      continue;
    }
    read.useRows += 1;
    if (ms(u.at) === null) {
      read.undated += 1;
      continue;
    }
    readings.push(u);
  }
  // Pass 1: the baseline — where the account acted before T0 (matched identity only).
  for (const u of readings) {
    if (!t0Anchors || u.failed || !realmCompatible(b.realm, u.realm)) continue;
    const t = ms(u.at)!;
    if (t >= t0Ms) continue;
    const k = hostKey(u.host);
    const cur = before.get(k);
    if (!cur) before.set(k, { host: u.host, count: 1, first: u.at, last: u.at });
    else {
      cur.count += 1;
      if (u.at < cur.first) cur.first = u.at;
      if (u.at > cur.last) cur.last = u.at;
    }
  }
  // Pass 2: every use, placed.
  for (const u of readings) {
    const matched = realmCompatible(b.realm, u.realm);
    // A realm on both sides that does not match is another account, not a candidate.
    if (!matched && b.realm && u.realm) continue;
    const t = ms(u.at)!;
    const placement: AccountUse["placement"] = !t0Anchors ? "undetermined" : t < t0Ms ? "before" : "after";
    if (u.failed) {
      if (matched && placement === "after") failedLogonsAfter += 1;
      continue;
    }
    if (placement === "before") continue;
    const k = hostKey(u.host);
    const floor = hostFloor.get(k);
    const hostBaseline: AccountUse["hostBaseline"] =
      t0Anchors && floor !== undefined && floor < t0Ms ? "available" : "unavailable";
    if (matched && placement === "after" && hostBaseline === "unavailable") hostsWithoutBaseline.add(u.host);
    const firstSeenHost = matched && placement === "after" && hostBaseline === "available" && !before.has(k);
    const src = normaliseAddress(u.sourceAddress);
    const sameReq = src ? requestAddresses.get(src) : undefined;
    const { realm: _r, short: _s, failed: _f, ...rest } = u;
    const use: AccountUse = {
      ...rest,
      realmState: matched ? "matched" : "not-established",
      placement,
      firstSeenHost,
      hostBaseline,
      ...(sameReq && matched
        ? {
            sameObservedAddress: {
              requestEventId: sameReq.eventId,
              requestObserver: sameReq.dc,
              requestAddress: sameReq.clientAddress!,
              useAddress: u.sourceAddress!,
            },
          }
        : {}),
    };
    (matched ? uses : candidates).push(use);
  }
  const after = uses.filter((u) => u.placement === "after");
  const firstSeen = after.filter((u) => u.firstSeenHost);
  const evidence: Record<Stage, string[]> = {
    "ticket-requested": b.requests.map((r) => r.eventId),
    "account-used-after": after.map((u) => u.eventId),
    "first-seen-host-use": firstSeen.map((u) => u.eventId),
  };
  const complete = b.unread === 0 && read.useRowsUnread === 0 && read.undated === 0;
  const incomplete = complete
    ? " (a complete read)"
    : ` — unknown: ${[b.unread ? `${b.unread} ticket row(s) unread` : "", read.useRowsUnread ? `${read.useRowsUnread} use row(s) unread` : "", read.undated ? `${read.undated} undated` : ""].filter(Boolean).join(", ")}`;
  let stage: Stage = "ticket-requested";
  let stageReason: string;
  if (firstSeen.length) {
    stage = "first-seen-host-use";
    stageReason = `${firstSeen.length} use(s) on a host the account was not seen on before the request, in the available evidence${incomplete}`;
  } else if (after.length) {
    stage = "account-used-after";
    stageReason = hostsWithoutBaseline.size
      ? `${after.length} use(s) after the request; baseline unavailable for ${[...hostsWithoutBaseline].join(", ")} (no rows on that host before the request)${incomplete}`
      : `every use after the request is on a host the account was seen on before it${incomplete}`;
  } else if (!b.realm) {
    stageReason = `realm not established for this account (the DC row carries no domain) — ${candidates.length} candidate use(s) listed, none joined${incomplete}`;
  } else if (!t0Anchors) {
    stageReason =
      t0Ms === null
        ? `no RC4 request anchors a before / after split; ${candidates.length + uses.length} use(s) listed as undetermined${incomplete}`
        : `the ticket read is incomplete, so no request anchors a before / after split${incomplete}`;
  } else {
    stageReason = `no row after the request shows this account acting${incomplete}`;
  }
  const requesterKeys = new Set(b.requests.map((r) => (r.requester ?? "").toLowerCase()).filter(Boolean));
  const hostsBefore = [...before.values()].sort((x, y) => x.host.localeCompare(y.host));
  return {
    service: b.service,
    ...(b.realm ? { realm: b.realm } : {}),
    realmSource: b.realm ? "dc-fqdn" : "not-established",
    listedBecause,
    requests: b.requests.slice(0, NAMED_MAX),
    requestsTotal: b.total,
    rc4Count: b.requests.filter((r) => r.rc4).length,
    aesCount: b.requests.filter((r) => !r.rc4).length,
    refusedCount: b.requests.filter((r) => r.outcome === "failed").length,
    rc4Words: RC4_WORDS,
    acquisition: ACQUISITION_WORDS,
    ...(t0Ms !== null ? { t0: new Date(t0Ms).toISOString() } : {}),
    t0Anchors,
    baseline: {
      hostsBefore,
      note: hostsBefore.length
        ? `before the request the account acted on ${hostsBefore.length} host(s) in the case`
        : t0Anchors
          ? "no prior use of this account observed in the case (not 'no prior use')"
          : "no before / after split — the baseline is not anchored",
    },
    uses: uses.slice(0, NAMED_MAX),
    usesTotal: uses.length,
    candidates: candidates.slice(0, NAMED_MAX),
    candidatesTotal: candidates.length,
    failedLogonsAfter,
    hostsWithoutBaseline: [...hostsWithoutBaseline].sort(),
    sameObservedAddressCount: uses.filter((u) => u.sameObservedAddress).length,
    toolEvidence: toolRows
      .filter((t) => t.account && requesterKeys.has(t.account.toLowerCase()))
      .map((t) => t.id),
    stage,
    stageReason,
    evidence,
    read,
  };
}

/** The reading over the forensic timeline. Pure; no AI; nothing fetched. */
export function kerberoastChain(
  state: InvestigationState,
  now: string = new Date().toISOString(),
): KerberoastChain {
  const events = state.forensicTimeline;
  const { buckets, excluded, undated } = collectTickets(events);
  const hostFloor = earliestByHost(events);
  const toolRows = events.filter(isToolRow).map((e) => ({
    id: e.id,
    host: e.asset ?? "",
    at: e.timestamp,
    account: e.canonical?.actor?.kind === "account" ? e.canonical.actor.name : undefined,
    detail: e.canonical?.process?.executable ?? e.canonical?.process?.name,
  }));
  const rc4Requesters = new Set<string>();
  for (const b of buckets.values())
    for (const r of b.requests) if (r.rc4 && r.requester) rc4Requesters.add(r.requester.toLowerCase());
  const accounts: ServiceAccountChain[] = [];
  for (const b of buckets.values()) {
    const listedBecause: ServiceAccountChain["listedBecause"] | null = b.requests.some((r) => r.rc4)
      ? "rc4-request"
      : b.requests.some((r) => r.requester && rc4Requesters.has(r.requester.toLowerCase()))
        ? "aes-request-by-an-rc4-requester"
        : null;
    if (!listedBecause) {
      excluded["AES only"] = (excluded["AES only"] ?? 0) + 1;
      continue;
    }
    accounts.push(chainFor(b, listedBecause, events, hostFloor, toolRows));
  }
  const rank: Record<Stage, number> = {
    "first-seen-host-use": 0,
    "account-used-after": 1,
    "ticket-requested": 2,
  };
  accounts.sort(
    (a, b) =>
      rank[a.stage] - rank[b.stage] ||
      Number(a.listedBecause !== "rc4-request") - Number(b.listedBecause !== "rc4-request") ||
      a.service.localeCompare(b.service),
  );
  const attached = new Set(accounts.flatMap((a) => a.toolEvidence));
  const toolLeads: ToolLead[] = toolRows
    .filter((t) => !attached.has(t.id))
    .slice(0, NAMED_MAX)
    .map((t) => ({
      eventId: t.id,
      host: t.host,
      ...(t.account ? { account: t.account } : {}),
      at: t.at,
      ...(t.detail ? { detail: t.detail } : {}),
    }));
  const gaps: string[] = [];
  if (!buckets.size && toolRows.length)
    gaps.push(
      "no ticket-request rows (4769) in the case — the account → use join cannot start; the tool rows are leads",
    );
  if (undated) gaps.push(`${undated} undated ticket row(s) not placed`);
  return {
    accounts: accounts.slice(0, ACCOUNTS_MAX),
    accountsNotShown: Math.max(0, accounts.length - ACCOUNTS_MAX),
    excluded,
    toolLeads,
    gaps,
    generated: now,
  };
}
