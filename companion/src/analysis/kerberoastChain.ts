import { isIP } from "node:net";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";

// Suspected Kerberoasting → service-account use (#930 item 6). A 4769 names the service account a
// ticket was issued for; a later row where that EXACT account acts is a use; the baseline is what
// the case holds about the account and the host before the earliest issued RC4 request. Every
// stage is judged over a complete read or says what was not read. Nothing here says a password
// was cracked, that the ticket was used, or that the requester and the later user are one
// person — none of that is in any row.
//
// Identity: a service account is (realm, name) where the realm is the issuing DC's DNS domain
// (its FQDN); a request on a DC named without a domain lands in a realm-less account of its own.
// A use joins by short name plus a compatible realm; a realm on one side only makes a candidate;
// a realm on both sides that differs is another account. Distinct SIDs under one name are an
// identity conflict that stops the stages.

export const ACCOUNTS_MAX = 200;
export const TICKET_ROWS_PER_ACCOUNT_MAX = 500;
export const USE_ROWS_PER_ACCOUNT_MAX = 5_000;
export const NAMED_MAX = 20;
const RC4 = new Set(["0x17", "0x18"]);
const ROAST_TECHNIQUE = "T1558.003";
export const RC4_WORDS =
  "the KDC issued a ticket encrypted with RC4 (0x17 / 0x18), an offline-cracking-compatible type; the record does not say who chose the type";
const REFUSED_WORDS = "the KDC refused the request(s); no ticket was issued";
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
type Family = "authentication" | "process" | "service" | "network";

export interface TicketRequest {
  eventId: string;
  at: string;
  dc: string;
  requester?: string;
  /** The client address as logged. */
  clientAddress?: string;
  /** The same address in canonical form, when it parses as an IP and is not a placeholder. */
  clientAddressNormalised?: string;
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
  placement: "before" | "after" | "contemporaneous" | "undetermined";
  firstSeenHost: boolean;
  hostBaseline: "available" | "unavailable";
  sameObservedAddress?: {
    requestEventId: string;
    requestObserver: string;
    requestAddress: string;
    useAddress: string;
    normalised: string;
  };
}

export interface ServiceAccountChain {
  service: string;
  realm?: string;
  realmSource: "dc-fqdn" | "not-established";
  listedBecause: "rc4-request" | "rc4-refused-only" | "aes-request-by-an-rc4-requester";
  requests: TicketRequest[];
  requestsTotal: number;
  rc4Count: number;
  aesCount: number;
  refusedCount: number;
  rc4Words: string;
  acquisition: string;
  t0?: string;
  t0Anchors: boolean;
  baseline: {
    hostsBefore: { host: string; count: number; first: string; last: string }[];
    hostsBeforeTotal: number;
    note: string;
  };
  uses: AccountUse[];
  usesTotal: number;
  candidates: AccountUse[];
  candidatesTotal: number;
  failedLogonsAfter: number;
  hostsWithoutBaseline: string[];
  sameObservedAddressCount: number;
  sids: string[];
  identityConflict?: string;
  toolEvidence: string[];
  toolEvidenceTotal: number;
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
  toolLeadsTotal: number;
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
  const x = (a ?? "").trim().toLowerCase();
  const y = (b ?? "").trim().toLowerCase();
  if (!x || !y) return false;
  if (x === y) return true;
  if (x.includes(".") === y.includes(".")) return false;
  return x.split(".")[0] === y.split(".")[0];
}

/** Canonical IPv6: groups expanded, lowercased, leading zeros dropped, `::` expanded. */
function canonicalIpv6(s: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (mapped) return mapped[1];
  const [head, tail = ""] = s.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const fill = s.includes("::") ? Array<string>(8 - h.length - t.length).fill("0") : [];
  return [...h, ...fill, ...t].map((g) => g.replace(/^0+(?=.)/, "").toLowerCase()).join(":");
}

/** An address that can be compared: a real IPv4 / IPv6, canonical, no loopback / unspecified / link-local. */
export function normaliseAddress(raw: string | undefined): string | null {
  const s = (raw ?? "").trim();
  const kind = isIP(s);
  if (!kind) return null;
  const v = kind === 4 ? s : canonicalIpv6(s);
  if (
    v === "0:0:0:0:0:0:0:1" ||
    v === "0:0:0:0:0:0:0:0" ||
    /^127\./.test(v) ||
    v === "0.0.0.0" ||
    /^169\.254\./.test(v)
  )
    return null;
  if (/^fe[89ab][0-9a-f]:/i.test(v)) return null;
  return v;
}

const hostKey = (h: string | undefined): string => (h ?? "").trim().toLowerCase();
const ms = (ts: string | undefined): number | null => {
  const n = Date.parse(ts ?? "");
  return Number.isFinite(n) ? n : null;
};
const realmOfDc = (asset: string | undefined): string | undefined => {
  const a = (asset ?? "").trim();
  if (isIP(a)) return undefined;
  const i = a.indexOf(".");
  return i > 0 && i < a.length - 1 ? a.slice(i + 1) : undefined;
};

function readTicket(e: ForensicEvent): { service: string; request: TicketRequest } | null {
  const c = e.canonical;
  if (c?.event?.category !== "authentication" || c.event.type !== "ticket-request") return null;
  const service = c.object?.kind === "account" ? (c.object.name ?? "").trim() : "";
  if (!service) return null;
  const enc = c.authentication?.mechanism?.toLowerCase();
  const raw = c.network?.source?.address;
  const norm = normaliseAddress(raw);
  return {
    service,
    request: {
      eventId: e.id,
      at: e.timestamp,
      dc: e.asset ?? "",
      ...(c.actor?.kind === "account" && c.actor.name ? { requester: c.actor.name } : {}),
      ...(raw ? { clientAddress: raw } : {}),
      ...(norm ? { clientAddressNormalised: norm } : {}),
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
  family: Family;
};

function readUse(e: ForensicEvent): UseReading | null {
  const c = e.canonical;
  const ev = c?.event;
  if (!c || !ev || c.actor?.kind !== "account" || !c.actor.name || !e.asset) return null;
  let kind: UseKind | null = null;
  let family: Family = "authentication";
  let detail: string | undefined;
  if (ev.category === "authentication" && ev.type === "logon") kind = "logon";
  else if (ev.category === "authentication" && ev.type === "explicit-credential-logon")
    kind = "explicit-credential-logon";
  else if (ev.category === "process" && ev.type === "start") {
    kind = "process-start";
    family = "process";
    detail = c.process?.executable ?? c.process?.name;
  } else if (ev.category === "service") {
    kind = "service-install";
    family = "service";
    detail = c.service?.name;
  } else if (ev.category === "network" && ev.type === "share-access") {
    kind = "share-access";
    family = "network";
  }
  if (!kind) return null;
  const { name, realm } = splitAccount(c.actor.name);
  const r = realm ?? c.actor.domain;
  return {
    eventId: e.id,
    at: e.timestamp,
    host: e.asset,
    kind,
    family,
    account: c.actor.name,
    short: name,
    ...(r ? { realm: r } : {}),
    ...(c.account?.id ? { sid: c.account.id } : {}),
    ...(c.subject?.kind === "account" && c.subject.name ? { initiator: c.subject.name } : {}),
    ...(c.authentication?.logonType !== undefined ? { logonType: c.authentication.logonType } : {}),
    ...(c.network?.source?.address ? { sourceAddress: c.network.source.address } : {}),
    ...(detail ? { detail } : {}),
    failed: ev.outcome === "failed",
  };
}

const familyOf = (e: ForensicEvent): Family | null => {
  const cat = e.canonical?.event?.category;
  return cat === "authentication" || cat === "process" || cat === "service" || cat === "network" ? cat : null;
};

function isToolRow(e: ForensicEvent): boolean {
  const ev = e.canonical?.event;
  return (
    (e.mitreTechniques ?? []).includes(ROAST_TECHNIQUE) &&
    !(ev?.category === "authentication" && ev.type === "ticket-request")
  );
}

interface Bucket {
  key: string;
  service: string;
  realm?: string;
  requests: TicketRequest[];
  total: number;
  unread: number;
  uses: UseReading[];
  usesUnread: number;
  usesUndated: number;
}

interface ToolRow {
  id: string;
  host: string;
  at: string;
  account?: string;
  detail?: string;
}

/** One bounded pass: ticket buckets keyed (realm, name), the per-(host, family) floor, tool rows. */
function index(events: readonly ForensicEvent[]): {
  buckets: Map<string, Bucket>;
  excluded: Partial<Record<ExclusionReason, number>>;
  undated: number;
  floor: Map<string, number>;
  tools: ToolRow[];
} {
  const buckets = new Map<string, Bucket>();
  const excluded: Partial<Record<ExclusionReason, number>> = {};
  const floor = new Map<string, number>();
  const tools: ToolRow[] = [];
  let undated = 0;
  for (const e of events) {
    const t = ms(e.timestamp);
    const fam = familyOf(e);
    if (t !== null && e.asset && fam) {
      const k = `${hostKey(e.asset)}|${fam}`;
      const cur = floor.get(k);
      if (cur === undefined || t < cur) floor.set(k, t);
    }
    if (isToolRow(e))
      tools.push({
        id: e.id,
        host: e.asset ?? "",
        at: e.timestamp,
        ...(e.canonical?.actor?.kind === "account" && e.canonical.actor.name
          ? { account: e.canonical.actor.name }
          : {}),
        ...((e.canonical?.process?.executable ?? e.canonical?.process?.name)
          ? { detail: e.canonical.process.executable ?? e.canonical.process.name }
          : {}),
      });
    const tk = readTicket(e);
    if (!tk) continue;
    const why = exclusionOf(tk.service);
    if (why) {
      excluded[why] = (excluded[why] ?? 0) + 1;
      continue;
    }
    if (t === null) {
      undated += 1;
      continue;
    }
    const realm = realmOfDc(e.asset);
    const key = `${(realm ?? "").toLowerCase()}|${tk.service.toLowerCase()}`;
    const b =
      buckets.get(key) ??
      buckets
        .set(key, {
          key,
          service: tk.service,
          ...(realm ? { realm } : {}),
          requests: [],
          total: 0,
          unread: 0,
          uses: [],
          usesUnread: 0,
          usesUndated: 0,
        })
        .get(key)!;
    b.total += 1;
    if (b.requests.length >= TICKET_ROWS_PER_ACCOUNT_MAX) b.unread += 1;
    else b.requests.push(tk.request);
  }
  return { buckets, excluded, undated, floor, tools };
}

/** Second pass over the uses, after the accounts to analyse are fixed: identity first, quota after. */
function attachUses(events: readonly ForensicEvent[], byName: ReadonlyMap<string, Bucket[]>): void {
  for (const e of events) {
    const u = readUse(e);
    if (!u) continue;
    const list = byName.get(u.short.toLowerCase());
    if (!list) continue;
    for (const b of list) {
      // A realm on both sides that does not match is another account — no charge, no candidate.
      if (b.realm && u.realm && !realmCompatible(b.realm, u.realm)) continue;
      if (b.uses.length >= USE_ROWS_PER_ACCOUNT_MAX) {
        b.usesUnread += 1;
        continue;
      }
      if (ms(u.at) === null) {
        b.usesUndated += 1;
        continue;
      }
      b.uses.push(u);
    }
  }
}

function chainFor(
  b: Bucket,
  listedBecause: ServiceAccountChain["listedBecause"],
  floor: ReadonlyMap<string, number>,
  tools: readonly ToolRow[],
): ServiceAccountChain {
  const issuedRc4 = b.requests.filter((r) => r.rc4 && r.outcome === "success");
  const t0Ms = issuedRc4.length ? Math.min(...issuedRc4.map((r) => ms(r.at)!)) : null;
  const t0Anchors = t0Ms !== null && b.unread === 0;
  const read = {
    ticketRows: b.requests.length,
    ticketRowsUnread: b.unread,
    useRows: b.uses.length,
    useRowsUnread: b.usesUnread,
    undated: b.usesUndated,
  };
  const requestAddresses = new Map<string, TicketRequest>();
  for (const r of b.requests)
    if (r.clientAddressNormalised && !requestAddresses.has(r.clientAddressNormalised))
      requestAddresses.set(r.clientAddressNormalised, r);
  const uses: AccountUse[] = [];
  const candidates: AccountUse[] = [];
  const before = new Map<string, { host: string; count: number; first: string; last: string }>();
  const sids = new Set<string>();
  let failedLogonsAfter = 0;
  const hostsWithoutBaseline = new Set<string>();
  // Pass 1: the baseline — where the account acted before T0 (matched identity only).
  for (const u of b.uses) {
    if (!t0Anchors || u.failed || !realmCompatible(b.realm, u.realm)) continue;
    if (ms(u.at)! >= t0Ms) continue;
    const k = hostKey(u.host);
    const cur = before.get(k);
    if (!cur) before.set(k, { host: u.host, count: 1, first: u.at, last: u.at });
    else {
      cur.count += 1;
      if (u.at < cur.first) cur.first = u.at;
      if (u.at > cur.last) cur.last = u.at;
    }
  }
  // Pass 2: every use, placed. Equality with T0 orders nothing.
  for (const u of b.uses) {
    const matched = realmCompatible(b.realm, u.realm);
    const t = ms(u.at)!;
    const placement: AccountUse["placement"] = !t0Anchors
      ? "undetermined"
      : t < t0Ms
        ? "before"
        : t === t0Ms
          ? "contemporaneous"
          : "after";
    if (matched && u.sid) sids.add(u.sid);
    if (u.failed) {
      if (matched && placement === "after") failedLogonsAfter += 1;
      continue;
    }
    if (placement === "before") continue;
    const k = hostKey(u.host);
    const hostFloor = floor.get(`${k}|${u.family}`);
    const hostBaseline: AccountUse["hostBaseline"] =
      t0Anchors && hostFloor !== undefined && hostFloor < t0Ms ? "available" : "unavailable";
    if (matched && placement === "after" && hostBaseline === "unavailable") hostsWithoutBaseline.add(u.host);
    const firstSeenHost = matched && placement === "after" && hostBaseline === "available" && !before.has(k);
    const norm = normaliseAddress(u.sourceAddress);
    const sameReq = norm ? requestAddresses.get(norm) : undefined;
    const { realm: _r, short: _s, failed: _f, family: _fam, ...rest } = u;
    const use: AccountUse = {
      ...rest,
      realmState: matched ? "matched" : "not-established",
      placement,
      firstSeenHost,
      hostBaseline,
      ...(sameReq && matched && norm
        ? {
            sameObservedAddress: {
              requestEventId: sameReq.eventId,
              requestObserver: sameReq.dc,
              requestAddress: sameReq.clientAddress!,
              useAddress: u.sourceAddress!,
              normalised: norm,
            },
          }
        : {}),
    };
    (matched ? uses : candidates).push(use);
  }
  const conflict =
    sids.size > 1
      ? `${sids.size} distinct SIDs act under this name (${[...sids].join(", ")}) — the ticket's owner is indeterminate; no stage past ticket-requested`
      : undefined;
  const after = conflict ? [] : uses.filter((u) => u.placement === "after");
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
  if (conflict) stageReason = `${conflict}${incomplete}`;
  else if (firstSeen.length) {
    stage = "first-seen-host-use";
    stageReason = `${firstSeen.length} use(s) on a host the account was not seen on before the request, in the available evidence${incomplete}`;
  } else if (after.length) {
    stage = "account-used-after";
    stageReason = hostsWithoutBaseline.size
      ? `${after.length} use(s) after the request; baseline unavailable for ${[...hostsWithoutBaseline].join(", ")} (no rows of that kind on the host before the request)${incomplete}`
      : `every use after the request is on a host the account was seen on before it${incomplete}`;
  } else if (listedBecause === "rc4-refused-only") stageReason = `${REFUSED_WORDS}${incomplete}`;
  else if (!b.realm)
    stageReason = `realm not established for this account (the DC row carries no domain) — ${candidates.length} candidate use(s) listed, none joined${incomplete}`;
  else if (!t0Anchors)
    stageReason =
      t0Ms === null
        ? `no RC4 request anchors a before / after split; ${candidates.length + uses.length} use(s) listed as undetermined${incomplete}`
        : `the ticket read is incomplete, so no request anchors a before / after split${incomplete}`;
  else stageReason = `no row after the request shows this account acting${incomplete}`;
  const requesterKeys = new Set(b.requests.map((r) => (r.requester ?? "").toLowerCase()).filter(Boolean));
  const toolIds = tools
    .filter((t) => t.account && requesterKeys.has(t.account.toLowerCase()))
    .map((t) => t.id);
  const hostsBefore = [...before.values()].sort((x, y) => x.host.localeCompare(y.host));
  return {
    service: b.service,
    ...(b.realm ? { realm: b.realm } : {}),
    realmSource: b.realm ? "dc-fqdn" : "not-established",
    listedBecause,
    requests: b.requests.slice(0, NAMED_MAX),
    requestsTotal: b.total,
    rc4Count: issuedRc4.length,
    aesCount: b.requests.filter((r) => !r.rc4).length,
    refusedCount: b.requests.filter((r) => r.outcome === "failed").length,
    rc4Words: issuedRc4.length ? RC4_WORDS : REFUSED_WORDS,
    acquisition: issuedRc4.length ? ACQUISITION_WORDS : REFUSED_WORDS,
    ...(t0Ms !== null ? { t0: new Date(t0Ms).toISOString() } : {}),
    t0Anchors,
    baseline: {
      hostsBefore: hostsBefore.slice(0, NAMED_MAX),
      hostsBeforeTotal: hostsBefore.length,
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
    hostsWithoutBaseline: [...hostsWithoutBaseline].sort().slice(0, NAMED_MAX),
    sameObservedAddressCount: uses.filter((u) => u.sameObservedAddress).length,
    sids: [...sids].sort(),
    ...(conflict ? { identityConflict: conflict } : {}),
    toolEvidence: toolIds.slice(0, NAMED_MAX),
    toolEvidenceTotal: toolIds.length,
    stage,
    stageReason,
    evidence,
    read,
  };
}

function listing(b: Bucket, rc4Requesters: ReadonlySet<string>): ServiceAccountChain["listedBecause"] | null {
  if (b.requests.some((r) => r.rc4 && r.outcome === "success")) return "rc4-request";
  if (b.requests.some((r) => r.rc4)) return "rc4-refused-only";
  if (b.requests.some((r) => r.requester && rc4Requesters.has(r.requester.toLowerCase())))
    return "aes-request-by-an-rc4-requester";
  return null;
}

/** The reading over the forensic timeline. Pure; no AI; nothing fetched. */
export function kerberoastChain(
  state: InvestigationState,
  now: string = new Date().toISOString(),
): KerberoastChain {
  const events = state.forensicTimeline;
  const { buckets, excluded, undated, floor, tools } = index(events);
  const rc4Requesters = new Set<string>();
  for (const b of buckets.values())
    for (const r of b.requests)
      if (r.rc4 && r.outcome === "success" && r.requester) rc4Requesters.add(r.requester.toLowerCase());
  const listed: { b: Bucket; why: ServiceAccountChain["listedBecause"] }[] = [];
  for (const b of buckets.values()) {
    const why = listing(b, rc4Requesters);
    if (why) listed.push({ b, why });
    else excluded["AES only"] = (excluded["AES only"] ?? 0) + 1;
  }
  // The accounts analysed are fixed BEFORE the use pass, so the work is bounded by the cap.
  const analysed = listed.slice(0, ACCOUNTS_MAX);
  const byName = new Map<string, Bucket[]>();
  for (const { b } of analysed) {
    const k = b.service.toLowerCase();
    byName.set(k, [...(byName.get(k) ?? []), b]);
  }
  attachUses(events, byName);
  const accounts = analysed.map(({ b, why }) => chainFor(b, why, floor, tools));
  const rank: Record<Stage, number> = {
    "first-seen-host-use": 0,
    "account-used-after": 1,
    "ticket-requested": 2,
  };
  accounts.sort(
    (a, b) =>
      rank[a.stage] - rank[b.stage] ||
      Number(a.listedBecause !== "rc4-request") - Number(b.listedBecause !== "rc4-request") ||
      a.service.localeCompare(b.service) ||
      (a.realm ?? "").localeCompare(b.realm ?? ""),
  );
  const attached = new Set(accounts.flatMap((a) => a.toolEvidence));
  const unattached = tools.filter((t) => !attached.has(t.id));
  const toolLeads: ToolLead[] = unattached.slice(0, NAMED_MAX).map((t) => ({
    eventId: t.id,
    host: t.host,
    ...(t.account ? { account: t.account } : {}),
    at: t.at,
    ...(t.detail ? { detail: t.detail } : {}),
  }));
  const gaps: string[] = [];
  if (!buckets.size && tools.length)
    gaps.push(
      "no ticket-request rows (4769) in the case — the account → use join cannot start; the tool rows are leads",
    );
  if (undated) gaps.push(`${undated} undated ticket row(s) not placed`);
  if (listed.length > ACCOUNTS_MAX)
    gaps.push(`${listed.length - ACCOUNTS_MAX} further service account(s) past the bound, not analysed`);
  return {
    accounts,
    accountsNotShown: Math.max(0, listed.length - ACCOUNTS_MAX),
    excluded,
    toolLeads,
    toolLeadsTotal: unattached.length,
    gaps,
    generated: now,
  };
}
