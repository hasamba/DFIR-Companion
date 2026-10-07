import { SEVERITY_RANK, type ForensicEvent } from "../stateTypes.js";
import type { CommandSeat } from "./synthCommandSeats.js";

/**
 * Reserved synthesis-prompt seats for the accounts an attacker used (#2014).
 *
 * The prompt holds at most DFIR_AI_SYNTH_MAX_EVENTS rows. A Medium explicit-credential logon (EID 4648)
 * that names a SECOND account the attacker used is graded below the anchors and carries no command
 * line, so only the even-spread fill could seat it — and on a large case that fill reaches a small
 * share of the rows. The model then sees the account only as routine Low rows, or not at all. This
 * module picks one row per distinct account for a small reserved share of the SAME cap, following the
 * #1622 precedent (synthCommandSeats.ts).
 *
 * WHAT IS READ. Only the scoped forensic timeline the prompt is built from, before burst collapsing —
 * never the super-timeline (CLAUDE.md §7). No grading changes.
 *
 * A CANDIDATE is a row graded Low or Medium that is either a 4648 explicit-credential logon, or a
 * successful 4624 network (3) or new-credentials (9) logon, and that names a user account. Machine
 * accounts (name ends in "$") and built-in service accounts (SYSTEM, DWM-n, UMFD-n, ...) never qualify.
 * A 4624 candidate is dropped when a Critical/High row already names the same account: the anchors
 * show it. A 4648 candidate is never dropped that way, since the anchor may not say how the account
 * was used.
 *
 * ORDER. One seat per distinct account (the 4648 row wins, then Medium before Low, then earliest,
 * then id). Round-robin across hosts, so one busy host cannot use every seat.
 */

/** Hard ceiling on reserved account seats per prompt. */
export const ACCOUNT_SEAT_MAX = 10;
/** Share of the prompt cap reserved for account seats (before the ceiling). */
export const ACCOUNT_SEAT_FRACTION = 0.02;

/** Seats reserved for account logons at a prompt cap of `max`: at least 1, at most 10. */
export function accountSeatCap(max: number): number {
  if (!(max > 0)) return 0;
  return Math.min(ACCOUNT_SEAT_MAX, Math.max(1, Math.floor(max * ACCOUNT_SEAT_FRACTION)));
}

const EXPLICIT_CREDENTIAL = /\(EID 4648\)/;
const NETWORK_LOGON = /\(EID 4624\)/;
const SERVICE_ACCOUNT = /^(system|local service|network service|anonymous logon|dwm-\d+|umfd-\d+|iusr|-)$/i;
const SERVICE_DOMAIN = /^(nt authority|nt service|window manager|font driver host)$/i;

interface Account {
  /** Lowercased bare name. */
  key: string;
  /** Lowercased first label of the domain ("" when the row names none). */
  domain: string;
  display: string;
}

/** The first account the row names: the canonical account, else the first one in the description. */
function accountOf(e: ForensicEvent): Account | undefined {
  const raw =
    e.canonical?.account?.name?.trim() ||
    /\(EID \d{4}\) - ([^,]+?)(?:,| @ | - |$)/.exec(e.description)?.[1]?.trim() ||
    "";
  const slash = raw.lastIndexOf("\\");
  const at = slash < 0 ? raw.lastIndexOf("@") : -1;
  const name = (slash >= 0 ? raw.slice(slash + 1) : at > 0 ? raw.slice(0, at) : raw).trim();
  const fullDomain = (slash >= 0 ? raw.slice(0, slash) : at > 0 ? raw.slice(at + 1) : "").trim();
  if (!name || name.endsWith("$")) return undefined;
  if (SERVICE_ACCOUNT.test(name) || SERVICE_DOMAIN.test(fullDomain)) return undefined;
  const domain = fullDomain.split(".")[0].toLowerCase();
  return { key: name.toLowerCase(), domain, display: name };
}

/**
 * Same account: equal names AND (either domain empty, or equal first labels). CORP.EXAMPLE and
 * CORP are one domain, as in real 4648 rows ("CORP.EXAMPLE\\user, CORP\\user").
 */
function sameDomain(a: string, b: string): boolean {
  return a === "" || b === "" || a === b;
}

function logonTypeOf(e: ForensicEvent): number | undefined {
  const t = e.canonical?.authentication?.logonType;
  if (typeof t === "number") return t;
  const m = /LogonType=(\d+)/.exec(e.description);
  return m ? Number(m[1]) : undefined;
}

type Kind = 0 | 1; // 0 = explicit credentials (4648), 1 = network / new-credentials logon (4624)

function kindOf(e: ForensicEvent): Kind | undefined {
  if (EXPLICIT_CREDENTIAL.test(e.description)) return 0;
  if (NETWORK_LOGON.test(e.description)) {
    const type = logonTypeOf(e);
    return type === 3 || type === 9 ? 1 : undefined;
  }
  return undefined;
}

interface Candidate {
  e: ForensicEvent;
  host: string;
  key: string;
  domain: string;
  kind: Kind;
  sevRank: number;
  time: number;
}

export interface AccountSeatInput {
  /** The scoped forensic timeline, uncollapsed. */
  events: readonly ForensicEvent[];
  /** Canonical host for a raw asset spelling. */
  hostOf: (raw: string) => string;
}

function byPriority(a: Candidate, b: Candidate): number {
  return a.kind - b.kind || a.sevRank - b.sevRank || a.time - b.time || a.e.id.localeCompare(b.e.id);
}

/** One row per distinct user account for the reserved account seats, in seat order. Pure. */
export function accountLogonSeats(input: AccountSeatInput): CommandSeat[] {
  const anchorText = input.events
    .filter((e) => e.severity === "Critical" || e.severity === "High")
    .map((e) => e.description.toLowerCase())
    .join("\n");

  const candidates: Candidate[] = [];
  for (const e of input.events) {
    if (e.severity !== "Low" && e.severity !== "Medium") continue;
    const kind = kindOf(e);
    if (kind === undefined) continue;
    const account = accountOf(e);
    if (!account) continue;
    if (kind === 1 && anchorText.includes(account.key)) continue;
    const time = Date.parse(e.timestamp);
    candidates.push({
      e,
      host: input.hostOf(e.asset?.trim() ?? ""),
      key: account.key,
      domain: account.domain,
      kind,
      sevRank: SEVERITY_RANK[e.severity],
      time: Number.isFinite(time) ? time : Infinity,
    });
  }

  const seenDomains = new Map<string, string[]>();
  const perHost = new Map<string, Candidate[]>();
  for (const c of [...candidates].sort(byPriority)) {
    const domains = seenDomains.get(c.key) ?? [];
    if (domains.some((d) => sameDomain(d, c.domain))) continue;
    seenDomains.set(c.key, [...domains, c.domain]);
    const list = perHost.get(c.host) ?? [];
    list.push(c);
    perHost.set(c.host, list);
  }

  const queues = [...perHost.entries()]
    .sort(([hostA, a], [hostB, b]) => byPriority(a[0], b[0]) || hostA.localeCompare(hostB))
    .map(([, list]) => list);
  const out: CommandSeat[] = [];
  const longest = Math.max(0, ...queues.map((q) => q.length));
  for (let i = 0; i < longest; i++)
    for (const q of queues) if (i < q.length) out.push({ event: q[i].e, shadowedBy: [] });
  return out;
}
