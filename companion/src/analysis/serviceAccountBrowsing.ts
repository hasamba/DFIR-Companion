// Interactive activity by accounts that are not supposed to be interactive (#908 item 10).
//
// A service account does not browse folders. It has no desktop, no Explorer window and no reason to
// look at anything — it runs one program against one set of paths and it does that forever. So when
// a shellbag or a network-share record is attributed to one, something used that account's identity
// at a keyboard, and that is worth an analyst's time even though every individual record is
// ordinary.
//
// ─────────────────────────── "EXPLICITLY IDENTIFIED AS NONINTERACTIVE" ───────────────────────────
//
// The issue's wording is exact, and it rules out the tempting shortcut. `svc_backup` is PROBABLY a
// service account; `svcHelpdesk` is probably a person. Guessing from a name prefix would produce
// findings against real people doing their jobs, and a finding that accuses a named human of
// unauthorised browsing is not a small mistake.
//
// So an account is noninteractive here only when something SAYS SO:
//
//   • a well-known service SID — LocalSystem, LocalService, NetworkService, IUSR
//   • a name ending in `$`, which is a machine account or a group-managed service account and
//     cannot log on interactively at all
//   • the analyst named it
//
// A naming convention is available as a SEPARATE, weaker signal that the caller opts into, and even
// then the finding says the classification came from the name.
//
// ─────────────────────────── BROWSING IS NOT COPYING ───────────────────────────
//
// A shellbag proves a folder was opened in Explorer. It does not prove a single byte was read out
// of it, and it never proves anything left the host. The two get conflated constantly, and a report
// that says "the service account exfiltrated the finance share" on shellbag evidence alone is
// wrong. Every finding here says what the artifact does and does not establish.
//
// ─────────────────────────── WHAT THE TIMESTAMP MEANS ───────────────────────────
//
// A shellbag's LastInteracted is the last write to a registry key. It bounds the LAST time the
// folder was viewed. It says nothing about how many times, and nothing about the first — an earlier
// visit leaves no separate trace, so a single timestamp can stand for months of activity. That
// limitation is stated on the finding rather than left for the reader to know.

import type { ForensicEvent, Severity } from "./stateTypes.js";

/** The marker this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const SERVICE_BROWSING_MARKER = "[noninteractive account browsing:";

/** How close a corroborating logon or collection event must be. */
export const DEFAULT_WINDOW_MS = 4 * 60 * 60 * 1000;

/** Well-known SIDs that cannot belong to a person. */
export const SERVICE_SIDS: readonly string[] = [
  "S-1-5-18", // LocalSystem
  "S-1-5-19", // LocalService
  "S-1-5-20", // NetworkService
  "S-1-5-17", // IUSR
  "S-1-5-90", // Window Manager
  "S-1-5-96", // Font Driver Host
];

/** The friendly names Windows shows for those SIDs. */
const SERVICE_NAMES = new Set([
  "system",
  "local system",
  "nt authority\\system",
  "local service",
  "nt authority\\local service",
  "network service",
  "nt authority\\network service",
  "iusr",
  "nt authority\\iusr",
  "anonymous logon",
  "defaultaccount",
  "wdagutilityaccount",
]);

/** Naming conventions. A HINT, never proof — see the header. */
const CONVENTION_RE = /^(?:svc[_.-]|service[_.-]|sa[_.-]|app[_.-]|_svc)|[_.-]svc$/i;

export type NoninteractiveReason = "well-known-sid" | "machine-account" | "analyst" | "naming-convention";

export interface AccountClassification {
  noninteractive: boolean;
  reason: NoninteractiveReason | null;
  /** Words for the finding, so the reader knows how the classification was reached. */
  basis: string;
}

export interface BrowsingContext {
  /** Accounts the analyst has marked as noninteractive. Names or SIDs, matched case-insensitively. */
  noninteractiveAccounts?: readonly string[];
  /** Accounts the analyst has confirmed ARE interactive, which overrides everything else. */
  interactiveAccounts?: readonly string[];
  /** Opt in to the naming convention as a weaker signal. Off by default. */
  useNamingConvention?: boolean;
}

const norm = (s: string): string => (s ?? "").trim().toLowerCase();

/** Strip a domain prefix, keeping the account itself. */
export function accountName(account: string): string {
  const a = (account ?? "").trim();
  const slash = a.lastIndexOf("\\");
  return slash >= 0 ? a.slice(slash + 1) : a;
}

/**
 * Is this account noninteractive, and on what basis?
 *
 * An analyst statement wins over everything, in both directions.
 */
export function classifyAccount(account: string, ctx: BrowsingContext = {}): AccountClassification {
  const raw = norm(account);
  const bare = norm(accountName(account));
  if (!raw) return { noninteractive: false, reason: null, basis: "" };

  if ((ctx.interactiveAccounts ?? []).some((a) => norm(a) === raw || norm(a) === bare)) {
    return {
      noninteractive: false,
      reason: null,
      basis: "the analyst has confirmed this account is interactive",
    };
  }
  if ((ctx.noninteractiveAccounts ?? []).some((a) => norm(a) === raw || norm(a) === bare)) {
    return {
      noninteractive: true,
      reason: "analyst",
      basis: "the analyst identified this account as noninteractive",
    };
  }
  if (SERVICE_SIDS.some((sid) => raw === norm(sid)) || SERVICE_NAMES.has(raw) || SERVICE_NAMES.has(bare)) {
    return {
      noninteractive: true,
      reason: "well-known-sid",
      basis: "it is a built-in service identity, which has no desktop and cannot browse",
    };
  }
  if (bare.endsWith("$")) {
    return {
      noninteractive: true,
      reason: "machine-account",
      basis:
        "the name ends in $, which makes it a computer or group-managed service account — neither can log on interactively",
    };
  }
  if (ctx.useNamingConvention && CONVENTION_RE.test(bare)) {
    return {
      noninteractive: true,
      reason: "naming-convention",
      basis: `it matches this environment's service-account naming convention — that is a naming convention, not a property of the account, so confirm "${accountName(account)}" is not a person`,
    };
  }
  return { noninteractive: false, reason: null, basis: "" };
}

// ─────────────────────────── reading the artifacts ───────────────────────────

/** The account a Shellbag event was attributed to by the importer. */
const SHELLBAG_USER_RE = /\[user:\s*([^\]]+?)\s*\]/i;

/**
 * A share path in a description.
 *
 * The share segment deliberately excludes spaces. Allowing them let the match run past the end of
 * the path and swallow the prose that followed it — "\\\\FS-01\\Finance by CORP\\svc" came back as a
 * share named "Finance by CORP". A share whose name contains a space is therefore truncated at the
 * space, which understates the target; over-capturing put a username inside a path, which is worse.
 */
const SHARE_RE = /\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+(?:\\[A-Za-z0-9$._-]+)*/;

export type BrowsingKind = "shellbag" | "share";

export interface BrowsingRecord {
  id: string;
  time: number;
  account: string;
  kind: BrowsingKind;
  /** What was browsed. */
  target: string;
  /** true when the importer said the account was not recorded, rather than not finding one. */
  attributionMissing: boolean;
}

/** Read a browsing record out of a timeline event, or null. */
export function readBrowsing(e: ForensicEvent): BrowsingRecord | null {
  const sources = (e.sources ?? []).map(norm);
  const description = e.description ?? "";
  const time = Date.parse(e.timestamp ?? "");

  const isShellbag = sources.includes("shellbags") || /^shellbag:/i.test(description);
  const share = SHARE_RE.exec(description);
  const isShare =
    !isShellbag && !!share && /\b(?:share|mapped|net use|net view|type 3|smb)\b/i.test(description);
  if (!isShellbag && !isShare) return null;
  if (!Number.isFinite(time)) return null;

  const tagged = SHELLBAG_USER_RE.exec(description)?.[1] ?? "";
  const attributionMissing = /not recorded by this collection/i.test(tagged);
  const account = attributionMissing ? "" : tagged;

  return {
    id: e.id,
    time,
    account,
    kind: isShellbag ? "shellbag" : "share",
    target: (isShellbag ? (e.path ?? description.replace(/^Shellbag:\s*/i, "")) : (share?.[0] ?? "")).slice(
      0,
      400,
    ),
    attributionMissing,
  };
}

// ─────────────────────────── corroboration ───────────────────────────

/** A logon that put this identity on a desktop, which is what makes the browsing possible. */
const INTERACTIVE_LOGON_RE =
  /\blogon\b[^\n]*\btype\s*(?:=|:)?\s*(2|10|11|7)\b|\b(?:interactive|remoteinteractive|rdp)\s+logon\b/i;

/** Activity that would turn browsing into collection. */
const COLLECTION_RE =
  /\b(?:copy-item|xcopy|robocopy|7z|rar\b|winrar|zip\b|compress-archive|tar\b|esentutl|copied to|staged)\b/i;

export interface Corroboration {
  logonId: string | null;
  collectionId: string | null;
}

/** Find a logon and a collection action by the same account near the browsing. */
export function corroborate(
  record: BrowsingRecord,
  events: readonly ForensicEvent[],
  windowMs = DEFAULT_WINDOW_MS,
): Corroboration {
  const account = norm(accountName(record.account));
  let logonId: string | null = null;
  let collectionId: string | null = null;
  if (!account) return { logonId, collectionId };

  for (const e of events) {
    const t = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(t) || Math.abs(t - record.time) > windowMs) continue;
    const d = e.description ?? "";
    if (!norm(d).includes(account)) continue;
    if (!logonId && INTERACTIVE_LOGON_RE.test(d)) logonId = e.id;
    if (!collectionId && COLLECTION_RE.test(d)) collectionId = e.id;
    if (logonId && collectionId) break;
  }
  return { logonId, collectionId };
}

// ─────────────────────────── grading ───────────────────────────

const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const DESCRIPTION_MAX = 600;

const WHAT_IT_SHOWS: Record<BrowsingKind, string> = {
  shellbag:
    "A shellbag records that a folder was opened in Explorer under this account. It does NOT record that any file was read, copied or sent anywhere — browsing and collection are different findings and this artifact only supports the first.",
  share:
    "This records that the share was reached under this account. It does NOT record which files were read or whether anything was copied off it.",
};

const TIME_LIMIT: Record<BrowsingKind, string> = {
  shellbag:
    "The timestamp is the last write to the shellbag's registry key, so it bounds the LAST time the folder was viewed. Earlier visits leave no separate trace, so one timestamp can stand for months of activity.",
  share:
    "The timestamp is when this record was written, which bounds the access rather than enumerating every one.",
};

export interface BrowsingVerdict {
  severity: Severity;
  reason: string;
}

export function gradeBrowsing(
  record: BrowsingRecord,
  classification: AccountClassification,
  corroboration: Corroboration = { logonId: null, collectionId: null },
): BrowsingVerdict | null {
  if (!classification.noninteractive) return null;

  // A naming-convention match is not enough on its own to raise. It is a hint about a label, not a
  // fact about the account, and a wrong one accuses a real person.
  const weak = classification.reason === "naming-convention";
  let severity: Severity = weak ? "Low" : "Medium";
  const parts: string[] = [
    `${record.account} browsed ${record.target}, and that account is noninteractive: ${classification.basis}.`,
  ];

  if (corroboration.logonId) {
    parts.push(
      `An interactive logon by the same account sits nearby (${corroboration.logonId}), which is how a desktop session under a service identity is established.`,
    );
    if (RANK[severity] < RANK.High) severity = "High";
  }
  if (corroboration.collectionId) {
    parts.push(
      `Archiving or copying activity by the same account sits nearby (${corroboration.collectionId}). That is a SEPARATE artifact from the browsing — read together they suggest collection, but neither alone establishes it.`,
    );
    if (RANK[severity] < RANK.High) severity = "High";
  }

  parts.push(WHAT_IT_SHOWS[record.kind]);
  parts.push(TIME_LIMIT[record.kind]);
  return { severity, reason: parts.join(" ") };
}

/**
 * Mark browsing by noninteractive accounts on the timeline.
 *
 * Only ever raises, and appends its marker once.
 */
export function markServiceAccountBrowsing(
  events: readonly ForensicEvent[],
  ctx: BrowsingContext = {},
  windowMs = DEFAULT_WINDOW_MS,
): ForensicEvent[] {
  let changed = false;
  const out = events.map((e) => {
    if ((e.description ?? "").includes(SERVICE_BROWSING_MARKER)) return e;
    const record = readBrowsing(e);
    if (!record || !record.account) return e;
    const classification = classifyAccount(record.account, ctx);
    if (!classification.noninteractive) return e;
    const verdict = gradeBrowsing(record, classification, corroborate(record, events, windowMs));
    if (!verdict) return e;
    changed = true;
    const severity: Severity = RANK[verdict.severity] > RANK[e.severity] ? verdict.severity : e.severity;
    return {
      ...e,
      severity,
      mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), "T1083", "T1078.003"])],
      description:
        `${(e.description ?? "").slice(0, DESCRIPTION_MAX)} ${SERVICE_BROWSING_MARKER} ${verdict.reason}]`.trim(),
    };
  });
  return changed ? out : (events as ForensicEvent[]);
}

/**
 * How much of the browsing evidence in this case can be attributed to an account at all.
 *
 * A shellbag with no recorded user cannot be judged, and reporting "no service-account browsing"
 * without saying how many records were unattributable would present a collection gap as a result.
 */
export function attributionNote(events: readonly ForensicEvent[]): string {
  let attributed = 0;
  let missing = 0;
  for (const e of events) {
    const r = readBrowsing(e);
    if (!r) continue;
    if (r.account) attributed++;
    else missing++;
  }
  if (attributed === 0 && missing === 0) return "This case holds no shellbag or share-access evidence.";
  if (missing === 0) return `All ${attributed} browsing record(s) carry an account.`;
  return `${missing} of ${attributed + missing} browsing record(s) carry no account, so who browsed those folders cannot be established from this collection. Re-collect the per-user hives with their filenames intact, or add a user column, to attribute them.`;
}
