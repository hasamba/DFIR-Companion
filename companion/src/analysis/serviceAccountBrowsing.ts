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

/** Has this pass already annotated this description? Anchored, so imported text cannot fake it. */
export function alreadyMarked(description: string): boolean {
  // The pass's OWN wording, not just the marker — see the same guard in containerEscape.ts.
  return /\[noninteractive account browsing: (?:[^\s\]]+ browsed|\d+ of \d+|All \d+|This case holds)[\s\S]{0,1200}?\]\s*$/.test(
    description ?? "",
  );
}

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
 * The account a share-access record names.
 *
 * Windows writes 5140/5145 with `Account Name:` and a `Subject:` block, and the SIEM importers
 * carry those through; `by DOMAIN\user` is the other shape the importers write. Both are read.
 *
 * This exists because requiring the Shellbags mapper's `[user: …]` tag made the entire share half
 * of this item unreachable — no importer could ever produce a share record with an account, so the
 * share path regex and everything built on it was dead code behind a test that added the tag by
 * hand.
 */
export function shareAccount(description: string): string {
  const d = description ?? "";
  const named = /\bAccount\s*Name\s*[:=]\s*([A-Za-z0-9._$-]+(?:\\[A-Za-z0-9._$-]+)?)/i.exec(d)?.[1];
  if (named && named !== "-") return named;
  const by = /\bby\s+([A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+|[A-Za-z0-9._-]+\$)/i.exec(d)?.[1];
  return by ?? "";
}

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
  // A share record carries its account in the EVENT LOG's own wording, not in a `[user: …]` tag —
  // only the Shellbags mapper writes that tag. Requiring it made the entire share half of this
  // item unreachable: no importer could ever produce a share record with an account, so SHARE_RE
  // and everything built on it was dead code behind a test that added the tag by hand.
  const account = attributionMissing ? "" : tagged || (isShare ? shareAccount(description) : "");

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

/**
 * Does this text name this account, as an ACCOUNT?
 *
 * A substring test was catastrophic here. The bare name of NT AUTHORITY\\SYSTEM is "system", which
 * is inside System32, systemd and filesystem — so `C:\\Windows\\System32\\winlogon.exe` in Alice's
 * logon and `C:\\Windows\\System32\\tar.exe` in an unrelated archive both "matched", and the pass
 * raised a machine account's browsing to High while asserting in the report that those two events
 * were by the same account. That is the false accusation this module's own header forbids.
 */
export function namesAccount(text: string, account: string): boolean {
  const bare = norm(accountName(account));
  if (!bare) return false;
  const escaped = bare.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // AN ACCOUNT-INTRODUCING CONTEXT IS REQUIRED, not merely a word boundary.
  //
  // A word boundary was not enough, because `DOMAIN\account` and `Folder\name` are the same shape:
  // "C:\Program Files\Admin Tools\x.exe" matched the account `admin`, and "C:\Users\test\Desktop"
  // matched `test`. Nothing in the surrounding characters separates the two — both are preceded by
  // a space — so the fix cannot come from the boundary. It comes from HOW the importers write an
  // account: after "for", "by", "as", "user", or an "Account Name:" field, or at the very start.
  //
  // The cost is a false negative when an event names the account only inside a path. That is the
  // right way to be wrong here: this function decides whether to raise a finding to High while
  // asserting two events share an account, and a wrong yes accuses a person.
  const intro =
    "(?:^|\\baccount(?:\\s*name)?\\s*[:=]\\s*|\\b(?:for|by|as|user|username|owner|caller|principal)\\s+)";
  // THE DOMAIN MUST AGREE WHEN BOTH SIDES CARRY ONE. `CORP\\svc` and `OTHER\\svc` are different
  // principals — the same service name in two domains is two accounts, and treating them as one
  // would corroborate a finding with an unrelated domain's activity.
  //
  // A bare mention with no domain still matches: the importers frequently write the account without
  // one, and refusing those would lose most real corroboration.
  const accountDomain = norm(account).includes("\\") ? norm(account).split("\\")[0] : "";
  const domain = accountDomain
    ? `(?:${accountDomain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\\\)?`
    : // The prefix may carry a space — Windows writes `NT AUTHORITY\SYSTEM`.
      "(?:[\\w.-]+(?:\\s+[\\w.-]+){0,2}\\\\)?";
  return new RegExp(`${intro}${domain}${escaped}(?![\\w$.-])`, "i").test(text ?? "");
}

/** How many events one corroboration pass will read. */
export const MAX_CORROBORATION_EVENTS = 20_000;

/**
 * Find a logon and a collection action near each browsing record, in ONE pass.
 *
 * The first version scanned every event for every record — O(records × events) with a Date.parse
 * per pair, inside the state lock. Measured: 500 shellbags in a 2,000-event timeline took 1.4
 * seconds, 4,000 in 16,000 took 85, and it is a clean 4× per doubling. A single Shellbags.csv from
 * a file server reaches tens of thousands of rows, which is hours on every merge with no progress
 * and no cancel. Now the candidate events are collected once, and each record checks that short
 * list.
 */
export function corroborateAll(
  records: readonly BrowsingRecord[],
  events: readonly ForensicEvent[],
  windowMs = DEFAULT_WINDOW_MS,
): Map<string, Corroboration> {
  const out = new Map<string, Corroboration>();
  if (records.length === 0) return out;

  // One pass over the timeline, keeping only what could ever corroborate anything.
  const candidates: { time: number; text: string; id: string; logon: boolean; collection: boolean }[] = [];
  let seen = 0;
  for (const e of events) {
    if (seen >= MAX_CORROBORATION_EVENTS) break;
    seen++;
    const d = e.description ?? "";
    const logon = INTERACTIVE_LOGON_RE.test(d);
    const collection = COLLECTION_RE.test(d);
    if (!logon && !collection) continue;
    const t = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(t)) continue;
    candidates.push({ time: t, text: d, id: e.id, logon, collection });
  }
  candidates.sort((a, b) => a.time - b.time);

  for (const record of records) {
    let logonId: string | null = null;
    let collectionId: string | null = null;
    if (record.account) {
      for (const c of candidates) {
        if (Math.abs(c.time - record.time) > windowMs) continue;
        if (!namesAccount(c.text, record.account)) continue;
        if (!logonId && c.logon) logonId = c.id;
        if (!collectionId && c.collection) collectionId = c.id;
        if (logonId && collectionId) break;
      }
    }
    out.set(record.id, { logonId, collectionId });
  }
  return out;
}

/** Single-record convenience, for callers holding one record. */
export function corroborate(
  record: BrowsingRecord,
  events: readonly ForensicEvent[],
  windowMs = DEFAULT_WINDOW_MS,
): Corroboration {
  return corroborateAll([record], events, windowMs).get(record.id) ?? { logonId: null, collectionId: null };
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

  // A NAMING CONVENTION CANNOT REACH HIGH. It is a hint about a label, not a property of the
  // account, and the corroboration below would otherwise promote a guess to a High-severity
  // assertion about a person who may simply have a service-shaped username.
  const ceiling: Severity = weak ? "Medium" : "Critical";
  const raise = (to: Severity) => {
    if (RANK[to] > RANK[severity] && RANK[to] <= RANK[ceiling]) severity = to;
  };

  if (corroboration.logonId) {
    parts.push(
      `An interactive logon by the same account sits nearby (${corroboration.logonId}), which is how a desktop session under a service identity is established.`,
    );
    raise("High");
  }
  if (corroboration.collectionId) {
    parts.push(
      `Archiving or copying activity by the same account sits nearby (${corroboration.collectionId}). That is a SEPARATE artifact from the browsing — read together they suggest collection, but neither alone establishes it.`,
    );
    raise("High");
  }

  if (weak && (corroboration.logonId || corroboration.collectionId)) {
    parts.push(
      "This account was classified from a NAMING CONVENTION rather than from a property of the account, so the corroboration above does not raise it further — confirm the account is not a person's.",
    );
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
  // The records worth corroborating are collected first, so the corroboration pass runs once over
  // the timeline rather than once per record.
  const records: BrowsingRecord[] = [];
  for (const e of events) {
    if (alreadyMarked(e.description ?? "")) continue;
    const record = readBrowsing(e);
    if (record?.account && classifyAccount(record.account, ctx).noninteractive) records.push(record);
  }
  if (records.length === 0) return events as ForensicEvent[];
  const corroborations = corroborateAll(records, events, windowMs);

  let changed = false;
  const out = events.map((e) => {
    if (alreadyMarked(e.description ?? "")) return e;
    const record = readBrowsing(e);
    if (!record || !record.account) return e;
    const classification = classifyAccount(record.account, ctx);
    if (!classification.noninteractive) return e;
    const verdict = gradeBrowsing(
      record,
      classification,
      corroborations.get(record.id) ?? { logonId: null, collectionId: null },
    );
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

/** The id of the attribution-coverage event, so a re-merge replaces it. */
export const ATTRIBUTION_COVERAGE_ID = "shellbag-attribution-coverage";

/**
 * One event saying how much browsing evidence could not be attributed, when some of it could not.
 *
 * attributionNote was an exported string builder no analyst ever saw. "No service-account browsing
 * found" is the wrong answer when the records carry no account, and the only way to say so is to
 * put it on the timeline.
 */
export function attributionCoverageEvent(events: readonly ForensicEvent[]): ForensicEvent | null {
  let missing = 0;
  let firstTime = "";
  for (const e of events) {
    if (e.id === ATTRIBUTION_COVERAGE_ID) continue;
    const r = readBrowsing(e);
    if (!r) continue;
    if (!firstTime) firstTime = e.timestamp ?? "";
    if (!r.account) missing++;
  }
  if (missing === 0) return null;
  return {
    id: ATTRIBUTION_COVERAGE_ID,
    timestamp: firstTime || new Date().toISOString(),
    description: `Browsing evidence without an account ${SERVICE_BROWSING_MARKER} ${attributionNote(events)}]`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Coverage"],
  };
}
