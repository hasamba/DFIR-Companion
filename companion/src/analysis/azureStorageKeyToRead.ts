// The key→read correlation half of #931 item 4: a storage-account shared-key listing
// (`storageAccounts/listKeys/action`, control-plane, from cloudActivityImport.ts) joined to a
// LATER account-key-authenticated object read on the same account (data-plane, from
// azureStorageLogImport.ts). Lives here — not in either importer — because the two records come
// from two separate uploads (an Activity Log export and a Storage diagnostic-log export): only a
// post-merge pass ever sees both.
//
// What one joined row establishes, and what it never claims:
//   - "a storage key was listed for this account at T; N account-key-authenticated read(s)
//     happened on the same account within the window after T" — temporal coexistence only;
//   - NEVER "the same actor did both" — SAS tokens are client-constructed with no audit trail,
//     and a listing's returned key may sit unused for the rest of the export while a DIFFERENT,
//     already-held key drives the reads. The row says so.
//   - only a SUCCESSFUL listing counts (a denied/failed attempt never retrieved a key);
//   - a read joins the nearest PRECEDING successful listing only, never more than one — avoids
//     inflating a finding when two listings' windows overlap one read.

import { createHash } from "node:crypto";
import type { ForensicEvent } from "./stateTypes.js";

// A local, small bound — aggKey.ts's boundedAggKey/boundedTextTo live in analysis/ingest, and this
// module is analysis/timeline (the layer stateMerge.ts's cross-import correlators live in);
// importing an ingest-layer helper from timeline is an upward import the architecture forbids.
// Same idea, inlined: a value under the cap passes through untouched, an over-long one keeps a
// digest of the full value in its tail.
function boundedText(text: string, max: number): string {
  if (text.length <= max) return text;
  const digest = createHash("sha256").update(text).digest("hex").slice(0, 16);
  return `${text.slice(0, max - 17)}#${digest}`;
}

export const STORAGE_KEY_USE_WINDOW_HOURS_DEFAULT = 24;
export const STORAGE_KEY_JOINS_MAX = 128;

function envInt(name: string, fallback: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export function storageKeyUseWindowHours(): number {
  return envInt("DFIR_STORAGE_KEY_USE_WINDOW_HOURS", STORAGE_KEY_USE_WINDOW_HOURS_DEFAULT);
}

/** The bare storage-account name from either an ARM resourceId or the importer's own "acct/container/object" shape. */
function accountNameOf(resource: string): string {
  const arm = /storageaccounts\/([^/]+)/i.exec(resource ?? "");
  if (arm) return arm[1].toLowerCase();
  return (resource ?? "").split("/")[0]?.toLowerCase() ?? "";
}

function isSuccessfulKeyListing(e: ForensicEvent): boolean {
  return (
    e.canonical?.event.type === "storage-key-list" &&
    e.canonical.event.outcome === "success" &&
    !!e.canonical.cloud?.resource
  );
}

function isAccountKeyRead(e: ForensicEvent): boolean {
  return (
    e.canonical?.event.type === "storage-object-op" &&
    e.canonical.event.outcome === "success" &&
    e.canonical.authentication?.mechanism === "account-key" &&
    !!e.canonical.cloud?.resource
  );
}

function ms(timestamp: string): number | null {
  const t = Date.parse(timestamp ?? "");
  return Number.isFinite(t) ? t : null;
}

export function correlateStorageKeyToRead(events: readonly ForensicEvent[]): ForensicEvent[] {
  const windowMs = storageKeyUseWindowHours() * 3_600_000;

  const listingsByAccount = new Map<string, { time: number; event: ForensicEvent }[]>();
  const readsByAccount = new Map<string, { time: number; event: ForensicEvent }[]>();
  for (const e of events) {
    const t = ms(e.timestamp ?? "");
    if (t === null) continue;
    if (isSuccessfulKeyListing(e)) {
      const acct = accountNameOf(e.canonical!.cloud!.resource!);
      if (!acct) continue;
      (listingsByAccount.get(acct) ?? listingsByAccount.set(acct, []).get(acct)!).push({ time: t, event: e });
    } else if (isAccountKeyRead(e)) {
      const acct = accountNameOf(e.canonical!.cloud!.resource!);
      if (!acct) continue;
      (readsByAccount.get(acct) ?? readsByAccount.set(acct, []).get(acct)!).push({ time: t, event: e });
    }
  }
  if (listingsByAccount.size === 0) return events as ForensicEvent[];

  const joins: { account: string; listing: ForensicEvent; reads: ForensicEvent[] }[] = [];
  for (const [account, listings] of listingsByAccount) {
    const sortedListings = [...listings].sort((a, b) => a.time - b.time);
    const reads = (readsByAccount.get(account) ?? []).sort((a, b) => a.time - b.time);
    // Each read joins the nearest PRECEDING listing whose window covers it, and only that one.
    const perListing = new Map<number, ForensicEvent[]>();
    for (const r of reads) {
      let best = -1;
      for (let i = sortedListings.length - 1; i >= 0; i--) {
        const l = sortedListings[i];
        if (l.time < r.time && r.time - l.time <= windowMs) {
          best = i;
          break;
        }
        if (l.time < r.time) break; // strictly closer listings only get closer; stop scanning back
      }
      if (best >= 0) {
        const arr = perListing.get(best) ?? [];
        arr.push(r.event);
        perListing.set(best, arr);
      }
    }
    for (const [idx, matchedReads] of perListing) {
      if (matchedReads.length === 0) continue;
      joins.push({ account, listing: sortedListings[idx].event, reads: matchedReads });
    }
  }
  if (joins.length === 0) return events as ForensicEvent[];

  joins.sort((a, b) => (ms(a.listing.timestamp) ?? 0) - (ms(b.listing.timestamp) ?? 0));
  const kept = joins.slice(0, STORAGE_KEY_JOINS_MAX);
  const overflow = joins.length - kept.length;

  const rows: ForensicEvent[] = kept.map(({ account, listing, reads }) => {
    const windowHours = storageKeyUseWindowHours();
    // Codex review (P2): a matched READ ROW can itself be an aggregated group (count > 1 when
    // cloudBulkRead's own importer collapsed repeated identical requests) — summing `count ?? 1`
    // reports the real number of reads, not the number of distinct rows they aggregated into.
    const readCount = reads.reduce((n, r) => n + (r.count ?? 1), 0);
    const description = boundedText(
      `Storage key listed for ${account} at ${listing.timestamp}; ${readCount} account-key-authenticated ` +
        `read(s) occurred on the same account within ${windowHours}h after — temporal coexistence only, ` +
        `never proof the same actor used the listed key`,
      600,
    );
    const id = boundedText(`storage-key-to-read|${account}|${listing.timestamp}`, 400);
    return {
      id,
      timestamp: listing.timestamp,
      description,
      severity: "Medium",
      mitreTechniques: ["T1552.001"],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Azure Storage Logs"],
      count: readCount,
    };
  });
  if (overflow > 0) {
    rows.push({
      id: "storage-key-to-read-omitted",
      timestamp: "",
      description: `${overflow} further storage key→read join(s) beyond the ${STORAGE_KEY_JOINS_MAX} reported — not shown`,
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Azure Storage Logs"],
    });
  }

  const replacedIds = new Set(rows.map((r) => r.id));
  return [...events.filter((e) => !replacedIds.has(e.id)), ...rows];
}
