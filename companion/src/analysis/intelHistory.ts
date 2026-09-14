// Intel assertion history (#933 item 19, second half — #1024). What a re-check used to do: replace
// a provider's previous hits with the fresh result, and DROP them on a fresh miss — a "malicious"
// a provider later withdrew vanished from the case with no record. What it does now:
//
//   - every hit is an ASSERTION with a stable identity (provider | source | the provider's own
//     record id), superseded only by a fresh assertion of the same identity, never by a verdict;
//   - a successful check that does not return a known assertion marks it `not-returned` — "no hit
//     in that query", never a withdrawal (ThreatFox drops IOCs older than six months from its API
//     while its UI keeps them as expired);
//   - an errored provider or backend keeps its last-known assertions (`errored-last-known`) and is
//     remembered in `intelChecks` so it is retried even when it never had a hit;
//   - a check that read an INCOMPLETE result set (a pagination bound) applies no absence at all;
//   - history is appended only on material change (a fingerprint over every material field),
//     identical consecutive checks coalesce, and the per-assertion record count is bounded with
//     an auditable compaction count.

import { createHash } from "node:crypto";
import type {
  IOC,
  IocEnrichment,
  IntelAssertionRecord,
  IntelAssertionStatus,
  IntelCheckState,
} from "./stateTypes.js";

/** Records kept per assertion: the first, the newest 32, and a compacted count for the rest. */
export const HISTORY_PER_ASSERTION_MAX = 256;
export const HISTORY_KEPT_TAIL = 32;

const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 24);
const lower = (s: string): string => s.trim().toLowerCase();

/** The owning provider of a hit — the fan-out owner when it differs from the displayed source. */
export const ownerOf = (e: Pick<IocEnrichment, "provider" | "source">): string => e.provider ?? e.source;

/** The stable identity: (owner, source, the provider's record id — or the IOC value under that source). */
export function assertionIdFor(
  e: Pick<IocEnrichment, "provider" | "source" | "providerRecordId">,
  iocValue: string,
): string {
  const record = e.providerRecordId?.trim() || `value:${lower(iocValue)}`;
  return digest(`${lower(ownerOf(e))}|${lower(e.source)}|${record}`);
}

/** Every material field, in one string: two checks with the same fingerprint are the same state. */
export function fingerprintOf(e: IocEnrichment): string {
  return digest(
    JSON.stringify([
      e.verdict,
      e.score ?? "",
      e.detections ?? null,
      e.total ?? null,
      [...(e.tags ?? [])].sort(),
      e.temporal ?? null,
      e.validity ?? null,
      e.revoked ?? false,
      e.providerRecordId ?? "",
      e.status ?? "live",
    ]),
  );
}

/** The status a fresh hit carries at its check time: revoked and expired are the provider's own facts. */
export function statusAtCheck(e: IocEnrichment, checkedAt: string): IntelAssertionStatus {
  if (e.revoked) return "revoked";
  const until = e.validity?.until;
  if (until && Date.parse(until) <= Date.parse(checkedAt)) return "expired";
  return "live";
}

/** A stored hit with no assertion tracking reads as legacy: last-known, labelled, never actionable. */
export function withIdentity(e: IocEnrichment, iocValue: string): IocEnrichment {
  return {
    ...e,
    assertionId: e.assertionId ?? assertionIdFor(e, iocValue),
    status: e.status ?? "legacy-unverified",
  };
}

/** Append one state to the history: coalesce onto the newest record of the same assertion when nothing material changed. */
export function appendHistory(
  history: readonly IntelAssertionRecord[] | undefined,
  e: IocEnrichment,
  checkedAt: string,
): IntelAssertionRecord[] {
  const list = history ? [...history] : [];
  const id = e.assertionId ?? "";
  const fp = fingerprintOf(e);
  const own = list.filter((r) => r.assertionId === id);
  const newest = own.length ? own.reduce((m, r) => (r.lastCheckedAt > m.lastCheckedAt ? r : m)) : null;
  if (newest && newest.fingerprint === fp) {
    const i = list.indexOf(newest);
    list[i] = { ...newest, lastCheckedAt: checkedAt, checkCount: newest.checkCount + 1 };
    return list;
  }
  list.push({
    assertionId: id,
    provider: ownerOf(e),
    source: e.source,
    ...(e.providerRecordId ? { providerRecordId: e.providerRecordId } : {}),
    verdict: e.verdict,
    ...(e.score ? { score: e.score } : {}),
    ...(e.tags?.length ? { tags: [...e.tags] } : {}),
    ...(e.temporal ? { temporal: e.temporal } : {}),
    ...(e.validity ? { validity: e.validity } : {}),
    ...(e.revoked ? { revoked: true } : {}),
    status: e.status ?? "live",
    fingerprint: fp,
    firstCheckedAt: checkedAt,
    lastCheckedAt: checkedAt,
    checkCount: 1,
  });
  return compact(list, id);
}

/** Bound one assertion's records: keep the first and the newest tail; count the rest on the first. */
function compact(list: IntelAssertionRecord[], id: string): IntelAssertionRecord[] {
  const own = list
    .filter((r) => r.assertionId === id)
    .sort((a, b) => a.firstCheckedAt.localeCompare(b.firstCheckedAt));
  if (own.length <= HISTORY_PER_ASSERTION_MAX) return list;
  const first = own[0];
  const tail = own.slice(own.length - HISTORY_KEPT_TAIL);
  const dropped = own.slice(1, own.length - HISTORY_KEPT_TAIL);
  const kept = new Set<IntelAssertionRecord>([first, ...tail]);
  return list
    .filter((r) => r.assertionId !== id || kept.has(r))
    .map((r) => (r === first ? { ...r, compacted: (r.compacted ?? 0) + dropped.length } : r));
}

export interface ProviderCheck {
  /** The owning provider's name; `backend` when the outcome is one backend's of a fan-out provider. */
  provider: string;
  backend?: string;
  outcome: IntelCheckState["outcome"];
  detail?: string;
  incomplete?: boolean;
}

export const checkKey = (c: Pick<ProviderCheck, "provider" | "backend">): string =>
  c.backend ? `${c.provider}|${c.backend}` : c.provider;

/**
 * Fold one run's results for one IOC into its enrichments, history and check state.
 *
 * `fresh` are the hits the run returned (already stamped with identity and status); `checks` are
 * the per-provider / per-backend outcomes. For a provider (or backend) that answered with a
 * COMPLETE result, every known assertion of that provider/backend it did not return becomes
 * `not-returned`; for an errored one, `errored-last-known`; for an incomplete one, nothing moves.
 */
export function foldCheck(
  ioc: IOC,
  fresh: readonly IocEnrichment[],
  checks: readonly ProviderCheck[],
  checkedAt: string,
): Pick<IOC, "enrichments" | "intelHistory" | "intelChecks"> {
  const previous = (ioc.enrichments ?? []).map((e) => withIdentity(e, ioc.value));
  const freshIds = new Set(fresh.map((f) => f.assertionId));
  // A stale hit whose displayed `source` a fresh result of ANOTHER owner now emits (the retired
  // standalone MalwareBazaar under Hunting.ch's "MalwareBazaar") is superseded by that source:
  // its owner no longer runs, so nothing else would ever mark it.
  const freshOwnerBySource = new Map(fresh.map((f) => [f.source, ownerOf(f)]));
  const supersededBySource = previous.filter(
    (e) =>
      !freshIds.has(e.assertionId) &&
      freshOwnerBySource.has(e.source) &&
      freshOwnerBySource.get(e.source) !== ownerOf(e),
  );
  // Which (provider, source) pairs each check covers: a backend check covers its own source; a
  // provider-level check covers every source the provider owns.
  const outcomeFor = (e: IocEnrichment): ProviderCheck | undefined =>
    checks.find((c) => c.provider === ownerOf(e) && (!c.backend || c.backend === e.source)) ??
    checks.find((c) => c.provider === ownerOf(e) && !c.backend);
  const carried = previous
    .filter((e) => !freshIds.has(e.assertionId) && !supersededBySource.includes(e))
    .map((e) => {
      const c = outcomeFor(e);
      if (!c || c.outcome === "not-queried") return e;
      if (c.outcome === "error") return { ...e, status: "errored-last-known" as const, stateAt: checkedAt };
      if (c.incomplete) return e;
      // A revoked or expired assertion stays what it is; a live one the query did not return is "not returned".
      return e.status === "live" || e.status === "legacy-unverified" || e.status === "errored-last-known"
        ? { ...e, status: "not-returned" as const, lastMissAt: checkedAt, stateAt: checkedAt }
        : e;
    });
  const enrichments = [...carried, ...fresh.map((f) => ({ ...f, stateAt: f.stateAt ?? f.fetchedAt }))];
  let history = ioc.intelHistory ? [...ioc.intelHistory] : [];
  for (const e of supersededBySource)
    history = appendHistory(history, { ...e, status: "superseded" }, checkedAt);
  for (const e of enrichments) {
    const before = previous.find((p) => p.assertionId === e.assertionId);
    const changed = !before || fingerprintOf(before) !== fingerprintOf(e) || freshIds.has(e.assertionId);
    if (changed) history = appendHistory(history, e, checkedAt);
  }
  const intelChecks: Record<string, IntelCheckState> = { ...(ioc.intelChecks ?? {}) };
  for (const c of checks)
    if (c.outcome !== "not-queried")
      intelChecks[checkKey(c)] = {
        outcome: c.outcome,
        at: checkedAt,
        ...(c.detail ? { detail: c.detail } : {}),
        ...(c.incomplete ? { incomplete: true } : {}),
      };
  // A successful miss on a never-enriched IOC is "checked, no intel" (an empty list); an IOC whose
  // every call errored keeps `enrichments` undefined — never cached as checked.
  const answered = checks.some((c) => c.outcome === "hit" || c.outcome === "miss");
  return {
    enrichments: enrichments.length || answered ? enrichments : ioc.enrichments,
    ...(history.length ? { intelHistory: history } : {}),
    intelChecks,
  };
}

/**
 * Merge two versions of one IOC's intel state (a concurrent re-check, a stale completion): the
 * newest check per assertion wins, histories union by (assertionId, fingerprint) coalescing
 * counts, and the newest check state per key wins. Never replaces a whole IOC.
 */
export function mergeIntelState(
  base: IOC,
  incoming: IOC,
): Pick<IOC, "enrichments" | "intelHistory" | "intelChecks"> {
  // The newest STATE wins — a miss or an error is a state as much as a hit is, so a stale hit
  // completing after a newer miss never resurrects the assertion.
  const stateTime = (e: IocEnrichment): string =>
    e.stateAt ?? [e.fetchedAt, e.lastMissAt ?? ""].sort().pop()!;
  const byId = new Map<string, IocEnrichment>();
  for (const e of [...(base.enrichments ?? []), ...(incoming.enrichments ?? [])].map((x) =>
    withIdentity(x, base.value),
  )) {
    const cur = byId.get(e.assertionId!);
    if (!cur || stateTime(e) > stateTime(cur)) byId.set(e.assertionId!, e);
  }
  const history = new Map<string, IntelAssertionRecord>();
  for (const r of [...(base.intelHistory ?? []), ...(incoming.intelHistory ?? [])]) {
    const k = `${r.assertionId}|${r.fingerprint}|${r.firstCheckedAt}`;
    const cur = history.get(k);
    history.set(
      k,
      cur
        ? {
            ...cur,
            lastCheckedAt: r.lastCheckedAt > cur.lastCheckedAt ? r.lastCheckedAt : cur.lastCheckedAt,
            checkCount: Math.max(cur.checkCount, r.checkCount),
            ...(Math.max(cur.compacted ?? 0, r.compacted ?? 0)
              ? { compacted: Math.max(cur.compacted ?? 0, r.compacted ?? 0) }
              : {}),
          }
        : r,
    );
  }
  const checks: Record<string, IntelCheckState> = { ...(base.intelChecks ?? {}) };
  for (const [k, v] of Object.entries(incoming.intelChecks ?? {}))
    if (!checks[k] || v.at > checks[k].at) checks[k] = v;
  const enrichments = [...byId.values()];
  const intelHistory = [...history.values()].sort((a, b) => a.firstCheckedAt.localeCompare(b.firstCheckedAt));
  // Fields neither side had stay absent; an empty list one side had ("checked, no intel") stays a list.
  return {
    ...(base.enrichments === undefined && incoming.enrichments === undefined ? {} : { enrichments }),
    ...(intelHistory.length ? { intelHistory } : {}),
    ...(Object.keys(checks).length ? { intelChecks: checks } : {}),
  };
}
