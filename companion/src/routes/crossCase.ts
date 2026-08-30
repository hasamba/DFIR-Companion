import { stat } from "node:fs/promises";
import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import type { StateStore } from "../analysis/stateStore.js";
import type { CaseMeta } from "../types.js";
import type { IOC } from "../analysis/stateTypes.js";
import {
  buildCrossCaseIndex,
  isMaliciousIoc,
  relatedCases,
  searchCrossCaseIocs,
  PIVOT_IOC_TYPES,
  type CaseIocSnapshot,
  type CrossCaseIndex,
  type IocType,
} from "../analysis/crossCaseIndex.js";

/**
 * Cross-case IOC pivot (#679) — `GET /global/iocs` and `GET /cases/:id/related`.
 *
 * The correlation itself is a pure function in analysis/crossCaseIndex.ts. This file owns the two
 * things that function deliberately does not: WHICH CASES THE CALLER MAY SEE, and not re-reading
 * every case on disk for every request.
 *
 * THE VISIBILITY GATE IS THE WHOLE SECURITY STORY, and it has two independent halves, because a
 * case can be closed to a caller in two unrelated ways:
 *
 *   1. Team roles. `teamAuth.visibleCaseIds(req)` is the same set that filters `GET /cases`, so a
 *      reader on case A learns nothing about case B, and a service token sees only its own case.
 *      In single-user mode there is no teamAuth and every case is visible — which is already true
 *      of every other route.
 *   2. Case passwords. The case-lock gate is mounted on `/cases/:id` and so does not cover
 *      `/global/*` at all, and on `/cases/:id/related` it only guards the SUBJECT case. Neither
 *      would stop a locked case's indicators being read out through its correlation with an
 *      unlocked one. So a password-protected case contributes nothing unless THIS request already
 *      carries its unlock cookie.
 *
 * Both halves are applied while collecting snapshots, before anything is indexed — the index has
 * no notion of a permission, so a case that must stay hidden must never reach it.
 *
 * CACHING. Reading every case's state per request is the expensive part, so each case's IOC list
 * is cached against a fingerprint of its SQLite file (mtime + size). The cache holds data, not
 * answers, so the permission filter still runs on every request against the current identity. The
 * built index is additionally memoised for the exact visible set that produced it — one entry,
 * because the common case is one analyst paging around one dashboard.
 */

/** Max cases listed by `GET /cases/:id/related` before `limit` is clamped. */
const MAX_RELATED_LIMIT = 100;
/** Max entries `GET /global/iocs` will return before `limit` is clamped. */
const MAX_SEARCH_LIMIT = 200;

interface CachedSnapshot {
  /** Identity of everything the snapshot was built from — see {@link cacheKey}. */
  key: string;
  snapshot: CaseIocSnapshot;
}

/**
 * Everything the index reads off an IOC, and nothing else.
 *
 * The cache holds one of these per IOC for the life of the process, so what it does NOT keep is
 * the point: an enriched IOC carries a full provider record per lookup — tags, permalinks, engine
 * tallies, geo coordinates — and none of it is read here. A case with thousands of enriched
 * indicators would otherwise pin megabytes per case for a panel that needs one boolean. The
 * verdict is preserved by carrying the first FLAGGING enrichment through as it stands, so
 * isMaliciousIoc answers the same on the trimmed copy as on the original.
 */
function slimIoc(ioc: IOC): IOC {
  const flagged = isMaliciousIoc(ioc)
    ? (ioc.enrichments ?? []).find((e) => e.verdict === "malicious" || e.verdict === "suspicious")
    : undefined;
  return {
    id: ioc.id,
    type: ioc.type,
    value: ioc.value,
    firstSeen: ioc.firstSeen,
    ...(ioc.aliasValues?.length ? { aliasValues: [...ioc.aliasValues] } : {}),
    ...(flagged
      ? { enrichments: [{ source: flagged.source, verdict: flagged.verdict, fetchedAt: flagged.fetchedAt }] }
      : {}),
  };
}

function parsePositiveInt(raw: unknown, fallback: number, max: number): number {
  const n = Number.parseInt(typeof raw === "string" ? raw : "", 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(n, max);
}

/**
 * `?type=ip&type=hash` or `?type=ip,hash`. Returns `undefined` when the caller named no type at
 * all, and `null` when they named only types this index does not carry — the two are NOT the same
 * answer. Treating an unrecognised filter as "no filter" would answer `?type=process` with every
 * domain and address in the estate, which is the opposite of what was asked for.
 */
function parseTypes(raw: unknown): IocType[] | null | undefined {
  if (raw === undefined) return undefined;
  const values = (Array.isArray(raw) ? raw : [raw])
    .filter((v): v is string => typeof v === "string")
    .flatMap((v) => v.split(","))
    .map((v) => v.trim().toLowerCase())
    .filter((v) => v.length > 0);
  if (!values.length) return undefined;
  const known = new Set<string>(PIVOT_IOC_TYPES);
  const picked = [...new Set(values.filter((v) => known.has(v)))] as IocType[];
  return picked.length ? picked : null;
}

export function registerCrossCaseRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  // OFF unless asked for (#723). Across one estate a shared indicator is usually ordinary
  // infrastructure — one resolver, one proxy, one patch server — and reading that overlap as a link
  // between investigations is the mistake the feature invites; #730 already hid the panel that
  // surfaced it. The ROUTES stayed live, though, and every answered request pins a slimmed copy of
  // each visible case's IOCs in memory for the life of the process, with nothing evicting a case
  // that has since been deleted. Off by default, that index is never built and nothing is pinned.
  //
  // Read ONCE at registration rather than per request: this is a deployment decision, and a value
  // that could change mid-session would let two requests in one sitting disagree about whether the
  // estate is searchable. Deliberately NOT on the Settings writable allowlist — envManager keeps
  // security toggles out of the dashboard's reach, and this one decides whether a case may name
  // other cases.
  const enabled = (process.env.DFIR_CROSS_CASE ?? "off").trim().toLowerCase() === "on";

  /** Refuse with the reason, so an operator meeting a 404 is not left guessing which. */
  function disabled(res: Response): Response {
    return res
      .status(404)
      .json({ error: "cross-case pivot is disabled — set DFIR_CROSS_CASE=on to enable it" });
  }
  const snapshots = new Map<string, CachedSnapshot>();
  let indexCache: { key: string; index: CrossCaseIndex } | null = null;

  /** mtime+size of a case's state database, or "absent" before it has one. */
  async function fingerprintOf(stateStore: StateStore, caseId: string): Promise<string> {
    try {
      const s = await stat(stateStore.databasePath(caseId));
      return `${s.mtimeMs}:${s.size}`;
    } catch {
      return "absent";
    }
  }

  /**
   * Everything a snapshot is derived from, in one string.
   *
   * The IOCs come from the state database, so its fingerprint covers those — but the display name
   * and the lifecycle status live in case.json and move independently. Keying on the fingerprint
   * alone would leave a renamed or archived case showing its old label until the next import.
   */
  function cacheKey(meta: CaseMeta, fingerprint: string): string {
    return JSON.stringify([meta.caseId, fingerprint, meta.name, meta.status ?? "open"]);
  }

  async function snapshotOf(
    stateStore: StateStore,
    meta: CaseMeta,
  ): Promise<{ key: string; snapshot: CaseIocSnapshot }> {
    const key = cacheKey(meta, await fingerprintOf(stateStore, meta.caseId));
    const cached = snapshots.get(meta.caseId);
    if (cached && cached.key === key) return cached;
    // loadOverview, not load: the forensic timeline is by far the largest kind and nothing here
    // reads it.
    const state = await stateStore.loadOverview(meta.caseId);
    const entry: CachedSnapshot = {
      key,
      snapshot: {
        caseId: meta.caseId,
        name: meta.name,
        status: meta.status ?? "open",
        iocs: state.iocs.map(slimIoc),
      },
    };
    snapshots.set(meta.caseId, entry);
    return entry;
  }

  /** The cases this request may read, after BOTH halves of the gate. */
  async function visibleCases(req: Request): Promise<CaseMeta[]> {
    const listed = await store.listCases();
    const visible = options.teamAuth?.visibleCaseIds(req); // null = global administrator
    return listed.filter((meta) => {
      if (visible && !visible.has(meta.caseId)) return false;
      if (!meta.password) return true;
      return ctx.readUnlockState(req, meta.caseId, meta.password.salt).unlocked;
    });
  }

  async function indexFor(
    req: Request,
    stateStore: StateStore,
  ): Promise<{ index: CrossCaseIndex; scanned: number }> {
    const metas = await visibleCases(req);
    const collected: CaseIocSnapshot[] = [];
    const keys: string[] = [];
    for (const meta of metas) {
      try {
        const entry = await snapshotOf(stateStore, meta);
        collected.push(entry.snapshot);
        keys.push(entry.key);
      } catch {
        // One unreadable case (a half-written database, a migration that needs an operator) must
        // not take the whole cross-case view down with it — it simply contributes nothing.
      }
    }
    // The key is the visible SET, so a caller who may see fewer cases can never be served an index
    // built for someone who may see more.
    const key = keys.join("|");
    if (indexCache?.key !== key) {
      indexCache = { key, index: buildCrossCaseIndex(collected) };
    }
    return { index: indexCache.index, scanned: collected.length };
  }

  // Search every case the caller may read for one indicator. The answer names the cases, so it is
  // gated exactly like GET /cases (auth/policy.ts resolves it to the "case-list" bucket): any
  // session, and a service token holding "read" — which sees only its own case.
  app.get("/global/iocs", async (req: Request, res: Response) => {
    if (!enabled) return disabled(res);
    const stateStore = options.stateStore;
    if (!stateStore) return res.status(501).json({ error: "state store not configured" });
    const q = typeof req.query.q === "string" ? req.query.q : "";
    if (!q.trim()) return res.status(400).json({ error: "q is required" });
    const types = parseTypes(req.query.type);
    if (types === null) {
      return res.status(400).json({ error: `type must be one of: ${PIVOT_IOC_TYPES.join(", ")}` });
    }
    try {
      const { index, scanned } = await indexFor(req, stateStore);
      const result = searchCrossCaseIocs(index, q, {
        limit: parsePositiveInt(req.query.limit, 50, MAX_SEARCH_LIMIT),
        minCases: parsePositiveInt(req.query.minCases, 1, 100),
        types,
      });
      return res.status(200).json({ ...result, scannedCases: scanned });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The cases that overlap with this one, strongest link first. The subject case is authorized by
  // the standard case-read policy plus the case-lock gate; every OTHER case in the answer went
  // through visibleCases() above.
  app.get("/cases/:id/related", async (req: Request, res: Response) => {
    if (!enabled) return disabled(res);
    const stateStore = options.stateStore;
    if (!stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      // StateStore.load answers an unknown case with emptyState, so without this the route would
      // 200 with an empty list for any id at all, the way the coach route would.
      if (!(await store.caseExists(caseId))) {
        return res.status(404).json({ error: `case ${caseId} does not exist` });
      }
      const { index, scanned } = await indexFor(req, stateStore);
      const related = relatedCases(index, caseId, {
        limit: parsePositiveInt(req.query.limit, 20, MAX_RELATED_LIMIT),
        sharedLimit: parsePositiveInt(req.query.sharedLimit, 10, 100),
      });
      return res.status(200).json({ caseId, related, scannedCases: scanned });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
