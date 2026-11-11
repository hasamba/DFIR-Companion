import { createHash } from "node:crypto";
import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { TRUSTED_SOURCE_EVENT, TRUSTED_SOURCE_PATH_PREFIX } from "../analysis/custody.js";
import {
  FRIENDLY_ATTRIBUTIONS,
  IOC_ATTRIBUTION_LABELS,
  cleanActor,
  cleanAttributionValue,
  isIocAttributionLabel,
  type IocAttributionLabel,
} from "../analysis/iocAttribution.js";
import { IocAttributionStore } from "../analysis/iocAttributionStore.js";
import { syncTrustedActivity } from "../analysis/trustedActivitySync.js";
import { TRUSTED_AUTHOR_PREFIX, classifyMark, honouredTrustedRows } from "../analysis/trustedSourceMarks.js";
import { requestAuthentication } from "../auth/types.js";
import { actorFrom } from "./collectionGenerations.js";
import type { RouteContext } from "./context.js";
import { trustedSyncDeps } from "./trustedActivityDeps.js";

const isFriendly = (l: IocAttributionLabel | null | undefined): boolean =>
  !!l && FRIENDLY_ATTRIBUTIONS.has(l);

// The analyst's attribution label on an IOC (#2543 part 1b): attacker / ours / responder / unknown.
// GET lists every label of the case; PUT sets one value's label, or clears it with `label: null`.
// Every change is written to the case activity log with the analyst and the old → new label, like
// the false-positive routes. A label never starts a run. An `ours`/`responder` label on a value the
// trusted-source matcher can read (an IP, an AWS key id or principal ARN) also re-tags that source's
// routine rows `trusted-activity` and writes a custody entry (#2561); synthesis is told which rows are
// trusted. GET /cases/:id/trusted-activity lists the rows whose trusted tag still holds.
//
// Its own module rather than routes/findings.ts because that file sits at its size ledger.
export function registerIocAttributionRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const labels = new IocAttributionStore(store);

  app.get("/cases/:id/ioc-attribution", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await labels.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/ioc-attribution", async (req: Request, res: Response) => {
    const value = cleanAttributionValue(req.body?.value);
    if (!value)
      return res.status(400).json({ error: "value is required (one line, at most 2048 characters)" });
    const raw = req.body?.label;
    if (raw !== null && !isIocAttributionLabel(raw))
      return res
        .status(400)
        .json({ error: `label must be one of ${IOC_ATTRIBUTION_LABELS.join(", ")} (or null to clear)` });
    const who = actorFrom(requestAuthentication(req), Boolean(options.teamAuth));
    const actor = who && who.id !== "local" ? who.displayName : cleanActor(req.body?.actor);
    try {
      const { map, change } = await labels.set(req.params.id, value, raw, actor || "anonymous");
      if (change.before !== change.after) {
        void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
          category: "triage",
          action: change.after ? "set-ioc-attribution" : "clear-ioc-attribution",
          actor,
          detail: `ioc ${value}: ${change.before ?? "unset"} → ${change.after ?? "unset"}`,
          targetType: "ioc",
          targetId: value,
        });
      }
      // A trusted-source transition owes a custody entry. An unchanged save re-checks the chain, so
      // re-saving the same label repairs an entry a failed write left out (Codex code review).
      const before = change.before ?? null;
      const after = change.after ?? null;
      const owed =
        before !== after
          ? isFriendly(before) || isFriendly(after)
            ? before
            : undefined
          : await custodyOwed(req.params.id, value, after);
      if (
        owed !== undefined &&
        !(await recordTrustedMark(req.params.id, value, { before: owed, after }, actor, who?.id))
      )
        return res.status(500).json({
          error:
            "The label was saved, but its custody entry could not be written. Save the same label again to retry.",
          map,
        });
      return res.status(200).json(map);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/trusted-activity", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    try {
      if (!options.stateStore || !options.tagsStore) return res.status(200).json({ rows: {}, count: 0 });
      const map = await labels.load(caseId);
      const rows = (await options.stateStore.load(caseId)).forensicTimeline;
      const tags = (
        await options.tagsStore.taggerTagsFor(
          caseId,
          rows.map((r) => r.id),
        )
      ).filter((t) => t.author.startsWith(TRUSTED_AUTHOR_PREFIX));
      const honoured = honouredTrustedRows(rows, tags, map);
      return res.status(200).json({ rows: Object.fromEntries(honoured), count: honoured.size });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  /**
   * For an unchanged save: the label custody last recorded for this value, when it differs from the
   * current one (a write that failed earlier), or undefined when nothing is owed.
   */
  async function custodyOwed(
    caseId: string,
    value: string,
    current: IocAttributionLabel | null,
  ): Promise<IocAttributionLabel | null | undefined> {
    if (!options.custodyStore) return undefined;
    const path = `${TRUSTED_SOURCE_PATH_PREFIX}${value}`;
    const last = (await options.custodyStore.load(caseId)).filter((r) => r.artifactPath === path).at(-1);
    const recorded = (last?.trustedSource?.after ?? null) as IocAttributionLabel | null;
    if (last ? recorded === current : !isFriendly(current)) return undefined;
    return recorded;
  }

  /** Re-tag the case, then pin the mark in custody. False when the custody entry could not be written. */
  async function recordTrustedMark(
    caseId: string,
    value: string,
    change: { before: IocAttributionLabel | null; after: IocAttributionLabel | null },
    actor: string,
    actorId: string | undefined,
  ): Promise<boolean> {
    const deps = trustedSyncDeps(options, store, (m) => ctx.serverLogger.info(m));
    const { tagged } = deps ? await syncTrustedActivity(deps, caseId) : { tagged: 0 };
    if (!options.custodyStore) return true;
    const readable = classifyMark(value, change.after ?? change.before ?? "ours");
    const trustedSource = { value, before: change.before, after: change.after, rowsTagged: tagged };
    const at = new Date().toISOString();
    try {
      await options.custodyStore.record(caseId, {
        artifactPath: `${TRUSTED_SOURCE_PATH_PREFIX}${value}`,
        sha256: createHash("sha256")
          .update(JSON.stringify({ ...trustedSource, by: actor, at }))
          .digest("hex"),
        caseId,
        event: TRUSTED_SOURCE_EVENT,
        collectedBy: actor || "anonymous",
        ...(actorId ? { actorId } : {}),
        collectedAt: at,
        source: readable ? `${readable.kind} ${value}` : `${value} (not a source the matcher reads)`,
        trigger: `trusted-source mark ${change.before ?? "unset"} → ${change.after ?? "unset"}; ${tagged} forensic row(s) tagged trusted-activity`,
        trustedSource,
      });
      return true;
    } catch (err) {
      ctx.serverLogger.error(
        `[ioc-attribution] case=${caseId} trusted mark on ${value} set, but its custody entry failed: ${(err as Error).message}`,
      );
      return false;
    }
  }
}
