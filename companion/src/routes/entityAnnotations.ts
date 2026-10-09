import type { Express, Request, Response } from "express";
import { resolveStoredTargets } from "../analysis/eventAliasLookup.js";
import { eventAliasSource } from "../analysis/eventAliasRead.js";
import { MAX_TAGGER_ROW_IDS, taggerTagsForRows } from "../analysis/taggerRowTags.js";
import type { RouteContext } from "./context.js";

const TAGGER_PAGE_DEFAULT = 500;
const TAGGER_PAGE_MAX = 5000;

/** A non-negative integer query value, clamped to `max`; `fallback` when absent or malformed. */
function pageNumber(raw: unknown, fallback: number, max: number): number {
  const n = Number(raw);
  if (raw === undefined || raw === "" || !Number.isFinite(n) || n < 0) return fallback;
  return Math.min(max, Math.floor(n));
}

// The two annotation LISTS the dashboard indexes by `(targetType, targetId)`: investigator comments and
// analyst tags (stars are `starred` tags). Moved here from routes/findings.ts, which has no line
// headroom, when #1715 made them resolve: correlation can fold the event an analyst marked into
// another, so each event target whose event is gone also carries `resolvedTargetId` — the event it
// lives on today. The stored record is unchanged; the dashboard shows the mark on both ids.
export function registerEntityAnnotationRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      const comments = await options.commentsStore.load(req.params.id);
      return res
        .status(200)
        .json(await resolveStoredTargets(eventAliasSource(options.stateStore), req.params.id, comments));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // #2059: the list carries ANALYST tags only. The automatic tagger's event tags — one per matched event
  // and label, nearly all of an auto-tagged case's tags — travel with the timeline page showing their
  // rows (routes/caseState.ts, routes/timeline.ts). The header tells a client when the tagger tags it
  // was handed went stale. `?scope=tagger` is the explicit, paged way to list the tagger's tags.
  app.get("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const scope = req.query.scope;
    if (scope !== undefined && scope !== "analyst" && scope !== "tagger") {
      return res.status(400).json({ error: "scope must be analyst or tagger" });
    }
    try {
      const aliases = eventAliasSource(options.stateStore);
      if (scope === "tagger") {
        const offset = pageNumber(req.query.offset, 0, Number.MAX_SAFE_INTEGER);
        const limit =
          pageNumber(req.query.limit, TAGGER_PAGE_DEFAULT, TAGGER_PAGE_MAX) || TAGGER_PAGE_DEFAULT;
        const page = await options.tagsStore.taggerPage(req.params.id, offset, limit);
        const nextOffset = offset + page.tags.length < page.total ? offset + page.tags.length : null;
        const tags = await resolveStoredTargets(aliases, req.params.id, page.tags);
        return res.status(200).json({ tags, total: page.total, offset, limit, nextOffset });
      }
      const { tags, taggerVersion } = await options.tagsStore.loadAnalyst(req.params.id);
      res.setHeader("X-Tagger-Tags-Version", taggerVersion);
      return res.status(200).json(await resolveStoredTargets(aliases, req.params.id, tags));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The tagger tags of the rows a dashboard already holds, after the tagger version moved (#2059).
  // Bounded: at most MAX_TAGGER_ROW_IDS ids per request; the client sends its rows in chunks.
  app.post("/cases/:id/tags/tagger-for", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const ids: unknown = req.body?.ids;
    if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string")) {
      return res.status(400).json({ error: "ids must be an array of event ids" });
    }
    if (ids.length > MAX_TAGGER_ROW_IDS) {
      return res.status(400).json({ error: `at most ${MAX_TAGGER_ROW_IDS} ids per request` });
    }
    try {
      const aliases = eventAliasSource(options.stateStore);
      const eventTaggerTags = await taggerTagsForRows(options.tagsStore, aliases, req.params.id, ids);
      return res.status(200).json({ eventTaggerTags });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
