import type { Express, Request, Response } from "express";
import { z } from "zod";
import { huntCoverageFromJobs } from "../analysis/huntFraming.js";
import { loadHuntJobsSafe } from "../analysis/huntFramingLoad.js";
import { stableHostKey } from "../analysis/huntHostKey.js";
import { confirmCandidates, confirmListCsv, confirmListMarkdown } from "../analysis/huntConfirmList.js";
import { EMPTY_BASELINE, PROFILE_ID_RE } from "../analysis/clientProfile.js";
import { logActivity } from "../analysis/activityLog.js";
import { currentIdentity } from "../auth/identityContext.js";
import { isAnalystCase } from "../storage/sweepCase.js";
import type { RouteContext } from "./context.js";

/**
 * A hunt case's client (#2670):
 *   GET  /cases/:id/hunt/client             — the linked client, baseline versions, earlier hunts.
 *   POST /cases/:id/hunt/client             — link the case to a client (case ADMINISTRATOR, D3).
 *   GET  /cases/:id/hunt/candidates         — what the client still has to confirm, rarest first.
 *   GET  /cases/:id/hunt/confirm-list.csv   — the same list for the client (export right).
 *   GET  /cases/:id/hunt/confirm-list.md
 *
 * Earlier hunts for the same client are listed ONLY when the caller may open them: team visibility
 * AND, for a password-protected case, this request's unlock cookie (the routes/crossCase.ts gate).
 */
const linkSchema = z.object({ clientId: z.string().regex(PROFILE_ID_RE, "invalid client id") });

export function registerHuntClientRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  async function answered(caseId: string): Promise<Set<string>> {
    const jobs = await loadHuntJobsSafe({ veloHuntStore: options.veloHuntStore }, caseId);
    const cov = huntCoverageFromJobs(jobs);
    const server = options.serverSetStore?.caseSetId(caseId) ?? "";
    return new Set(cov.known ? cov.answeredHosts.map((h) => stableHostKey(server, h.clientId)) : []);
  }

  async function candidatesFor(caseId: string) {
    const link = await options.huntClientLinkStore?.load(caseId);
    const profile = link ? await options.clientProfileStore?.get(link.clientId) : null;
    const rec = await options.huntInventoryStore?.load(caseId);
    const list = rec
      ? confirmCandidates(
          rec.inventory,
          profile?.baseline ?? EMPTY_BASELINE,
          await answered(caseId),
          new Date().toISOString(),
        )
      : [];
    return { link, profile, list, pinnedVersion: rec?.baselineVersion };
  }

  /** Other cases linked to `clientId` that THIS request may open. */
  async function earlierHunts(req: Request, caseId: string, clientId: string) {
    const visible = options.teamAuth?.visibleCaseIds(req); // null = instance administrator
    const out: { caseId: string; name: string; linkedAt: string }[] = [];
    for (const meta of await store.listCases()) {
      if (meta.caseId === caseId || !isAnalystCase(meta)) continue;
      if (visible && !visible.has(meta.caseId)) continue;
      if (meta.password && !ctx.readUnlockState(req, meta.caseId, meta.password.salt).unlocked) continue;
      const link = await options.huntClientLinkStore?.load(meta.caseId).catch(() => null);
      if (link?.clientId === clientId)
        out.push({ caseId: meta.caseId, name: meta.name, linkedAt: link.linkedAt });
    }
    return out.sort((a, b) => b.linkedAt.localeCompare(a.linkedAt));
  }

  app.get("/cases/:id/hunt/client", async (req: Request, res: Response) => {
    try {
      const { link, profile, list, pinnedVersion } = await candidatesFor(req.params.id);
      return res.status(200).json({
        link,
        client: profile
          ? { id: profile.id, name: profile.name, defaultServerSetId: profile.defaultServerSetId }
          : null,
        currentVersion: profile?.version ?? null,
        pinnedVersion: pinnedVersion ?? null,
        pending: list.length,
        earlierHunts: profile ? await earlierHunts(req, req.params.id, profile.id) : [],
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/hunt/client", async (req: Request, res: Response) => {
    const body = linkSchema.safeParse(req.body ?? {});
    if (!body.success) return res.status(400).json({ error: "clientId is required" });
    if (!options.huntClientLinkStore || !options.clientProfileStore)
      return res.status(501).json({ error: "client profiles not configured" });
    try {
      const profile = await options.clientProfileStore.get(body.data.clientId);
      if (!profile) return res.status(404).json({ error: "client profile not found" });
      const by = currentIdentity()?.displayName || "analyst";
      const link = await options.huntClientLinkStore.save(req.params.id, {
        clientId: profile.id,
        linkedAt: new Date().toISOString(),
        linkedBy: by,
      });
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "hunt",
        action: "hunt-client-link",
        detail: `Linked to client profile "${profile.name}" (baseline version ${profile.version})`,
      });
      return res.status(200).json({ link, client: { id: profile.id, name: profile.name } });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/hunt/candidates", async (req: Request, res: Response) => {
    try {
      const { list } = await candidatesFor(req.params.id);
      return res.status(200).json({ candidates: list.slice(0, 1000), total: list.length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/hunt/confirm-list.:fmt(csv|md)", async (req: Request, res: Response) => {
    try {
      const { list, profile } = await candidatesFor(req.params.id);
      const name = profile?.name ?? "client";
      if (req.params.fmt === "csv") {
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="confirm-list-${req.params.id}.csv"`);
        return res.status(200).send(confirmListCsv(list));
      }
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="confirm-list-${req.params.id}.md"`);
      return res.status(200).send(confirmListMarkdown(list, name));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
