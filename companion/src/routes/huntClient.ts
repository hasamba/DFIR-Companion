import type { Express, NextFunction, Request, Response } from "express";
import { z } from "zod";
import { huntCoverageFromJobs } from "../analysis/huntFraming.js";
import { loadHuntJobsSafe } from "../analysis/huntFramingLoad.js";
import { stableHostKey } from "../analysis/huntHostKey.js";
import { confirmCandidates, confirmListCsv, confirmListMarkdown } from "../analysis/huntConfirmList.js";
import { EMPTY_BASELINE, PROFILE_ID_RE, isArchivedProfile } from "../analysis/clientProfile.js";
import { logActivity } from "../analysis/activityLog.js";
import { currentIdentity } from "../auth/identityContext.js";
import { CLIENT_DATA_DEMO_REFUSAL } from "../auth/policy.js";
import { isAnalystCase } from "../storage/sweepCase.js";
import type { RouteContext } from "./context.js";

/**
 * A hunt case's client (#2670):
 *   GET  /cases/:id/hunt/client             — the linked client, baseline versions, earlier hunts.
 *   POST /cases/:id/hunt/client             — link the case to a client (case ADMINISTRATOR, D3). Not
 *                                             to an archived client (409, #2941), and under the
 *                                             client's lock, so a delete of it cannot slip in between.
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

  // Every route here reads the linked client's profile: refused on the public demo (no login), GET
  // included. The demo gate (composition/httpStack.ts) refuses first; this is the second line.
  app.use(
    ["/cases/:id/hunt/client", "/cases/:id/hunt/candidates", "/cases/:id/hunt/confirm-list.:fmt(csv|md)"],
    function huntClientDemoRefusal(_req: Request, res: Response, next: NextFunction) {
      if (options.demoMode) return res.status(403).json({ error: CLIENT_DATA_DEMO_REFUSAL, demo: true });
      return next();
    },
  );

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
          ? {
              id: profile.id,
              name: profile.name,
              defaultServerSetId: profile.defaultServerSetId,
              ...(isArchivedProfile(profile) ? { archived: true } : {}),
            }
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
    const profiles = options.clientProfileStore;
    const linkStore = options.huntClientLinkStore;
    try {
      // The profile is read and the link written under the client's lock (#2941): a delete holds the
      // same lock across its linked-case check, so it sees this link or this link sees no client.
      const out = await profiles.exclusive(body.data.clientId, async () => {
        const profile = await profiles.get(body.data.clientId);
        if (!profile) return { status: 404, error: "client profile not found" } as const;
        if (isArchivedProfile(profile))
          return {
            status: 409,
            error: "This client is archived. Unarchive it before linking a case to it.",
          } as const;
        const link = await linkStore.save(req.params.id, {
          clientId: profile.id,
          linkedAt: new Date().toISOString(),
          linkedBy: currentIdentity()?.displayName || "analyst",
        });
        return { status: 200, link, profile } as const;
      });
      if (out.status !== 200) return res.status(out.status).json({ error: out.error });
      const { link, profile } = out;
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
