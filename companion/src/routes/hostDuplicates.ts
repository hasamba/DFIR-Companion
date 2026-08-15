import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import { canonicalHostName, type NearDuplicate } from "../analysis/hostAlias.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { hostNamesFromState, pendingNearDuplicates } from "../analysis/hostDuplicateGate.js";
import type { RouteContext } from "./context.js";

/**
 * Near-duplicate host review — the pre-synthesis merge gate's UI surface.
 *   - GET  /cases/:id/host-duplicates          — pairs still awaiting a decision.
 *   - POST /cases/:id/host-duplicates/merge    — fold `other` into `canonical` (asset-graph merge).
 *   - POST /cases/:id/host-duplicates/dismiss  — record that they are genuinely different machines.
 *
 * Resolving the LAST pending pair kicks the synthesis the gate was holding.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
const HOST_ID_PREFIX = "host:";

export function registerHostDuplicateRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  function configured(res: Response): boolean {
    if (!options.stateStore || !options.assetOverridesStore || !options.hostDuplicateDismissalStore) {
      res.status(501).json({ error: "host-duplicate review not configured" });
      return false;
    }
    return true;
  }

  async function pending(caseId: string): Promise<NearDuplicate[]> {
    const state = await options.stateStore!.load(caseId);
    const aliasIndex = await loadHostAliasIndex(
      {
        assetOverrides: options.assetOverridesStore!,
        ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
      },
      caseId,
    );
    return pendingNearDuplicates(
      hostNamesFromState(state),
      aliasIndex,
      await options.hostDuplicateDismissalStore!.load(caseId),
    );
  }

  // Both POST bodies name the pair the same way, and both reject the same malformed input.
  function readPair(req: Request): { canonical: string; other: string } | null {
    const canonical = canonicalHostName(String(req.body?.canonical ?? ""));
    const other = canonicalHostName(String(req.body?.other ?? ""));
    if (!canonical || !other || canonical === other) return null;
    return { canonical, other };
  }

  // Both resolve paths answer with the freshly-recomputed pending list. Task 10 adds the
  // auto-synthesis kick here.
  async function respond(caseId: string, res: Response): Promise<Response> {
    return res.status(200).json({ pending: await pending(caseId) });
  }

  app.get("/cases/:id/host-duplicates", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      return res.status(200).json({ pending: await pending(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/host-duplicates/merge", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const pair = readPair(req);
    if (!pair) return res.status(400).json({ error: "canonical and other must be two different hosts" });
    try {
      // The alias index is keyed by host NAME; asset-override merges are keyed by asset id.
      await options.assetOverridesStore!.mergeAsset(
        req.params.id,
        `${HOST_ID_PREFIX}${pair.other}`,
        `${HOST_ID_PREFIX}${pair.canonical}`,
      );
      // Every other asset-override mutation fires this; skipping it leaves the derived graph stale.
      options.onAssetOverrides?.(req.params.id);
      return await respond(req.params.id, res);
    } catch (err) {
      // 400, not 500: mergeAsset throws only on analyst-caused conditions (self-merge, cycle).
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/host-duplicates/dismiss", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const pair = readPair(req);
    if (!pair) return res.status(400).json({ error: "canonical and other must be two different hosts" });
    try {
      await options.hostDuplicateDismissalStore!.append(req.params.id, {
        canonical: pair.canonical,
        other: pair.other,
        dismissedAt: new Date().toISOString(),
        dismissedBy: requestAuthentication(req)?.identity.displayName ?? "local",
      });
      return await respond(req.params.id, res);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
