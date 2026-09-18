import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import { canonicalHostName, NEAR_DUPLICATE_BLOCKING, type NearDuplicate } from "../analysis/hostAlias.js";
import { loadHostDuplicatePanelCandidates } from "../analysis/hostScopeLoad.js";
import type { RouteContext } from "./context.js";

/**
 * Near-duplicate host review — the pre-synthesis merge gate's UI surface.
 *   - GET    /cases/:id/host-duplicates            — pairs still awaiting a decision.
 *   - POST   /cases/:id/host-duplicates/merge      — fold `other` into `canonical` (asset-graph merge).
 *   - POST   /cases/:id/host-duplicates/dismiss    — record that they are genuinely different machines.
 *   - GET    /cases/:id/host-duplicates/dismissed  — every currently-recorded dismissal (#1170).
 *   - DELETE /cases/:id/host-duplicates/dismiss    — undo exactly one dismissal (#1170), never every
 *     dismissal in the case (deleting the store file on disk, the only prior workaround). The pair
 *     becomes eligible to be suggested again on the next read — the pending list is derived, never
 *     cached — including re-arming the AI-synthesis gate if it was a blocking pair, which is the
 *     correct, expected outcome of an explicit undo, so this route never kicks a resynthesis.
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
    return loadHostDuplicatePanelCandidates(
      {
        state: options.stateStore!,
        assetOverrides: options.assetOverridesStore!,
        dismissals: options.hostDuplicateDismissalStore!,
        ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
      },
      caseId,
    );
  }

  // Both POST bodies name the pair the same way, and both reject the same malformed input.
  function readPair(req: Request): { canonical: string; other: string } | null {
    const canonical = canonicalHostName(String(req.body?.canonical ?? ""));
    const other = canonicalHostName(String(req.body?.other ?? ""));
    if (!canonical || !other || canonical === other) return null;
    return { canonical, other };
  }

  // A "network-identity" candidate never blocks synthesis in the first place
  // (hostDuplicateGate.ts's own pendingNearDuplicates — the only source HostMergeDecisionRequired
  // reads — never includes them). Reads hostAlias.ts's own NEAR_DUPLICATE_BLOCKING rather than
  // negating one reason string, so a third reason added to the type forces a deliberate choice at
  // the source instead of silently becoming blocking here (#1259).
  function isBlocking(p: NearDuplicate): boolean {
    return NEAR_DUPLICATE_BLOCKING[p.reason];
  }

  // Both resolve paths answer with the freshly-recomputed pending list.
  // Resolving the LAST BLOCKING pair is what lifts the gate, so that TRANSITION — not the raw list
  // merely becoming empty — is the moment worth a synthesis. `wasBlocking` is a snapshot the caller
  // takes BEFORE the mutation, since respond() itself only ever sees the AFTER state. Kicking on
  // every resolve while only non-blocking network-identity candidates remain (e.g. checking
  // `remaining.every(reason === "network-identity")` on the AFTER state alone, an earlier draft of
  // this fix) would spend one full synthesis run per candidate instead of the single run the
  // blocking-pair transition earns (Ollama review finding on #1167). The list hitting fully empty
  // is kept as its own, separate trigger purely for exact backward compatibility with this route's
  // original, pre-#1167 behavior — resolving the very last candidate of any kind still kicks once,
  // even when it was never a blocking one.
  async function respond(caseId: string, res: Response, wasBlocking: boolean): Promise<Response> {
    const remaining = await pending(caseId);
    const nowBlocking = remaining.some(isBlocking);
    if ((wasBlocking && !nowBlocking) || remaining.length === 0) ctx.resynthesizeInBackground(caseId);
    return res.status(200).json({ pending: remaining });
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
      const wasBlocking = (await pending(req.params.id)).some(isBlocking);
      // The alias index is keyed by host NAME; asset-override merges are keyed by asset id.
      await options.assetOverridesStore!.mergeAsset(
        req.params.id,
        `${HOST_ID_PREFIX}${pair.other}`,
        `${HOST_ID_PREFIX}${pair.canonical}`,
      );
      // Every other asset-override mutation fires this; skipping it leaves the derived graph stale.
      options.onAssetOverrides?.(req.params.id);
      return await respond(req.params.id, res, wasBlocking);
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
      const wasBlocking = (await pending(req.params.id)).some(isBlocking);
      await options.hostDuplicateDismissalStore!.append(req.params.id, {
        canonical: pair.canonical,
        other: pair.other,
        dismissedAt: new Date().toISOString(),
        dismissedBy: requestAuthentication(req)?.identity.displayName ?? "local",
      });
      return await respond(req.params.id, res, wasBlocking);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/host-duplicates/dismissed", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      return res
        .status(200)
        .json({ dismissed: await options.hostDuplicateDismissalStore!.load(req.params.id) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Deliberately asymmetric with merge/dismiss above: this handler does NOT snapshot
  // `wasBlocking` before mutating, and its response shape (`{ dismissed, pending }`) differs
  // from respond()'s (`{ pending }`). That is intentional, not an oversight — undo never
  // resynthesizes (see the file-level docstring on why #1170 keeps it a no-op for synthesis),
  // so there is no transition to detect and nothing here reads a `wasBlocking`/`wasClear`
  // boolean today. If a future feature needs to know whether undoing a dismissal re-armed a
  // blocking gate, snapshot it the same way merge/dismiss do — swap the order below to read
  // `pending(req.params.id).some(isBlocking)` BEFORE calling `remove()`, then add the resulting
  // boolean to the JSON body — rather than assuming the two routes already agree (#1283).
  app.delete("/cases/:id/host-duplicates/dismiss", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const pair = readPair(req);
    if (!pair) return res.status(400).json({ error: "canonical and other must be two different hosts" });
    try {
      const removed = await options.hostDuplicateDismissalStore!.remove(
        req.params.id,
        pair.canonical,
        pair.other,
      );
      if (!removed) return res.status(404).json({ error: "no such dismissal" });
      const [dismissed, pendingList] = await Promise.all([
        options.hostDuplicateDismissalStore!.load(req.params.id),
        pending(req.params.id),
      ]);
      return res.status(200).json({ dismissed, pending: pendingList });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
