import type { Express, Request, Response } from "express";
import { deriveAiState, type AiState } from "../analysis/aiState.js";
import { loadPendingHostDuplicates } from "../analysis/hostScopeLoad.js";
import { PresidioPendingStore } from "../analysis/presidioPending.js";
import { AiControlStore } from "../analysis/aiControl.js";
import type { RouteContext } from "./context.js";

/**
 * `GET /cases/:id/ai-state` — what this case's AI is actually doing, derived rather than remembered.
 *
 * The header pill's state used to live only in the pushed `ai_status` stream, with nothing to
 * correct it when an event was wrong, absent, or simply never seen because the page had just
 * loaded. See analysis/aiState.ts for the three bugs that came out of that. This is the endpoint the
 * dashboard reads whenever it needs the truth instead of the latest rumour: on case connect, on
 * websocket reconnect, after a terminal event, and after resolving a gate.
 *
 * Composes stores exactly like routes/cockpit.ts, and reuses loadPendingHostDuplicates so this is
 * not a fourth hand-rolled copy of "load state, alias index, dismissals".
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
export function registerAiStateRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  /**
   * Each gate's pending list, or empty when its feature is not wired.
   *
   * Fail-quiet per gate rather than for the request as a whole: one unreadable store must not turn
   * the whole answer into a 500, because a 500 here leaves the pill showing whatever stale thing it
   * had — which is the failure mode this endpoint exists to end.
   */
  async function hostDuplicates(caseId: string) {
    const { stateStore, assetOverridesStore, hostDuplicateDismissalStore } = options;
    if (!stateStore || !assetOverridesStore || !hostDuplicateDismissalStore) return [];
    try {
      return await loadPendingHostDuplicates(
        {
          state: stateStore,
          assetOverrides: assetOverridesStore,
          dismissals: hostDuplicateDismissalStore,
          ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
        },
        caseId,
      );
    } catch {
      return [];
    }
  }

  async function presidioPending(caseId: string) {
    try {
      return await new PresidioPendingStore(store).load(caseId);
    } catch {
      return [];
    }
  }

  /** The per-case AI toggle. Defaults to enabled, matching the control store's own default. */
  async function enabled(caseId: string): Promise<boolean> {
    try {
      return (await new AiControlStore(store).load(caseId)).enabled;
    } catch {
      return true;
    }
  }

  app.get("/cases/:id/ai-state", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    try {
      if (!(await store.caseExists(caseId))) {
        return res.status(404).json({ error: `case ${caseId} does not exist` });
      }
      const [dupes, presidio, isEnabled] = await Promise.all([
        hostDuplicates(caseId),
        presidioPending(caseId),
        enabled(caseId),
      ]);
      const state: AiState = deriveAiState({
        // Mirrors server.ts's own hasAiProvider: the explicit flag wins, the pipeline answers
        // otherwise. Without this an install that sets aiConfigured directly would derive "off".
        aiConfigured: options.aiConfigured ?? Boolean(options.pipeline?.hasAiProvider()),
        enabled: isEnabled,
        hostDuplicates: dupes,
        presidioPending: presidio,
        jobs: options.jobManager?.list(caseId) ?? [],
      });
      return res.status(200).json(state);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
