import { randomUUID } from "node:crypto";
import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { buildImportAnonContext } from "../analysis/ai/providerCall.js";
import { anonRevision, assertAnonRevision } from "../analysis/anonRevision.js";
import { AnonControlStore } from "../analysis/anonControl.js";
import { CustomEntitiesStore } from "../analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../analysis/anonDiscovered.js";
import { askJev, type JevBatchResult } from "../analysis/ai/jev/jevClient.js";
import { resolveJevSettings } from "../analysis/ai/jev/jevConfig.js";
import { CONTAINMENT_QUESTIONS } from "../analysis/ai/jev/containmentQuestions.js";
import { RULE_VERSION, classifyAnswers, suggestSteps } from "../analysis/ai/jev/containmentRule.js";
import { buildContainmentState, findingFingerprint } from "../analysis/ai/jev/containmentState.js";
import { containmentDuplicate, type ContainmentAnswer } from "../analysis/playbookContainment.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";
import {
  ContainmentCheckRecords,
  basisLabels,
  registerContainmentCheckPlaybookRoute,
  type ContainmentCheckRecord,
} from "./containmentCheckPlaybook.js";
import type { RouteContext } from "./context.js";

/**
 * The per-finding containment check (#1925) — analyst-pressed, one Jev call per press.
 *
 * POST /cases/:id/findings/:findingId/containment-check asks Jev eleven narrow questions about one
 * finding and the forensic-timeline events it cites (analysis/ai/jev/containmentState.ts), and a
 * fixed rule (containmentRule.ts) turns the answers into suggested containment steps. It reads the
 * FORENSIC TIMELINE ONLY — never the super-timeline — so it is not an exception to the boundary in
 * ARCHITECTURE.md. It writes no investigation state: it records the call's cost and keeps the
 * result in memory, where the add route (containmentCheckPlaybook.ts) reads it. Nothing is run,
 * isolated, blocked or deleted. The check is advice.
 */

/** Shown beside "in progress": the evidence is a snapshot, not a live status. */
const SNAPSHOT_CAVEAT =
  "In progress means still in progress at the end of the collected evidence — it is not a live status.";

const CHECK_RUNNING = "a containment check of this finding is already running — wait for it to finish";

export function registerContainmentCheckRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const casesRoot = () => ctx.store.casesRoot;
  // Per finding, per case incarnation: a double press must not buy the same check twice.
  const running = new CaseKeyedMap<true>(casesRoot);
  const records = new ContainmentCheckRecords(casesRoot);
  // The anonymizer's own stores, over the case files. AppOptions carries none of them — only the
  // pipeline does — so `opts: options` would build no anonymizer and send the finding in clear.
  // These are stateless file readers; the pipeline builds the same three over the same store.
  const anonOpts = {
    anonStore: new AnonControlStore(store),
    customEntitiesStore: new CustomEntitiesStore(store),
    discoveredStore: new DiscoveredEntitiesStore(store),
  };

  app.post("/cases/:id/findings/:findingId/containment-check", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const findingId = req.params.findingId;
    const resolved = resolveJevSettings();
    if (!resolved.settings) return res.status(501).json({ error: resolved.reason });
    const settings = resolved.settings;
    const stateStore = options.stateStore;
    if (!stateStore) return res.status(501).json({ error: "investigation state not configured" });
    // Before the state store is touched, so a typo'd id never creates a case directory (#1549).
    if (!(await store.getCaseMeta(caseId).catch(() => null)))
      return res.status(404).json({ error: "case not found" });
    if (running.has(caseId, findingId)) return res.status(409).json({ error: CHECK_RUNNING });
    running.set(caseId, true, findingId);
    try {
      const state = await stateStore.load(caseId);
      const finding = state.findings.find((f) => f.id === findingId);
      if (!finding) return res.status(404).json({ error: "finding not found" });

      // Masked like every Jev call: the revision is read BEFORE the lists load (#1840).
      const maskedAt = anonRevision(caseId);
      const anon = await buildImportAnonContext({ log: getServerLogger(), opts: anonOpts }, caseId, state);
      const mask = anon ? (text: string) => anon.anon.apply(text) : (text: string) => text;
      const { state: jevState, coverage } = buildContainmentState(finding, state, mask);

      let result: JevBatchResult;
      let answers: ContainmentAnswer[];
      try {
        result = await askJev(
          {
            baseUrl: settings.baseUrl,
            model: settings.model,
            apiKey: settings.apiKey,
            timeoutMs: settings.timeoutMs,
            beforeSend: () => assertAnonRevision(caseId, maskedAt, "the containment check"),
          },
          jevState,
          CONTAINMENT_QUESTIONS,
        );
        answers = classifyAnswers(result.answers);
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        getServerLogger().warn(`[jev] ${caseId}: containment check failed — ${detail}`, { caseId });
        return res.status(502).json({ error: `Jev containment check failed: ${detail}` });
      }

      await options.aiCostStore?.record(caseId, "other", "jev", result.model, {
        inputTokens: result.usage.inputTokens,
        outputTokens: result.usage.outputTokens,
        ...(result.usage.costUSD !== undefined ? { costUSD: result.usage.costUSD } : {}),
      });

      const steps = suggestSteps(answers);
      const record: ContainmentCheckRecord = {
        checkId: randomUUID(),
        rule: RULE_VERSION,
        model: result.model,
        checkedAt: new Date().toISOString(),
        findingId,
        fingerprint: findingFingerprint(finding),
        answers,
        steps,
        inProgressCaveat: answers.some((a) => a.id === "in_progress" && a.verdict === "yes"),
      };
      records.remember(caseId, record);

      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "ai",
        action: "jev-containment-check",
        detail:
          `containment check on finding ${findingId}: ${steps.length} step(s) suggested from ` +
          `${coverage.sent} of ${coverage.cited} cited event(s) — nothing was run`,
        targetType: "finding",
        targetId: findingId,
      });

      const tasks: PlaybookTask[] = options.playbookStore ? await options.playbookStore.load(caseId) : [];
      const inPlaybook = (stepId: string): PlaybookTask | undefined =>
        tasks.find((t) =>
          containmentDuplicate(t, { relatedFindingId: findingId, containmentCheck: { stepId } }),
        );
      return res.json({
        checkId: record.checkId,
        model: record.model,
        checkedAt: record.checkedAt,
        answers,
        steps: steps.map((s) => {
          const task = inPlaybook(s.id);
          return {
            ...s,
            basisLabels: basisLabels(s.basis),
            inPlaybook: !!task,
            ...(task?.shortId ? { taskShortId: task.shortId } : {}),
          };
        }),
        coverage,
        snapshotCaveat: SNAPSHOT_CAVEAT,
        usage: result.usage,
      });
    } finally {
      running.delete(caseId, findingId);
    }
  });

  registerContainmentCheckPlaybookRoute(app, ctx, records);
}
