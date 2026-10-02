import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { playbookTaskEvent, type NotificationEvent } from "../analysis/notifications.js";
import type { NewPlaybookTask } from "../analysis/playbookStore.js";
import { containmentDuplicate, type ContainmentAnswer } from "../analysis/playbookContainment.js";
import { QUESTION_LABELS, type ContainmentQuestionId } from "../analysis/ai/jev/containmentQuestions.js";
import type { SuggestedStep } from "../analysis/ai/jev/containmentRule.js";
import { findingFingerprint } from "../analysis/ai/jev/containmentState.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";
import type { RouteContext } from "./context.js";

/**
 * The write half of the per-finding containment check (#1925): POST
 * /cases/:id/findings/:findingId/containment-check/playbook adds the steps the analyst ticked as
 * Playbook tasks. It makes no AI call and is not on the AI rate limiter.
 *
 * The browser sends ids only — the check id and the step ids. The title, priority, model, answers
 * and confidence all come from the server's own record of that check, so a forged body cannot put
 * words in Jev's mouth (the #1578 precedent). The records live in memory: after a restart the
 * analyst runs the check again.
 */

export interface ContainmentCheckRecord {
  readonly checkId: string;
  readonly rule: string;
  readonly model: string;
  readonly checkedAt: string;
  readonly findingId: string;
  readonly fingerprint: string;
  readonly answers: readonly ContainmentAnswer[];
  readonly steps: readonly SuggestedStep[];
  readonly inProgressCaveat: boolean;
}

/** Checks kept per finding, so a second tab's check does not invalidate the first tab's. */
const KEEP_PER_FINDING = 5;
/** More step ids than the rule can ever suggest is a malformed body, not a request. */
const MAX_STEPS = 20;

/** The recent check records of each finding, per case incarnation, newest last. */
export class ContainmentCheckRecords {
  private readonly byFinding: CaseKeyedMap<readonly ContainmentCheckRecord[]>;

  constructor(casesRoot: () => string) {
    this.byFinding = new CaseKeyedMap(casesRoot);
  }

  remember(caseId: string, record: ContainmentCheckRecord): void {
    const kept = this.byFinding.get(caseId, record.findingId) ?? [];
    this.byFinding.set(caseId, [...kept, record].slice(-KEEP_PER_FINDING), record.findingId);
  }

  find(caseId: string, findingId: string, checkId: string): ContainmentCheckRecord | undefined {
    return this.byFinding.get(caseId, findingId)?.find((r) => r.checkId === checkId);
  }
}

/** The fixed labels of the answers a step rests on. */
export function basisLabels(basis: readonly string[]): string[] {
  return basis.map((id) => QUESTION_LABELS[id as ContainmentQuestionId] ?? id);
}

function taskInput(record: ContainmentCheckRecord, step: SuggestedStep): NewPlaybookTask {
  return {
    title: step.title,
    description:
      "Suggested by the Jev containment check — advice only, nothing was run. " +
      `Because: ${basisLabels(step.basis).join("; ")}.`,
    priority: step.priority,
    relatedFindingId: record.findingId,
    containmentCheck: {
      kind: "jev-containment",
      rule: record.rule,
      model: record.model,
      checkedAt: record.checkedAt,
      findingId: record.findingId,
      stepId: step.id,
      basis: [...step.basis],
      answers: record.answers.map((a) => ({ ...a })),
      inProgressCaveat: record.inProgressCaveat,
    },
  };
}

const RERUN = (error: string) => ({ error, rerun: true });

function readBody(body: unknown): { checkId: string; steps: string[] } | null {
  const b = (body ?? {}) as { checkId?: unknown; steps?: unknown };
  if (typeof b.checkId !== "string" || !b.checkId) return null;
  if (!Array.isArray(b.steps) || !b.steps.length || b.steps.length > MAX_STEPS) return null;
  if (!b.steps.every((s): s is string => typeof s === "string" && s.length > 0)) return null;
  return { checkId: b.checkId, steps: [...new Set(b.steps)] };
}

export function registerContainmentCheckPlaybookRoute(
  app: Express,
  ctx: RouteContext,
  records: ContainmentCheckRecords,
): void {
  const { options } = ctx;

  // Same side channel as POST /cases/:id/playbook (routes/playbookHunts.ts): best-effort.
  const dispatchNotify = (event: NotificationEvent): void => {
    if (!options.notifier) return;
    const url = options.dashboardBaseUrl
      ? `${options.dashboardBaseUrl.replace(/\/+$/, "")}/dashboard?caseId=${encodeURIComponent(event.caseId)}`
      : undefined;
    options.notifier
      .dispatch(event.url || !url ? event : { ...event, url })
      .catch((err) => ctx.serverLogger.info(`[notify] dispatch error: ${(err as Error).message}`));
  };

  app.post(
    "/cases/:id/findings/:findingId/containment-check/playbook",
    async (req: Request, res: Response) => {
      const caseId = req.params.id;
      const findingId = req.params.findingId;
      if (!options.playbookStore || !options.stateStore)
        return res.status(501).json({ error: "playbook not configured" });
      const body = readBody(req.body);
      if (!body) return res.status(400).json({ error: "send a checkId and a non-empty list of step ids" });

      const record = records.find(caseId, findingId, body.checkId);
      if (!record) return res.status(409).json(RERUN("This check result has expired — run the check again."));
      const finding = (await options.stateStore.load(caseId)).findings.find((f) => f.id === findingId);
      if (!finding || findingFingerprint(finding) !== record.fingerprint)
        return res.status(409).json(RERUN("The finding changed since the check ran — run the check again."));

      const byId = new Map(record.steps.map((s) => [s.id as string, s]));
      const unknown = body.steps.filter((id) => !byId.has(id));
      if (unknown.length)
        return res.status(400).json({ error: `not a step this check suggested: ${unknown.join(", ")}` });

      const inputs = body.steps.map((id) => taskInput(record, byId.get(id)!));
      const { added, skipped } = await options.playbookStore.addMany(caseId, inputs, containmentDuplicate);
      if (added.length) options.onPlaybook?.(caseId);
      const at = new Date().toISOString();
      for (const task of added) {
        dispatchNotify(playbookTaskEvent(caseId, task, "added", at));
        void logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "playbook",
          action: "task-added",
          detail: `task added from a containment check: "${task.title}"`,
          targetType: "playbook-task",
          targetId: task.id,
        });
      }
      return res.json({
        added,
        alreadyInPlaybook: skipped.map((s) => s.containmentCheck?.stepId).filter((s): s is string => !!s),
      });
    },
  );
}
