import { randomUUID } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { StateLock } from "../analysis/stateLock.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import {
  REPORT_WORKFLOW_ACTIONS,
  REPORT_WORKFLOW_STATUSES,
  reportActorSchema,
  reportAnnotationInputSchema,
  type ReportActor,
  type ReportAnnotationInput,
  type ReportWorkflow,
  type ReportWorkflowAction,
} from "./reportWorkflowTypes.js";

const workflowSchema = z.object({
  versionId: z.string().min(1),
  status: z.enum(REPORT_WORKFLOW_STATUSES),
  createdBy: reportActorSchema,
  assignedReviewer: reportActorSchema.optional(),
  annotations: z.array(
    reportAnnotationInputSchema.extend({
      id: z.string().min(1),
      authorId: z.string().min(1),
      authorDisplayName: z.string().min(1),
      createdAt: z.string().datetime(),
      resolvedAt: z.string().datetime().optional(),
      resolvedById: z.string().optional(),
      resolvedByDisplayName: z.string().optional(),
      resolution: z.string().optional(),
    }),
  ),
  approvals: z.array(
    z.object({
      actorId: z.string().min(1),
      actorDisplayName: z.string().min(1),
      actorKind: z.enum(["local", "oidc", "service", "solo"]),
      at: z.string().datetime(),
      independent: z.boolean(),
      note: z.string(),
    }),
  ),
  history: z.array(
    z.object({
      at: z.string().datetime(),
      action: z.enum(REPORT_WORKFLOW_ACTIONS),
      actorId: z.string().min(1),
      actorDisplayName: z.string().min(1),
      detail: z.string(),
    }),
  ),
  releaseId: z.string().optional(),
});

function validVersionId(value: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(value);
}

function defaultWorkflow(versionId: string, actor: ReportActor): ReportWorkflow {
  const at = new Date().toISOString();
  const createdBy = reportActorSchema.parse(actor);
  return {
    versionId,
    status: "draft",
    createdBy,
    assignedReviewer: undefined,
    annotations: [],
    approvals: [],
    history: [event("created", createdBy, at, "report version created as a draft")],
  };
}

function event(
  action: ReportWorkflowAction,
  actor: ReportActor,
  at: string,
  detail: string,
): ReportWorkflow["history"][number] {
  return {
    at,
    action,
    actorId: actor.id,
    actorDisplayName: actor.displayName,
    detail,
  };
}

function cleanNote(value: string, field: string): string {
  const note = value.trim();
  if (!note || note.length > 4_000) throw new Error(`${field} must be 1-4000 characters`);
  return note;
}

function requireStatus(workflow: ReportWorkflow, expected: ReportWorkflow["status"]): void {
  if (workflow.status !== expected) {
    throw new Error(`report must be ${expected}; current status is ${workflow.status}`);
  }
}

function requireAssignedReviewer(workflow: ReportWorkflow, actor: ReportActor): void {
  if (!workflow.assignedReviewer || workflow.assignedReviewer.id !== actor.id) {
    throw new Error("only the assigned reviewer can perform this action");
  }
}

export class ReportWorkflowStore {
  private readonly lock = new StateLock();

  constructor(private readonly cases: CaseStore) {}

  private dir(caseId: string): string {
    return join(this.cases.stateDir(caseId), "report-workflows");
  }

  private path(caseId: string, versionId: string): string {
    if (!validVersionId(versionId)) throw new Error("invalid report version id");
    return join(this.dir(caseId), `${versionId}.json`);
  }

  async load(caseId: string, versionId: string, createdBy?: ReportActor): Promise<ReportWorkflow> {
    try {
      return workflowSchema.parse(JSON.parse(await readFile(this.path(caseId, versionId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return defaultWorkflow(
          versionId,
          createdBy ?? { id: "solo", displayName: "Solo investigator", kind: "solo" },
        );
      }
      throw err;
    }
  }

  private async save(caseId: string, workflow: ReportWorkflow): Promise<ReportWorkflow> {
    const validated = workflowSchema.parse(workflow);
    await mkdir(this.dir(caseId), { recursive: true });
    await atomicWrite(this.path(caseId, workflow.versionId), JSON.stringify(validated, null, 2));
    return validated;
  }

  private mutate(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    change: (workflow: ReportWorkflow) => ReportWorkflow,
  ): Promise<ReportWorkflow> {
    return this.lock.runExclusive(caseId, async () => {
      const current = await this.load(caseId, versionId, actor);
      return this.save(caseId, change(current));
    });
  }

  submit(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    reviewer: ReportActor,
  ): Promise<ReportWorkflow> {
    return this.mutate(caseId, versionId, actor, (current) => {
      requireStatus(current, "draft");
      if (reviewer.kind === "service") throw new Error("a service identity cannot review a report");
      if (actor.id === reviewer.id) throw new Error("the reviewer must be a different person");
      const at = new Date().toISOString();
      return {
        ...current,
        status: "peer-review",
        assignedReviewer: reviewer,
        history: [
          ...current.history,
          event("submitted-for-review", actor, at, `assigned reviewer ${reviewer.displayName}`),
        ],
      };
    });
  }

  addAnnotation(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    input: ReportAnnotationInput,
  ): Promise<ReportWorkflow> {
    const annotation = reportAnnotationInputSchema.parse(input);
    return this.mutate(caseId, versionId, actor, (current) => {
      requireStatus(current, "peer-review");
      requireAssignedReviewer(current, actor);
      if (actor.kind === "service") throw new Error("a service identity cannot review a report");
      const at = new Date().toISOString();
      return {
        ...current,
        annotations: [
          ...current.annotations,
          {
            ...annotation,
            id: randomUUID(),
            authorId: actor.id,
            authorDisplayName: actor.displayName,
            createdAt: at,
          },
        ],
        history: [
          ...current.history,
          event("annotation-added", actor, at, `${annotation.targetType}:${annotation.targetId}`),
        ],
      };
    });
  }

  resolveAnnotation(
    caseId: string,
    versionId: string,
    annotationId: string,
    actor: ReportActor,
    resolution: string,
  ): Promise<ReportWorkflow> {
    const cleanResolution = cleanNote(resolution, "resolution");
    return this.mutate(caseId, versionId, actor, (current) => {
      if (current.status === "approved" || current.status === "released") {
        throw new Error("approved or released review records cannot be changed");
      }
      const target = current.annotations.find((item) => item.id === annotationId);
      if (!target) throw new Error("annotation not found");
      if (target.resolvedAt) throw new Error("annotation is already resolved");
      const at = new Date().toISOString();
      return {
        ...current,
        annotations: current.annotations.map((item) =>
          item.id === annotationId
            ? {
                ...item,
                resolvedAt: at,
                resolvedById: actor.id,
                resolvedByDisplayName: actor.displayName,
                resolution: cleanResolution,
              }
            : item,
        ),
        history: [
          ...current.history,
          event("annotation-resolved", actor, at, `${target.targetType}:${target.targetId}`),
        ],
      };
    });
  }

  requestChanges(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    reason: string,
  ): Promise<ReportWorkflow> {
    const detail = cleanNote(reason, "reason");
    return this.mutate(caseId, versionId, actor, (current) => {
      requireStatus(current, "peer-review");
      requireAssignedReviewer(current, actor);
      if (actor.kind === "service") throw new Error("a service identity cannot review a report");
      const at = new Date().toISOString();
      return {
        ...current,
        status: "draft",
        history: [...current.history, event("changes-requested", actor, at, detail)],
      };
    });
  }

  approve(caseId: string, versionId: string, actor: ReportActor, note: string): Promise<ReportWorkflow> {
    const clean = cleanNote(note, "approval note");
    return this.mutate(caseId, versionId, actor, (current) => {
      requireStatus(current, "peer-review");
      requireAssignedReviewer(current, actor);
      if (actor.kind === "service") throw new Error("a service identity cannot approve a report");
      const unresolved = current.annotations.filter(
        (item) => item.category === "uncertainty" && item.impact === "high" && !item.resolvedAt,
      );
      if (unresolved.length > 0) throw new Error("unresolved high-impact uncertainty blocks approval");
      const at = new Date().toISOString();
      return {
        ...current,
        status: "approved",
        approvals: [
          ...current.approvals,
          {
            actorId: actor.id,
            actorDisplayName: actor.displayName,
            actorKind: actor.kind,
            at,
            independent: actor.id !== current.createdBy.id,
            note: clean,
          },
        ],
        history: [...current.history, event("approved", actor, at, clean)],
      };
    });
  }

  selfApprove(caseId: string, versionId: string, actor: ReportActor, note: string): Promise<ReportWorkflow> {
    const clean = cleanNote(note, "self-review note");
    return this.mutate(caseId, versionId, actor, (current) => {
      requireStatus(current, "draft");
      if (actor.kind === "service") throw new Error("a service identity cannot approve a report");
      const at = new Date().toISOString();
      return {
        ...current,
        status: "approved",
        approvals: [
          ...current.approvals,
          {
            actorId: actor.id,
            actorDisplayName: actor.displayName,
            actorKind: actor.kind,
            at,
            independent: false,
            note: clean,
          },
        ],
        history: [...current.history, event("self-approved", actor, at, clean)],
      };
    });
  }

  markReleased(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    releaseId: string,
  ): Promise<ReportWorkflow> {
    return this.mutate(caseId, versionId, actor, (current) => {
      requireStatus(current, "approved");
      if (actor.kind === "service") throw new Error("a service identity cannot release a report");
      const at = new Date().toISOString();
      return {
        ...current,
        status: "released",
        releaseId,
        history: [...current.history, event("released", actor, at, releaseId)],
      };
    });
  }
}
