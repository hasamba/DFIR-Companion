import { z } from "zod";

export const REPORT_WORKFLOW_STATUSES = ["draft", "peer-review", "approved", "released"] as const;
export type ReportWorkflowStatus = (typeof REPORT_WORKFLOW_STATUSES)[number];

export const reportActorSchema = z.object({
  id: z.string().min(1).max(200),
  displayName: z.string().min(1).max(200),
  kind: z.enum(["local", "oidc", "service", "solo"]),
});
export type ReportActor = z.infer<typeof reportActorSchema>;

export const REPORT_ANNOTATION_TARGETS = ["claim", "finding", "evidence"] as const;
export const REPORT_ANNOTATION_CATEGORIES = ["comment", "uncertainty"] as const;
export const REPORT_ANNOTATION_IMPACTS = ["low", "medium", "high"] as const;

export const reportAnnotationInputSchema = z.object({
  targetType: z.enum(REPORT_ANNOTATION_TARGETS),
  targetId: z.string().trim().min(1).max(240),
  category: z.enum(REPORT_ANNOTATION_CATEGORIES),
  impact: z.enum(REPORT_ANNOTATION_IMPACTS),
  message: z.string().trim().min(1).max(4_000),
});
export type ReportAnnotationInput = z.infer<typeof reportAnnotationInputSchema>;

export interface ReportAnnotation extends ReportAnnotationInput {
  id: string;
  authorId: string;
  authorDisplayName: string;
  createdAt: string;
  resolvedAt?: string;
  resolvedById?: string;
  resolvedByDisplayName?: string;
  resolution?: string;
}

export interface ReportApproval {
  actorId: string;
  actorDisplayName: string;
  actorKind: ReportActor["kind"];
  at: string;
  independent: boolean;
  note: string;
}

export const REPORT_WORKFLOW_ACTIONS = [
  "created",
  "submitted-for-review",
  "annotation-added",
  "annotation-resolved",
  "changes-requested",
  "self-approved",
  "approved",
  "released",
] as const;
export type ReportWorkflowAction = (typeof REPORT_WORKFLOW_ACTIONS)[number];

export interface ReportWorkflowEvent {
  at: string;
  action: ReportWorkflowAction;
  actorId: string;
  actorDisplayName: string;
  detail: string;
}

export interface ReportWorkflow {
  versionId: string;
  status: ReportWorkflowStatus;
  createdBy: ReportActor;
  assignedReviewer?: ReportActor;
  annotations: ReportAnnotation[];
  approvals: ReportApproval[];
  history: ReportWorkflowEvent[];
  releaseId?: string;
}
