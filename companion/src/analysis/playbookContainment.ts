import { z } from "zod";

// Attribution carried by a Playbook task that the analyst added from a Jev containment check
// (#1925). It records which rule and which model suggested the step, and the answers the step
// rests on, so the report can say where the task came from. Every string here comes from the
// server's own check record and fixed tables, never from the browser.

export const containmentAnswerSchema = z.object({
  id: z.string(),
  label: z.string(),
  kind: z.enum(["yesno", "choice"]),
  value: z.number(),
  verdict: z.string(),
  checkManually: z.boolean(),
});

export const containmentAttributionSchema = z.object({
  kind: z.literal("jev-containment"),
  rule: z.string(),
  model: z.string(),
  checkedAt: z.string(),
  findingId: z.string(),
  stepId: z.string(),
  basis: z.array(z.string()),
  answers: z.array(containmentAnswerSchema),
  inProgressCaveat: z.boolean(),
});

export type ContainmentAnswer = z.infer<typeof containmentAnswerSchema>;
export type ContainmentAttribution = z.infer<typeof containmentAttributionSchema>;

interface ContainmentKeyed {
  relatedFindingId?: string;
  containmentCheck?: { stepId: string };
}

// The dedup key for "Add to Playbook": one task per (finding, step), whatever its status. A
// skipped task means the analyst already decided, so the step is not added again.
export function containmentDuplicate(existing: ContainmentKeyed, input: ContainmentKeyed): boolean {
  return (
    !!existing.containmentCheck &&
    !!input.containmentCheck &&
    existing.relatedFindingId === input.relatedFindingId &&
    existing.containmentCheck.stepId === input.containmentCheck.stepId
  );
}
