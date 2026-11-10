import type { RouteContext } from "./context.js";

/**
 * A "Preview what the AI will see" action that needs the route's own context (#2515): the import-time
 * extraction reads (they take the chosen file), playbook hunts and the two decision-model requests.
 * The 21 pipeline actions keep their own shape in aiPreviewActions.ts.
 */
export interface RouteAiPreviewAction {
  readonly label: string;
  /** Shown with the result when the action asks more than once. */
  readonly multiRequest?: string;
  /** "jev": needs the decision model configured; "ai": needs the synthesis provider. */
  readonly needs: "ai" | "jev";
  /** Validates params only — every case read happens inside the returned run. */
  prepare(
    ctx: RouteContext,
    caseId: string,
    params: Record<string, unknown>,
  ): Promise<(() => Promise<unknown>) | string>;
}
