import { applyIncidentTypeToState } from "../analysis/incidentTypes.js";
import { buildInitialNextSteps, buildInitialQuestions } from "../analysis/templateStore.js";
import { applyHuntDefaults } from "../analysis/huntCase.js";
import type { RouteContext } from "./context.js";
import { linkNewCase } from "./serverSets.js";
import { keepWatsonSteps } from "../analysis/timeline/watsonItems.js";

/**
 * #2772: the follow-up steps of POST /cases, run AFTER the case folder is claimed. Each step is
 * caught on its own: the case is real once claimed, so a failure here must be reported on the 201
 * (`seedError`) rather than answered as a 500 that makes the analyst retry into "already exists".
 */
export interface CreationSeedInput {
  readonly templateId?: unknown;
  readonly incidentTypeId?: unknown;
  readonly serverSetId?: string;
}

interface SeedFailure {
  readonly part: string;
  readonly message: string;
}

async function seedTemplate(ctx: RouteContext, caseId: string, templateId: unknown): Promise<void> {
  const { templateStore, stateStore } = ctx.options;
  if (!templateId || !templateStore || !stateStore) return;
  const template = await templateStore.get(String(templateId));
  if (!template || !(template.initialKeyQuestions.length || template.initialNextSteps?.length)) return;
  const state = await stateStore.load(caseId);
  if (template.initialKeyQuestions.length) state.keyQuestions = buildInitialQuestions(template);
  const seeded = template.initialNextSteps?.length ? buildInitialNextSteps(template) : null;
  if (seeded) state.nextSteps = keepWatsonSteps(seeded, state.nextSteps); // Watson's are kept
  state.updatedAt = new Date().toISOString();
  await stateStore.save(state);
}

// Incident-type auto-configuration (#236): apply the picked type's key questions, next steps and
// findings seeds, persist the chosen-type record (the synthesis prompt reads its hint), and give a
// hunt type its default report (#2670). Runs AFTER the template and MERGES: an API caller may send
// both, and discarding the questions the template just seeded would lose what it asked for.
async function seedIncidentType(ctx: RouteContext, caseId: string, incidentTypeId: unknown): Promise<void> {
  const { incidentTypeStore, stateStore, reportTemplateControlStore } = ctx.options;
  if (!incidentTypeId || !incidentTypeStore || !stateStore) return;
  const type = await incidentTypeStore.get(String(incidentTypeId));
  if (!type) return;
  const state = await stateStore.load(caseId);
  const { state: next } = applyIncidentTypeToState(state, type);
  await stateStore.save(next);
  await incidentTypeStore.saveRecord(caseId, String(incidentTypeId));
  await applyHuntDefaults(reportTemplateControlStore, caseId, type);
}

async function attempt(part: string, run: () => Promise<unknown>): Promise<SeedFailure | null> {
  try {
    await run();
    return null;
  } catch (err) {
    return { part, message: (err as Error)?.message ?? String(err) };
  }
}

/** The analyst-facing sentence for the 201 answer, or undefined when every step applied. */
export function describeSeedFailures(failures: readonly SeedFailure[]): string | undefined {
  if (!failures.length) return undefined;
  const parts = failures.map((f) => `${f.part} (${f.message})`).join(", ");
  return `the case was created, but these were not applied: ${parts}`;
}

export async function applyCreationSeeds(
  ctx: RouteContext,
  caseId: string,
  input: CreationSeedInput,
): Promise<string | undefined> {
  const failures: SeedFailure[] = [];
  const record = (f: SeedFailure | null): void => {
    if (f) failures.push(f);
  };
  if (!linkNewCase(ctx, caseId, { setId: input.serverSetId })) {
    record({ part: "server set", message: "could not link the case — pick a set in Settings" });
  }
  record(await attempt("template", () => seedTemplate(ctx, caseId, input.templateId)));
  record(await attempt("incident type", () => seedIncidentType(ctx, caseId, input.incidentTypeId)));
  // The watcher re-ensures the drop folder on its next poll, so this one is a heads-up only.
  record(await attempt("drop folder", () => ctx.ensureDropFolders(caseId)));
  for (const f of failures) {
    ctx.serverLogger.error(`[case-create] case ${caseId}: ${f.part} not applied — ${f.message}`);
  }
  return describeSeedFailures(failures);
}
