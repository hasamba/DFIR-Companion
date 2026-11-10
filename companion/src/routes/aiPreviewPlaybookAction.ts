import { noteAiPreview } from "../analysis/ai/aiPreviewScope.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import { EMPTY_PERSISTED_HUNTS, planPlaybookHuntRun } from "../analysis/playbookHunt.js";
import type { RouteAiPreviewAction } from "./aiPreviewRouteAction.js";
import type { RouteContext } from "./context.js";

/**
 * "Preview what the AI will see" for playbook hunts (#2515).
 *
 * The real route (routes/playbookHunts.ts) does three things before it asks: it re-syncs the playbook
 * from the analysis (a write when tasks changed), refreshes the case's Velociraptor fleet inventory (an
 * external call and a write) and fetches the server's artifact list (an external call). A preview may
 * do none of them. So it:
 * - derives the playbook the same way, saving nothing (`previewPlaybook`) — exact;
 * - builds from the LAST STORED fleet inventory and says so, with its time — the real run refreshes
 *   the fleet first, so a host enrolled since then can resolve differently;
 * - uses the artifact list this server already fetched, if any, and says when; else an empty list.
 * The task selection (incremental / force / one task) is the route's own helper, and the prompt is
 * built by the real `suggestPlaybookHunts`, stopped at the AI-call gate.
 */
interface PlaybookPreviewParams {
  readonly force: boolean;
  readonly taskId: string;
  readonly excludeVql: string;
}

const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
/** A stored time as "2026-11-10 07:45 UTC"; a value that does not parse is shown as it is. */
function when(at: string | number): string {
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? String(at) : `${d.toISOString().replace("T", " ").slice(0, 16)} UTC`;
}

/** The tasks one press would send, and the VQL a single-task regenerate asks the model to avoid. */
async function tasksToSend(
  ctx: RouteContext,
  caseId: string,
  tasks: PlaybookTask[],
  p: PlaybookPreviewParams,
): Promise<{ send: PlaybookTask[]; excludeVql?: string; regen: boolean }> {
  const persisted = ctx.options.playbookHuntStore
    ? await ctx.options.playbookHuntStore.load(caseId)
    : { ...EMPTY_PERSISTED_HUNTS };
  if (!p.taskId) return { send: planPlaybookHuntRun(persisted, tasks, p.force).pending, regen: false };
  const task = tasks.find((t) => t.id === p.taskId);
  if (!task) throw new Error(`playbook task ${p.taskId} not found`);
  // The panel's regenerate sends the shown suggestion's VQL unless the analyst typed one.
  const stored = (persisted.suggestions ?? []).find((s) => s.taskId === p.taskId)?.vql;
  return { send: [task], excludeVql: p.excludeVql || stored || undefined, regen: true };
}

/** The artifact names the real run would fetch — from what this server already holds, never a new call. */
async function artifactNames(velo: VeloClient | undefined): Promise<string[]> {
  if (!velo) return [];
  const cached =
    typeof velo.cachedClientArtifacts === "function" ? await velo.cachedClientArtifacts() : undefined;
  if (!cached) {
    noteAiPreview(
      "No Velociraptor artifact list has been fetched since the server started, so the list in this preview " +
        "is empty. The real run fetches the server's artifact list first.",
    );
    return [];
  }
  noteAiPreview(
    `The Velociraptor artifact list is the one fetched at ${when(cached.at)}. The real run fetches it again first.`,
  );
  return cached.rows.map((a) => a.name);
}

type VeloClient = NonNullable<
  Extract<ReturnType<RouteContext["serverClients"]["forCase"]>, { ok: true }>["servers"]["velociraptor"]
>;

/** Say which fleet inventory the prompt was built from: the stored one, never a refresh. */
async function noteInventory(ctx: RouteContext, caseId: string): Promise<void> {
  const inventory = ctx.options.velociraptorClientStore
    ? await ctx.options.velociraptorClientStore.load(caseId)
    : { updatedAt: "", clients: [] };
  noteAiPreview(
    inventory.updatedAt
      ? `Built from the Velociraptor fleet inventory stored at ${when(inventory.updatedAt)} ` +
          `(${inventory.clients.length} client(s)). The real run refreshes the fleet first, so a host ` +
          `enrolled since then can be named differently.`
      : "No Velociraptor fleet inventory is stored for this case yet. The real run fetches it first, so the " +
          "host names it resolves may differ from this preview.",
  );
}

async function previewPlaybookHunts(ctx: RouteContext, caseId: string, p: PlaybookPreviewParams) {
  const pipeline = ctx.options.pipeline!;
  const tasks = await ctx.previewPlaybook(caseId);
  const { send, excludeVql, regen } = await tasksToSend(ctx, caseId, tasks, p);
  if (!send.length) return; // nothing new or changed: the real press asks nothing either
  const servers = ctx.serverClients.forCase(caseId);
  const velo = servers.ok ? servers.servers.velociraptor : undefined;
  if (velo) await noteInventory(ctx, caseId);
  else
    noteAiPreview(
      "This case has no Velociraptor server, so the real run refreshes no fleet and fetches no artifact list either.",
    );
  const names = await artifactNames(velo);
  return regen
    ? pipeline.suggestPlaybookHunts(caseId, send, names, { excludeVql })
    : pipeline.suggestPlaybookHunts(caseId, send, names);
}

export const PLAYBOOK_HUNTS_PREVIEW: RouteAiPreviewAction = {
  label: "Playbook hunt suggestions",
  needs: "ai",
  prepare: async (ctx, caseId, params) => {
    if (!ctx.options.playbookStore || !ctx.options.stateStore) return "playbook not configured";
    const p: PlaybookPreviewParams = {
      force: params.force === true || params.force === "true",
      taskId: str(params.taskId),
      excludeVql: str(params.excludeVql),
    };
    return () => previewPlaybookHunts(ctx, caseId, p);
  },
};
