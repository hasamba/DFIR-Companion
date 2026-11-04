import { warnLine } from "../logging/serverLogger.js";
import type { IrisClient } from "../integrations/iris/irisClient.js";
import type { TimesketchClient } from "../integrations/timesketch/timesketchClient.js";
import type { VelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";
import type { ServerSetStore } from "../integrations/serverSets/serverSetStore.js";
import { logSafeError } from "../integrations/serverSets/logSafeError.js";
import {
  incompleteTools,
  TOOL_LABEL,
  type CaseServers,
  type InputServers,
  type IrisSettings,
  type ResolveResult,
  type ServerClients,
  type ServerSet,
  type TimesketchSettings,
  type ToolName,
  type VelociraptorSettings,
} from "../integrations/serverSets/types.js";
import {
  buildIrisClientFrom,
  buildTimesketchClientFrom,
  buildVelociraptorClientFrom,
  irisPushOptionsFrom,
  timesketchPushOptionsFrom,
} from "./integrationClients.js";

export interface ServerClientBuilders {
  iris: (s: IrisSettings) => IrisClient;
  timesketch: (s: TimesketchSettings) => TimesketchClient;
  velociraptor: (s: VelociraptorSettings) => VelociraptorClient | undefined;
}

const fail = (error: string): ResolveResult => ({ ok: false, status: 409, error });
const NO_LINK = "This case has no server set. Choose one in the case header.";
const DANGLING = "This case's server set was deleted. Choose another in the case header.";
const NO_DEFAULT = "No default server set. Choose one in Settings → Server sets.";
const UNREADABLE = "Server sets cannot be read. Check the server log.";

// Stand-in for tests that build the app without a server-set store: every lookup is an error.
export const unavailableServerClients: ServerClients = {
  forCase: () => fail("Server sets are not available."),
  forDefault: () => fail("Server sets are not available."),
  forSet: () => fail("Server sets are not available."),
  forInput: (set) => ({ servers: { setId: set.id, setName: set.name }, errors: {} }),
  invalidate: () => undefined,
};

// Resolves a case to the clients of the one set it links to. There is no fallback: no link, a
// deleted set or an incomplete tool is an error. Only forDefault() reads the default id.
export function createServerClients(
  store: ServerSetStore,
  env: NodeJS.ProcessEnv,
  builders?: Partial<ServerClientBuilders>,
): ServerClients {
  const build: ServerClientBuilders = {
    iris: buildIrisClientFrom,
    timesketch: buildTimesketchClientFrom,
    velociraptor: (s) => buildVelociraptorClientFrom(s, env),
    ...builders,
  };
  const cache = new Map<string, { revision: number; servers: CaseServers }>();

  function resolveSet(set: ServerSet): ResolveResult {
    const hit = cache.get(set.id);
    if (hit && hit.revision === set.revision) return { ok: true, servers: hit.servers };
    cache.delete(set.id);
    const bad = incompleteTools(set)[0];
    if (bad) {
      return fail(
        `Server set '${set.name}' has incomplete ${TOOL_LABEL[bad]} settings. Fix it in Settings → Server sets.`,
      );
    }
    const servers = buildServers(set, build);
    cache.set(set.id, { revision: set.revision, servers });
    return { ok: true, servers };
  }

  // The last error logged per lookup key. Background loops resolve on every tick, so a broken store
  // logs once, then stays quiet until a resolve for that key succeeds.
  const logged = new Map<string, string>();
  function guarded(key: string, read: () => ResolveResult): ResolveResult {
    try {
      const r = read();
      if (r.ok) logged.delete(key);
      return r;
    } catch (err) {
      // Decrypt errors carry no plaintext; a parse error quotes the file, so only its name. Never returned.
      const msg = logSafeError(err);
      if (logged.get(key) !== msg) warnLine(`[server-sets] ${msg}`);
      logged.set(key, msg);
      return fail(UNREADABLE);
    }
  }

  function bySetId(setId: string, missing: string): ResolveResult {
    const set = store.get(setId);
    return set ? resolveSet(set) : fail(missing);
  }

  return {
    forCase: (caseId) =>
      guarded(`case:${caseId}`, () => {
        const setId = store.caseSetId(caseId);
        return setId ? bySetId(setId, DANGLING) : fail(NO_LINK);
      }),
    forDefault: () =>
      guarded("default", () => {
        const id = store.defaultId();
        return id ? bySetId(id, NO_DEFAULT) : fail(NO_DEFAULT);
      }),
    forSet: (setId) => guarded(`set:${setId}`, () => bySetId(setId, "Server set not found.")),
    forInput: (set) => buildInputServers(set, build),
    invalidate: (setId) => {
      if (setId === undefined) cache.clear();
      else cache.delete(setId);
    },
  };
}

// A tool the set leaves empty stays undefined. Incomplete tools were refused before this point.
function buildServers(set: ServerSet, build: ServerClientBuilders): CaseServers {
  const out: CaseServers = { setId: set.id, setName: set.name };
  const i = set.iris;
  if (i?.url && i.apiKey) {
    out.iris = build.iris(i);
    out.irisPush = irisPushOptionsFrom(i);
  }
  const t = set.timesketch;
  if (t?.url && t.user && t.password) {
    out.timesketch = build.timesketch(t);
    out.timesketchPush = timesketchPushOptionsFrom(t);
  }
  const v = set.velociraptor;
  if (v?.apiConfigPath) out.velociraptor = build.velociraptor(v);
  return out;
}

// Typed editor values: each tool is built on its own, so an incomplete tool or a builder that throws
// costs that tool only. Never cached: nothing here is a saved set.
function buildInputServers(set: ServerSet, build: ServerClientBuilders): InputServers {
  const errors: InputServers["errors"] = {};
  for (const tool of incompleteTools(set)) errors[tool] = `${TOOL_LABEL[tool]} is incomplete`;
  const out: CaseServers = { setId: set.id, setName: set.name };
  const attempt = (tool: ToolName, make: () => void) => {
    if (errors[tool]) return;
    try {
      make();
    } catch (err) {
      errors[tool] = err instanceof Error ? err.message : String(err);
    }
  };
  const { iris: i, timesketch: t, velociraptor: v } = set;
  if (i?.url && i.apiKey) attempt("iris", () => void (out.iris = build.iris(i)));
  if (t?.url && t.user && t.password)
    attempt("timesketch", () => void (out.timesketch = build.timesketch(t)));
  if (v?.apiConfigPath) {
    attempt("velociraptor", () => {
      out.velociraptor = build.velociraptor(v);
      if (!out.velociraptor) throw new Error("Velociraptor API config cannot be read. Check the path.");
    });
  }
  return { servers: out, errors };
}
