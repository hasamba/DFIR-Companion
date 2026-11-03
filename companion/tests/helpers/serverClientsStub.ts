import type { CaseServers, ServerClients } from "../../src/integrations/serverSets/types.js";

// A ServerClients that hands every case (and the default) the same pre-built clients. For route tests
// that only need "some IRIS/Timesketch client" and do not exercise set resolution.
export function stubServerClients(tools: Partial<CaseServers>): ServerClients {
  const ok = { ok: true as const, servers: { setId: "stub", setName: "Stub", ...tools } };
  return { forCase: () => ok, forDefault: () => ok, forSet: () => ok, invalidate: () => undefined };
}
