import type { CaseServers, ServerClients } from "../../src/integrations/serverSets/types.js";
import type { VelociraptorClient } from "../../src/integrations/velociraptor/velociraptorApi.js";

// A ServerClients that hands every case (and the default) the same pre-built clients. For route tests
// that only need "some IRIS/Timesketch/Velociraptor client" and do not exercise set resolution.
export function stubServerClients(tools: Partial<CaseServers>): ServerClients {
  const ok = { ok: true as const, servers: { setId: "stub", setName: "Stub", ...tools } };
  return {
    forCase: () => ok,
    forDefault: () => ok,
    forSet: () => ok,
    forInput: () => ({ servers: ok.servers, errors: {} }),
    invalidate: () => undefined,
  };
}

// Every case resolves to one Velociraptor client — a real one over a fake runner, or a hand-rolled
// fake (hence `unknown`). The set id is "stub", so a per-set inventory lives under that id.
export function veloServerClients(client: unknown): ServerClients {
  return stubServerClients({ velociraptor: client as VelociraptorClient });
}
