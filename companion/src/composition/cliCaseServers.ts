// The server set a command-line script (iris:push, iris:import, timesketch:push) uses: the case's
// own set, resolved exactly as the server resolves it. There is no fallback to the default set or
// to the DFIR_* values in .env.
import { existsSync } from "node:fs";
import { instanceSecretPath, loadOrCreateInstanceSecret } from "../analysis/instanceSecret.js";
import { deriveServerSetKey } from "../integrations/serverSets/secretBox.js";
import { ServerSetStore } from "../integrations/serverSets/serverSetStore.js";
import { serverSetStoreDir } from "../integrations/serverSets/storePath.js";
import type { CaseServers, ToolName } from "../integrations/serverSets/types.js";
import { createServerClients, type ServerClientBuilders } from "./serverSetClients.js";

const TOOL_LABEL: Record<ToolName, string> = {
  iris: "DFIR-IRIS",
  timesketch: "Timesketch",
  velociraptor: "Velociraptor",
};

export type CliToolResult =
  { ok: true; setName: string; servers: CaseServers } | { ok: false; error: string };

export function cliCaseTool(
  casesRoot: string,
  caseId: string,
  tool: ToolName,
  opts: { env?: NodeJS.ProcessEnv; builders?: Partial<ServerClientBuilders> } = {},
): CliToolResult {
  const dir = serverSetStoreDir(casesRoot);
  // Read-only: a script never creates the store or the instance secret (a wrong cases root would
  // otherwise get a fresh, empty store).
  if (!existsSync(dir) || !existsSync(instanceSecretPath(casesRoot))) {
    return { ok: false, error: `No server sets found beside ${casesRoot}. Start the Companion once first.` };
  }
  const store = new ServerSetStore(dir, deriveServerSetKey(loadOrCreateInstanceSecret(casesRoot)));
  const r = createServerClients(store, opts.env ?? process.env, opts.builders).forCase(caseId);
  if (!r.ok) return { ok: false, error: r.error };
  if (!r.servers[tool]) {
    return {
      ok: false,
      error: `${TOOL_LABEL[tool]} is not configured in server set '${r.servers.setName}'. Add it in Settings → Server sets.`,
    };
  }
  return { ok: true, setName: r.servers.setName, servers: r.servers };
}
