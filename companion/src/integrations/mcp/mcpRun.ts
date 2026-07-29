import { deliver, type TransferRunner } from "./mcpDelivery.js";
import { assertCallAllowed } from "./mcpGuard.js";
import type { McpClient } from "./mcpClient.js";
import type { McpServer } from "./mcpServerStore.js";

// One MCP run, end to end (#296 phase 3): get the evidence where the server can read it, check the
// call is permitted, make it, tidy up. Deliberately knows nothing about cases, storage or ingest —
// the route composes this with ingestStreamed, exactly as routes/tools.ts composes the tool runner.
//
// Everything it needs is injected (client, transfer runner, custody hook), so the whole sequence
// tests without a socket, an ssh key or a case on disk.

/** The placeholder standing in for the delivered evidence, matching the tool runner's `<target>`. */
export const TARGET_PLACEHOLDER = "<target>";

export interface McpRunInput {
  tool: string;
  args: Record<string, unknown>;
  /** A path inside the case dir. When set, it is delivered and substituted for `<target>`. */
  targetPath?: string;
}

export interface McpRunDeps {
  server: McpServer;
  client: McpClient;
  transferRunner: TransferRunner;
  signal?: AbortSignal;
  recordTransfer?: (destination: string) => Promise<void>;
  onProgress?: (detail: string) => void;
}

export interface McpRunOutcome {
  text: string;
  structured: unknown;
  /** Where the evidence went, when something was delivered. */
  destination?: string;
  remotePath?: string;
}

/**
 * Replace `<target>` with the delivered path everywhere it appears in the tool arguments.
 *
 * Substituted IN PLACE within each string and never re-split, the same rule substituteArgs follows
 * for spawned tools — so `"-f"`, `"<target>"` stays two argv elements and a path with spaces stays
 * one. Nested arrays are walked because sift-mcp's run_command takes its whole command line as an
 * array of strings.
 */
export function substituteTarget(value: unknown, remotePath: string): unknown {
  if (typeof value === "string") return value.split(TARGET_PLACEHOLDER).join(remotePath);
  if (Array.isArray(value)) return value.map((v) => substituteTarget(v, remotePath));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substituteTarget(v, remotePath)]));
  }
  return value;
}

/** Whether `<target>` appears anywhere in the arguments. */
export function mentionsTarget(value: unknown): boolean {
  if (typeof value === "string") return value.includes(TARGET_PLACEHOLDER);
  if (Array.isArray(value)) return value.some((v) => mentionsTarget(v));
  if (value && typeof value === "object") return Object.values(value).some((v) => mentionsTarget(v));
  return false;
}

export async function runMcpTool(deps: McpRunDeps, input: McpRunInput): Promise<McpRunOutcome> {
  const { server, client } = deps;

  // Checked BEFORE anything is delivered, so a call that was never going to be permitted does not
  // first ship a memory image across the network. Checked again after substitution below, because
  // the delivered path could in principle land where a command head is read from.
  assertCallAllowed(server, input.tool, input.args);

  if (input.targetPath && !mentionsTarget(input.args)) {
    throw new Error(
      `${server.id}/${input.tool}: a target file was given but the arguments never reference ${TARGET_PLACEHOLDER}` +
      ` — put ${TARGET_PLACEHOLDER} where the tool expects the evidence path`,
    );
  }

  let cleanup: (() => Promise<void>) | undefined;
  let destination: string | undefined;
  let remotePath: string | undefined;
  let args = input.args;

  try {
    if (input.targetPath) {
      deps.onProgress?.(`delivering evidence to ${server.label}`);
      const target = await deliver(server, input.targetPath, {
        runner: deps.transferRunner,
        signal: deps.signal,
        recordTransfer: deps.recordTransfer,
      });
      cleanup = target.cleanup;
      destination = target.destination;
      remotePath = target.remotePath;
      args = substituteTarget(input.args, target.remotePath) as Record<string, unknown>;
      assertCallAllowed(server, input.tool, args);
    }

    deps.onProgress?.(`running ${input.tool} on ${server.label}`);
    const result = await client.callTool(input.tool, args, deps.signal);

    // The tool ran and reported its own failure. That is a diagnostic, not evidence — ingesting it
    // would file an error message in the case timeline as if it were an artifact.
    if (result.isError) {
      throw new Error(`${server.id}/${input.tool} reported a failure: ${result.text.trim().slice(0, 400) || "no detail given"}`);
    }

    return { text: result.text, structured: result.structured, destination, remotePath };
  } finally {
    // Always, including on failure: a copy left behind after a crashed run is evidence sitting on a
    // machine nobody is tracking. Best-effort inside deliver's cleanup.
    if (cleanup) {
      deps.onProgress?.("removing the staged copy");
      await cleanup();
    }
    await client.close().catch(() => { /* the server expires its own sessions */ });
  }
}
