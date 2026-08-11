import { deliver, type TransferRunner } from "./mcpDelivery.js";
import { assertCallAllowed } from "./mcpGuard.js";
import { callTool } from "./mcpBridge.js";
import type { ClaudeRunner } from "../../providers/claudeRunner.js";
import type { McpServer } from "./mcpServerStore.js";

// One MCP run, end to end (#296): get the evidence where the server can read it, check the call is
// permitted, ask Claude Code to make it, tidy up. Deliberately knows nothing about cases, storage or
// ingest — the route composes this with ingestStreamed, exactly as routes/tools.ts composes the
// tool runner.
//
// The Companion does not call the server itself; mcpBridge asks Claude Code to. What survives that
// is the guard: the Companion still decides the tool and the arguments, so assertCallAllowed vets
// both before anything is asked for. What it cannot do is guarantee the model passes them through
// unchanged — the prompt demands it and --allowed-tools bounds the reachable surface, but the
// argument-level check is advice to a model rather than a wire-level constraint. That is the price
// of the Companion not being an MCP client, and it is why the agent path is gated separately.
//
// Everything it needs is injected (the Claude runner, the transfer runner, the custody hook), so the
// whole sequence tests without spawning anything, an ssh key or a case on disk.

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
  /** Drives the `claude` CLI. Injected so tests never spawn it. */
  claudeRunner?: ClaudeRunner;
  claudeBin?: string;
  model?: string;
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
  const { server } = deps;

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
    const text = await callTool({
      server: server.id,
      tool: input.tool,
      args,
      ...(deps.claudeRunner ? { runner: deps.claudeRunner } : {}),
      ...(deps.claudeBin ? { bin: deps.claudeBin } : {}),
      ...(deps.model ? { model: deps.model } : {}),
      timeoutMs: server.timeoutMs,
      ...(deps.signal ? { signal: deps.signal } : {}),
    });

    return { text, structured: undefined, destination, remotePath };
  } finally {
    // Always, including on failure: a copy left behind after a crashed run is evidence sitting on a
    // machine nobody is tracking. Best-effort inside deliver's cleanup.
    if (cleanup) {
      deps.onProgress?.("removing the staged copy");
      await cleanup();
    }
  }
}
