import { defaultClaudeRunner, type ClaudeRunner } from "../../providers/claudeRunner.js";

// The Companion's only route to an MCP server: ask Claude Code (#296).
//
// The Companion does NOT speak MCP. It holds no server URLs, no bearer tokens, and spawns no
// `npx`/`uvx` of its own. Claude Code is already configured with the operator's servers and already
// holds their credentials, so it does the talking and the Companion asks it to.
//
// What that buys: no second place to configure a server, no second copy of a token, no transport for
// the Companion to keep current as the MCP spec moves, and nothing new to trust on disk.
//
// What it costs, stated so it is not discovered later: every MCP call now goes through a model. It
// spends tokens, it is not bit-for-bit deterministic the way a direct JSON-RPC call was, and the
// whole feature requires Claude Code installed AND authenticated on the Companion host. There is no
// path here that works without it, including for operators using Ollama or another provider for
// everything else.
//
// ── Secrets ─────────────────────────────────────────────────────────────────────────────────────
// `claude mcp list` prints each server's full command line, which for an mcp-remote entry INCLUDES
// the bearer token in cleartext. Nothing in this module returns, logs or renders that portion: the
// parser keeps the name and the health verdict and discards the rest of the line. Treat any change
// to listServers as security-relevant.

export interface McpBridgeServer {
  /** The name as Claude Code knows it — e.g. "sift-mcp". The Companion's registry keys on this. */
  name: string;
  connected: boolean;
  /** Health as reported, normalized. Never the command line. */
  status: "connected" | "needs-auth" | "failed";
}

export interface McpBridgeOptions {
  bin?: string;
  runner?: ClaudeRunner;
  timeoutMs?: number;
  signal?: AbortSignal;
}

const STATUS_CONNECTED = /✔|\bconnected\b/i;
const STATUS_AUTH = /needs? authentication/i;

/**
 * Parse `claude mcp list` into names and health.
 *
 * Deliberately lossy. Each line looks like `name: <command or url> - <status>`, and the middle is
 * the operator's configured command, which for these servers carries a bearer token. Splitting on
 * the FIRST ": " and the LAST " - " isolates the two ends and drops everything between them, so a
 * token cannot reach a caller, a log line or the dashboard.
 */
export function parseServerList(stdout: string): McpBridgeServer[] {
  const out: McpBridgeServer[] = [];
  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (!t || /^checking\b/i.test(t)) continue;
    const colon = t.indexOf(": ");
    const dash = t.lastIndexOf(" - ");
    if (colon === -1 || dash <= colon) continue;
    const name = t.slice(0, colon).trim();
    const status = t.slice(dash + 3).trim();   // the ONLY other part kept
    if (!name) continue;
    out.push({
      name,
      connected: STATUS_CONNECTED.test(status),
      status: STATUS_CONNECTED.test(status) ? "connected" : STATUS_AUTH.test(status) ? "needs-auth" : "failed",
    });
  }
  return out;
}

/** The MCP servers Claude Code is configured with, and whether each is answering. */
export async function listServers(opts: McpBridgeOptions = {}): Promise<McpBridgeServer[]> {
  const runner = opts.runner ?? defaultClaudeRunner;
  const run = await runner({
    bin: opts.bin?.trim() || "claude",
    args: ["mcp", "list"],
    stdin: "",
    timeoutMs: opts.timeoutMs ?? 120_000,
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  if (run.spawnError) throw new Error(claudeMissingMessage(opts.bin, run.spawnError));
  if (run.timedOut) throw new Error("`claude mcp list` timed out — a configured MCP server may be hanging on startup");
  // Never quote stdout on failure: it is the very output that carries tokens.
  if (run.code !== 0 && !run.stdout.trim()) {
    throw new Error(`\`claude mcp list\` failed (exit ${run.code ?? "null"}) — check that Claude Code is configured on this host`);
  }
  return parseServerList(run.stdout);
}

export function claudeMissingMessage(bin: string | undefined, err: NodeJS.ErrnoException): string {
  if (err.code === "ENOENT") {
    return `Claude Code CLI not found (tried "${bin || "claude"}"). The Companion reaches MCP servers only through ` +
      `Claude Code, so it must be installed and authenticated on THIS host, with your MCP servers configured in it. ` +
      `Set DFIR_AI_CLAUDE_CODE_BIN if it is not on PATH.`;
  }
  return `Claude Code failed to start: ${err.message}`;
}
