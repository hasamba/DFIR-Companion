import { describe, it, expect, beforeEach } from "vitest";
import {
  runMcpAgent, allowedToolPatterns, parseDelta, DEFAULT_MAX_TURNS,
} from "../../src/integrations/mcp/mcpAgentRunner.js";
import { finalText } from "../../src/integrations/mcp/mcpBridge.js";
import { DEFAULT_DELIVERY, type McpServer } from "../../src/integrations/mcp/mcpServerStore.js";
import type { ClaudeRunner, ClaudeRunOptions } from "../../src/providers/claudeRunner.js";

const server = (over: Partial<McpServer> = {}): McpServer => ({
  id: "sift-mcp", label: "SIFT", enabled: true,
  allowedTools: ["run_command"], allowedCommands: ["vol.py"], agentEnabled: true,
  timeoutMs: 1000, delivery: DEFAULT_DELIVERY, ...over,
});

/** stream-json output ending in a successful terminal result carrying `text`. */
const stdoutWith = (text: string, turns: string[] = []): string =>
  [
    ...turns.map((t) => JSON.stringify({ type: "assistant", message: { content: [{ type: "text", text: t }] } })),
    JSON.stringify({ type: "result", subtype: "success", result: text }),
  ].join("\n") + "\n";

const DELTA = '{"findings":[{"title":"Injected process","detail":"malfind hit","severity":"High","confidence":70}],"iocs":[{"type":"ip","value":"10.2.3.4"}]}';

let seen: ClaudeRunOptions[];

function runnerReturning(stdout: string, extra: Partial<Awaited<ReturnType<ClaudeRunner>>> = {}): ClaudeRunner {
  return async (opts) => {
    seen.push(opts);
    return { code: 0, stdout, stderr: "", ...extra };
  };
}

beforeEach(() => { seen = []; });

describe("allowedToolPatterns", () => {
  it("enumerates tool by tool when an allowlist was configured", () => {
    expect(allowedToolPatterns([server({ allowedTools: ["run_command", "check_tools"] })]))
      .toEqual(["mcp__sift-mcp__run_command", "mcp__sift-mcp__check_tools"]);
  });

  // The default. Use Claude Code's explicit wildcard form so every current and future tool from
  // the server is approved without an interactive permission prompt.
  it("grants the whole server when no allowlist was configured", () => {
    expect(allowedToolPatterns([server({ allowedTools: [] })])).toEqual(["mcp__sift-mcp__*"]);
  });
});

describe("finalText", () => {
  it("takes the terminal result", () => {
    expect(finalText(stdoutWith("final answer"), "", 0)).toBe("final answer");
  });

  // ClaudeCodeProvider stitches multiple assistant messages because tools are disabled there, so
  // more than one can only be a continuation. Here they are ordinary turns and stitching them would
  // splice the agent's intermediate reasoning into its answer.
  it("ignores the per-turn assistant messages", () => {
    expect(finalText(stdoutWith("final answer", ["let me check pslist", "now malfind"]), "", 0)).toBe("final answer");
  });

  it("throws when there is no result event, quoting stderr", () => {
    expect(() => finalText("", "claude: not logged in", 1)).toThrow(/no result \(exit 1\).*not logged in/);
  });

  it("throws when the run reported an error", () => {
    const out = JSON.stringify({ type: "result", subtype: "error_max_turns", result: "hit the turn limit" });
    expect(() => finalText(out, "", 0)).toThrow(/hit the turn limit/);
  });
});

describe("parseDelta", () => {
  it("validates the agent's JSON into a delta", () => {
    const d = parseDelta(DELTA);
    expect(d.findings?.[0]).toMatchObject({ title: "Injected process", severity: "High" });
    expect(d.iocs[0]).toMatchObject({ type: "ip", value: "10.2.3.4" });
  });

  it("tolerates code fences and surrounding prose", () => {
    expect(parseDelta("Here is what I found:\n```json\n" + DELTA + "\n```\nHope that helps.").iocs).toHaveLength(1);
  });

  // Everything the agent saw came from tool output, which is untrusted; extractedFrom asserts an
  // authoritative link to a stored source event that only the deterministic importers may set.
  it("strips extractedFrom so injected content cannot fabricate provenance", () => {
    const d = parseDelta('{"iocs":[{"type":"ip","value":"10.2.3.4","extractedFrom":["e001"]}]}');
    expect(d.iocs[0]).not.toHaveProperty("extractedFrom");
  });

  // The agent is never asked for a summary: one tool run must not overwrite the case's conclusions.
  // mergeDelta ignores an empty summary/timelineNote, so filling them here is a no-op by design.
  it("never carries a summary that would overwrite the case's conclusions", () => {
    const d = parseDelta('{"findings":[],"iocs":[],"summary":"the whole case was X"}');
    expect(d.summary).toBe("");
    expect(d.timelineNote).toBe("");
  });

  it("accepts detail as an alias for description, and drops entries with nothing in them", () => {
    const d = parseDelta('{"findings":[{"title":"A","detail":"seen in malfind"},{"description":"no title"}],"iocs":[{"type":"ip","value":""}]}');
    expect(d.findings).toHaveLength(1);
    expect(d.findings?.[0]).toMatchObject({ title: "A", description: "seen in malfind" });
    expect(d.iocs).toHaveLength(0);
  });

  it("maps the agent's timeline onto forensic events, dropping undated ones", () => {
    const d = parseDelta('{"timeline":[{"timestamp":"2026-07-29T10:00:00Z","description":"beacon"},{"description":"no time"}]}');
    expect(d.forensicEvents).toHaveLength(1);
    expect(d.forensicEvents?.[0]).toMatchObject({ timestamp: "2026-07-29T10:00:00Z", description: "beacon" });
  });

  it("refuses output that is not JSON at all", () => {
    expect(() => parseDelta("I could not complete the investigation.")).toThrow(/did not return JSON/);
  });

  it("refuses JSON that does not parse", () => {
    expect(() => parseDelta("{not: valid}")).toThrow(/did not parse/);
  });
});

describe("runMcpAgent", () => {
  it("returns the parsed delta and the agent's own text", async () => {
    const r = await runMcpAgent({ servers: [server()], prompt: "investigate", runner: runnerReturning(stdoutWith(DELTA)) });
    expect(r.rawText).toBe(DELTA);
    expect(r.delta.iocs).toHaveLength(1);
  });

  it("scopes the CLI to the allowed tools only", async () => {
    await runMcpAgent({ servers: [server()], prompt: "go", runner: runnerReturning(stdoutWith(DELTA)) });
    const args = seen[0].args;
    expect(args).toContain("--setting-sources");              // no CLAUDE.md, hooks or settings
    expect(args[args.indexOf("--setting-sources") + 1]).toBe("user");
    expect(args[args.indexOf("--allowed-tools") + 1]).toBe("mcp__sift-mcp__run_command");
    expect(args[args.indexOf("--max-turns") + 1]).toBe(String(DEFAULT_MAX_TURNS));
  });

  // The whole point of the change: the Companion holds no credentials and writes no config, because
  // Claude Code is already configured with these servers.
  it("generates no config and passes no token", async () => {
    await runMcpAgent({ servers: [server()], prompt: "go", runner: runnerReturning(stdoutWith(DELTA)) });
    const args = seen[0].args;
    expect(args).not.toContain("--mcp-config");
    expect(args).not.toContain("--strict-mcp-config");
    expect(args.join(" ")).not.toMatch(/Bearer|token/i);
  });

  it("refuses to run with no servers selected at all", async () => {
    await expect(runMcpAgent({ servers: [], prompt: "go", runner: runnerReturning(stdoutWith(DELTA)) }))
      .rejects.toThrow(/no MCP servers were selected/);
    expect(seen).toHaveLength(0);
  });

  it("says the whole feature needs Claude Code on this host when the binary is missing", async () => {
    const enoent = Object.assign(new Error("spawn claude ENOENT"), { code: "ENOENT" }) as NodeJS.ErrnoException;
    await expect(runMcpAgent({
      servers: [server()], prompt: "go",
      runner: async () => ({ code: null, stdout: "", stderr: "", spawnError: enoent }),
    })).rejects.toThrow(/installed and authenticated on THIS host.*configured in it/s);
  });

  it("reports a timeout as one", async () => {
    await expect(runMcpAgent({
      servers: [server()], prompt: "go", timeoutMs: 5000,
      runner: async () => ({ code: null, stdout: "", stderr: "", timedOut: true }),
    })).rejects.toThrow(/exceeded 5000ms/);
  });

  it("exposes several servers at once", async () => {
    const two = [server(), server({ id: "remnux", allowedTools: ["run_tool"] })];
    await runMcpAgent({ servers: two, prompt: "go", runner: runnerReturning(stdoutWith(DELTA)) });
    expect(seen[0].args[seen[0].args.indexOf("--allowed-tools") + 1]).toBe("mcp__sift-mcp__run_command,mcp__remnux__run_tool");
  });

  it("turns a max-turns investigation into a report in the same session with tools disabled", async () => {
    const sessionId = "11111111-1111-4111-8111-111111111111";
    const runner: ClaudeRunner = async (opts) => {
      seen.push(opts);
      if (seen.length === 1) {
        return {
          code: 0, stderr: "",
          stdout: JSON.stringify({
            type: "result", subtype: "error_max_turns", is_error: true,
            result: "", session_id: sessionId,
          }) + "\n",
        };
      }
      return { code: 0, stderr: "", stdout: stdoutWith(DELTA) };
    };

    const result = await runMcpAgent({ servers: [server()], prompt: "investigate", runner });

    expect(result.delta.findings?.[0]?.title).toBe("Injected process");
    expect(seen).toHaveLength(2);
    expect(seen[1].args).toContain("--resume");
    expect(seen[1].args[seen[1].args.indexOf("--resume") + 1]).toBe(sessionId);
    expect(seen[1].args[seen[1].args.indexOf("--tools") + 1]).toBe("");
    expect(seen[1].stdin).toContain("Do not call any more tools");
  });

  it("explains a max-turns failure when Claude Code provides no resumable session", async () => {
    const out = JSON.stringify({
      type: "result", subtype: "error_max_turns", is_error: true, result: "",
    }) + "\n";
    await expect(runMcpAgent({
      servers: [server()], prompt: "investigate", runner: runnerReturning(out),
    })).rejects.toThrow(/turn safety limit.*could not open the final reporting turn/i);
  });
});
