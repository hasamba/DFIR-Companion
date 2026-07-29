import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runMcpAgent, buildMcpConfig, allowedToolPatterns, parseDelta, finalText, DEFAULT_MAX_TURNS,
} from "../../src/integrations/mcp/mcpAgentRunner.js";
import { DEFAULT_DELIVERY, type McpServer } from "../../src/integrations/mcp/mcpServerStore.js";
import type { ClaudeRunner, ClaudeRunOptions } from "../../src/providers/claudeRunner.js";

const server = (over: Partial<McpServer> = {}): McpServer => ({
  id: "sift", label: "SIFT", url: "http://192.168.1.50:8080/mcp", enabled: true,
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

let workDir: string;
let seen: ClaudeRunOptions[];
let configAtRunTime: { text: string; mode: number } | null;

function runnerReturning(stdout: string, extra: Partial<Awaited<ReturnType<ClaudeRunner>>> = {}): ClaudeRunner {
  return async (opts) => {
    seen.push(opts);
    // Read the config while the process would be running — it must be gone by the time we return.
    const i = opts.args.indexOf("--mcp-config");
    if (i >= 0) {
      const p = opts.args[i + 1];
      configAtRunTime = { text: await readFile(p, "utf8"), mode: (await stat(p)).mode & 0o777 };
    }
    return { code: 0, stdout, stderr: "", ...extra };
  };
}

beforeEach(async () => {
  workDir = await mkdtemp(join(tmpdir(), "dfir-mcpagent-"));
  seen = [];
  configAtRunTime = null;
});

describe("buildMcpConfig", () => {
  it("describes each server as streamable HTTP with its bearer token", () => {
    const cfg = buildMcpConfig([server()], { sift: "lab-token" });
    expect(cfg).toEqual({
      mcpServers: { sift: { type: "http", url: "http://192.168.1.50:8080/mcp", headers: { Authorization: "Bearer lab-token" } } },
    });
  });

  it("omits the header entirely when there is no token", () => {
    expect(buildMcpConfig([server()], {}).mcpServers.sift).toEqual({ type: "http", url: "http://192.168.1.50:8080/mcp" });
  });
});

describe("allowedToolPatterns", () => {
  it("qualifies each allowed tool with its server", () => {
    expect(allowedToolPatterns([server({ allowedTools: ["run_command", "check_tools"] })]))
      .toEqual(["mcp__sift__run_command", "mcp__sift__check_tools"]);
  });

  // A wildcard would hand the agent whatever the server advertises NEXT, which is the widening the
  // tool allowlist exists to prevent.
  it("enumerates rather than wildcarding", () => {
    expect(allowedToolPatterns([server()]).some((p) => p.includes("*"))).toBe(false);
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
    const r = await runMcpAgent({ servers: [server()], tokens: { sift: "t" }, prompt: "investigate", workDir, runner: runnerReturning(stdoutWith(DELTA)) });
    expect(r.rawText).toBe(DELTA);
    expect(r.delta.iocs).toHaveLength(1);
  });

  it("scopes the CLI to the generated config and the allowed tools only", async () => {
    await runMcpAgent({ servers: [server()], tokens: {}, prompt: "go", workDir, runner: runnerReturning(stdoutWith(DELTA)) });
    const args = seen[0].args;
    expect(args).toContain("--strict-mcp-config");            // never the operator's own MCP servers
    expect(args).toContain("--setting-sources");              // no CLAUDE.md, hooks or settings
    expect(args[args.indexOf("--setting-sources") + 1]).toBe("");
    expect(args[args.indexOf("--allowed-tools") + 1]).toBe("mcp__sift__run_command");
    expect(args[args.indexOf("--max-turns") + 1]).toBe(String(DEFAULT_MAX_TURNS));
  });

  // The config holds a bearer token: argv is readable by any process on the box.
  it("passes the token in a file, never on the command line", async () => {
    await runMcpAgent({ servers: [server()], tokens: { sift: "super-secret" }, prompt: "go", workDir, runner: runnerReturning(stdoutWith(DELTA)) });
    expect(seen[0].args.join(" ")).not.toContain("super-secret");
    expect(configAtRunTime?.text).toContain("super-secret");
  });

  it("writes that file owner-only and removes it afterwards", async () => {
    await runMcpAgent({ servers: [server()], tokens: { sift: "t" }, prompt: "go", workDir, runner: runnerReturning(stdoutWith(DELTA)) });
    expect(configAtRunTime?.mode).toBe(0o600);
    expect(await readdir(workDir)).toEqual([]);
  });

  it("removes the config even when the run fails", async () => {
    await expect(runMcpAgent({
      servers: [server()], tokens: { sift: "t" }, prompt: "go", workDir,
      runner: runnerReturning("", { code: 1 }),
    })).rejects.toThrow();
    expect(await readdir(workDir)).toEqual([]);
  });

  it("refuses to run when no tool is allowed on any selected server", async () => {
    await expect(runMcpAgent({
      servers: [server({ allowedTools: [] })], tokens: {}, prompt: "go", workDir,
      runner: runnerReturning(stdoutWith(DELTA)),
    })).rejects.toThrow(/no MCP tools are allowed/);
    expect(seen).toHaveLength(0);
  });

  it("says that agentic mode needs Claude Code on this host when the binary is missing", async () => {
    const enoent = Object.assign(new Error("spawn claude ENOENT"), { code: "ENOENT" }) as NodeJS.ErrnoException;
    await expect(runMcpAgent({
      servers: [server()], tokens: {}, prompt: "go", workDir,
      runner: async () => ({ code: null, stdout: "", stderr: "", spawnError: enoent }),
    })).rejects.toThrow(/needs Claude Code installed and authenticated ON THIS HOST/);
  });

  it("reports a timeout as one", async () => {
    await expect(runMcpAgent({
      servers: [server()], tokens: {}, prompt: "go", workDir, timeoutMs: 5000,
      runner: async () => ({ code: null, stdout: "", stderr: "", timedOut: true }),
    })).rejects.toThrow(/exceeded 5000ms/);
  });

  it("exposes several servers at once", async () => {
    const two = [server(), server({ id: "remnux", url: "http://192.168.1.60:3000/mcp", allowedTools: ["run_tool"] })];
    await runMcpAgent({ servers: two, tokens: { sift: "a", remnux: "b" }, prompt: "go", workDir, runner: runnerReturning(stdoutWith(DELTA)) });
    expect(seen[0].args[seen[0].args.indexOf("--allowed-tools") + 1]).toBe("mcp__sift__run_command,mcp__remnux__run_tool");
    expect(JSON.parse(configAtRunTime!.text).mcpServers).toHaveProperty("remnux");
  });
});
