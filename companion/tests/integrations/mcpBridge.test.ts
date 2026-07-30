import { describe, it, expect } from "vitest";
import { parseServerList, listServers } from "../../src/integrations/mcp/mcpBridge.js";
import type { ClaudeRunner } from "../../src/providers/claudeRunner.js";

// Synthetic `claude mcp list` output. RFC 5737 addresses and unmistakable fixture values exercise
// redaction without copying an operator's private MCP configuration into source control.
const TOKEN = "SIFT_TEST_BEARER_VALUE";
const LIST = [
  "Checking MCP server health…",
  "",
  "claude.ai ClickUp: https://mcp.clickup.com/mcp - ! Needs authentication",
  "n8n-mcp: npx n8n-mcp - ✔ Connected",
  `sift-mcp: npx -y mcp-remote http://192.0.2.10:4508/mcp/sift-mcp --header Authorization:Bearer ${TOKEN} --transport http-only --allow-http - ✔ Connected`,
  "remnux: npx -y mcp-remote http://192.0.2.11:3000/mcp --header Authorization:Bearer REMNUX_TEST_BEARER_VALUE --allow-http - ✔ Connected",
  "broken-mcp: npx broken - ✘ Failed to connect",
].join("\n");

const runnerReturning = (stdout: string, extra = {}): ClaudeRunner =>
  async () => ({ code: 0, stdout, stderr: "", ...extra });

describe("parseServerList", () => {
  it("reads every configured server's name and health", () => {
    expect(parseServerList(LIST)).toEqual([
      { name: "claude.ai ClickUp", connected: false, status: "needs-auth" },
      { name: "n8n-mcp", connected: true, status: "connected" },
      { name: "sift-mcp", connected: true, status: "connected" },
      { name: "remnux", connected: true, status: "connected" },
      { name: "broken-mcp", connected: false, status: "failed" },
    ]);
  });

  // `claude mcp list` echoes each server's full command line, which for these entries contains the
  // bearer token in cleartext. Nothing may carry it out of this function.
  it("never carries the bearer token out of the command line", () => {
    const parsed = parseServerList(LIST);
    expect(JSON.stringify(parsed)).not.toContain(TOKEN);
    expect(JSON.stringify(parsed)).not.toContain("Authorization");
    expect(JSON.stringify(parsed)).not.toContain("mcp-remote");
    expect(JSON.stringify(parsed)).not.toContain("192.0.2.10");
  });

  it("keeps a name that contains spaces", () => {
    expect(parseServerList("claude.ai Google Drive: https://x/mcp - ✔ Connected")[0].name)
      .toBe("claude.ai Google Drive");
  });

  it("ignores the health-check banner and blank lines", () => {
    expect(parseServerList("Checking MCP server health…\n\n")).toEqual([]);
  });

  it("ignores a line it cannot make sense of", () => {
    expect(parseServerList("something entirely unexpected")).toEqual([]);
  });
});

describe("listServers", () => {
  it("returns the parsed servers", async () => {
    expect((await listServers({ runner: runnerReturning(LIST) })).map((s) => s.name))
      .toContain("sift-mcp");
  });

  it("explains that MCP works only through Claude Code when the CLI is missing", async () => {
    const enoent = Object.assign(new Error("spawn claude ENOENT"), { code: "ENOENT" }) as NodeJS.ErrnoException;
    await expect(listServers({ runner: async () => ({ code: null, stdout: "", stderr: "", spawnError: enoent }) }))
      .rejects.toThrow(/installed and authenticated on THIS host.*configured in it/s);
  });

  it("reports a hanging server as a timeout rather than an empty list", async () => {
    await expect(listServers({ runner: async () => ({ code: null, stdout: "", stderr: "", timedOut: true }) }))
      .rejects.toThrow(/timed out/);
  });

  // The failure path must not quote stdout — that is the output holding the tokens.
  it("does not echo command output when the CLI fails", async () => {
    const err = await listServers({ runner: runnerReturning("", { code: 1 }) }).catch((e: Error) => e.message);
    expect(err).toMatch(/failed \(exit 1\)/);
    expect(err).not.toContain(TOKEN);
  });
});
