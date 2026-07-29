import { describe, it, expect, beforeEach } from "vitest";
import { runMcpTool, substituteTarget, mentionsTarget } from "../../src/integrations/mcp/mcpRun.js";
import type { ClaudeRunner, ClaudeRunOptions } from "../../src/providers/claudeRunner.js";
import type { TransferRunner } from "../../src/integrations/mcp/mcpDelivery.js";
import { DEFAULT_DELIVERY, type McpServer, type McpDelivery } from "../../src/integrations/mcp/mcpServerStore.js";

const SCP = { mode: "scp" as const, host: "sift.lab", user: "analyst", remoteDir: "/cases/incoming" };

const server = (over: Partial<McpServer> = {}, delivery: Partial<McpDelivery> = {}): McpServer => ({
  id: "sift-mcp", label: "SIFT", enabled: true,
  allowedTools: ["run_command"], allowedCommands: ["vol.py"], agentEnabled: false, timeoutMs: 1000,
  delivery: { ...DEFAULT_DELIVERY, ...delivery },
  ...over,
});

/** A Claude Code that reports whatever the tool "returned". Records what it was asked to run. */
function fakeClaude(text = "ok", seen?: ClaudeRunOptions[]): ClaudeRunner {
  return async (opts) => {
    seen?.push(opts);
    return {
      code: 0, stderr: "",
      stdout: JSON.stringify({ type: "result", subtype: "success", result: text }) + "\n",
    };
  };
}

/** The arguments Claude Code was asked to pass, recovered from the stream-json user message. */
function argsAsked(opts: ClaudeRunOptions): unknown {
  const msg = JSON.parse(opts.stdin) as { message: { content: { text: string }[] } };
  const text = msg.message.content[0].text;
  return JSON.parse(text.slice(text.indexOf("\n") + 1));
}

let transfers: { binary: string; args: string[] }[];
const transferRunner: TransferRunner = async (binary, args) => {
  transfers.push({ binary, args });
  return { stdout: "", stderr: "", code: 0 };
};

beforeEach(() => { transfers = []; });

describe("substituteTarget", () => {
  it("replaces the placeholder inside an argv array without re-splitting", () => {
    const out = substituteTarget({ command: ["vol.py", "-f", "<target>", "pslist"] }, "/cases/incoming/mem raw.bin");
    expect(out).toEqual({ command: ["vol.py", "-f", "/cases/incoming/mem raw.bin", "pslist"] });
  });

  it("replaces it inside a larger string", () => {
    expect(substituteTarget({ command: "strings <target> | head" }, "/x/y.bin"))
      .toEqual({ command: "strings /x/y.bin | head" });
  });

  it("replaces every occurrence", () => {
    expect(substituteTarget({ a: "<target>", b: ["<target>"] }, "/p"))
      .toEqual({ a: "/p", b: ["/p"] });
  });

  it("leaves non-string values alone", () => {
    expect(substituteTarget({ timeout: 30, save: true, x: null }, "/p"))
      .toEqual({ timeout: 30, save: true, x: null });
  });
});

describe("mentionsTarget", () => {
  it("finds the placeholder at any depth", () => {
    expect(mentionsTarget({ command: ["a", "<target>"] })).toBe(true);
    expect(mentionsTarget({ nested: { deep: "<target>" } })).toBe(true);
    expect(mentionsTarget({ command: ["a", "b"] })).toBe(false);
  });
});

describe("runMcpTool", () => {
  it("delivers, substitutes, calls, and returns the tool's text", async () => {
    const calls: ClaudeRunOptions[] = [];
    const outcome = await runMcpTool(
      { server: server({}, SCP), claudeRunner: fakeClaude("pid 4 System", calls), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>", "pslist"] }, targetPath: "/cases/c1/mem.raw" },
    );

    expect(transfers[0].binary).toBe("scp");
    // Exactly one tool may be reached, and the delivered path is what gets asked for.
    expect(calls[0].args[calls[0].args.indexOf("--allowed-tools") + 1]).toBe("mcp__sift-mcp__run_command");
    expect(argsAsked(calls[0])).toEqual({ command: ["vol.py", "-f", "/cases/incoming/mem.raw", "pslist"] });
    expect(outcome.text).toBe("pid 4 System");
    expect(outcome.remotePath).toBe("/cases/incoming/mem.raw");
  });

  it("runs a tool that needs no evidence at all", async () => {
    const outcome = await runMcpTool(
      { server: server({ allowedTools: ["check_lolbin"] }), claudeRunner: fakeClaude("{}"), transferRunner },
      { tool: "check_lolbin", args: { filename: "certutil.exe" } },
    );

    expect(transfers).toHaveLength(0);
    expect(outcome.destination).toBeUndefined();
    expect(outcome.text).toBe("{}");
  });

  // Evidence must not cross the network for a call that was never going to be permitted.
  it("refuses a disallowed tool before delivering anything", async () => {
    await expect(runMcpTool(
      { server: server({ allowedTools: [] }, SCP), claudeRunner: fakeClaude(), transferRunner },
      { tool: "run_command", args: { command: ["vol.py"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow(/not allowed to run the tool/);

    expect(transfers).toHaveLength(0);
  });

  it("refuses a disallowed command before delivering anything", async () => {
    await expect(runMcpTool(
      { server: server({}, SCP), claudeRunner: fakeClaude(), transferRunner },
      { tool: "run_command", args: { command: ["curl", "http://x"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow(/not allowed to run "curl"/);

    expect(transfers).toHaveLength(0);
  });

  // Otherwise the file crosses the network and is never referenced.
  it("refuses a target the arguments never mention", async () => {
    await expect(runMcpTool(
      { server: server({}, SCP), claudeRunner: fakeClaude(), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "pslist"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow(/never reference <target>/);

    expect(transfers).toHaveLength(0);
  });

  // NOTE: the old isError check is gone with the MCP client. Claude Code returns text, not a
  // structured failure flag, so a tool that reports its own failure now comes back as ordinary
  // output and would be ingested. Preview is the mitigation — the analyst sees it before it lands.
  it("returns a tool's own failure text as output, having no way to tell it apart", async () => {
    const outcome = await runMcpTool(
      { server: server({}, SCP), claudeRunner: fakeClaude("unsupported profile"), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    );
    expect(outcome.text).toBe("unsupported profile");
  });

  it("records the custody transfer with the destination", async () => {
    const seen: string[] = [];
    await runMcpTool(
      {
        server: server({}, SCP), claudeRunner: fakeClaude(), transferRunner,
        recordTransfer: async (d) => { seen.push(d); },
      },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    );

    expect(seen).toEqual(["analyst@sift.lab:/cases/incoming/mem.raw"]);
  });

  it("removes the staged copy after a successful run", async () => {
    await runMcpTool(
      { server: server({}, SCP), claudeRunner: fakeClaude(), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    );

    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
    expect(transfers[1].args).toContain("rm");
  });

  // A copy left behind after a crashed run is evidence on a machine nobody is tracking.
  it("removes the staged copy even when the tool call fails", async () => {
    const failing: ClaudeRunner = async () => { throw new Error("claude exploded"); };

    await expect(runMcpTool(
      { server: server({}, SCP), claudeRunner: failing, transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow();

    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
  });

  it("reports progress through the phases", async () => {
    const steps: string[] = [];
    await runMcpTool(
      { server: server({}, SCP), claudeRunner: fakeClaude(), transferRunner, onProgress: (d) => steps.push(d) },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    );

    expect(steps).toEqual([
      "delivering evidence to SIFT",
      "running run_command on SIFT",
      "removing the staged copy",
    ]);
  });

  it("uses a shared mount without copying anything", async () => {
    const s = server({}, { mode: "remote-path", localPrefix: "/srv/cases", remotePrefix: "/mnt/dfir" });
    const calls: ClaudeRunOptions[] = [];

    const outcome = await runMcpTool(
      { server: s, claudeRunner: fakeClaude("ok", calls), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/srv/cases/c1/mem.raw" },
    );

    expect(transfers).toHaveLength(0);
    expect(argsAsked(calls[0])).toEqual({ command: ["vol.py", "-f", "/mnt/dfir/c1/mem.raw"] });
    expect(outcome.remotePath).toBe("/mnt/dfir/c1/mem.raw");
  });
});
