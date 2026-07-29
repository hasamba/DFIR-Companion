import { describe, it, expect, beforeEach } from "vitest";
import { runMcpTool, substituteTarget, mentionsTarget } from "../../src/integrations/mcp/mcpRun.js";
import { McpClient, type McpHttpResponse, type McpHttpTransport } from "../../src/integrations/mcp/mcpClient.js";
import type { TransferRunner } from "../../src/integrations/mcp/mcpDelivery.js";
import { DEFAULT_DELIVERY, type McpServer, type McpDelivery } from "../../src/integrations/mcp/mcpServerStore.js";

const SCP = { mode: "scp" as const, host: "sift.lab", user: "analyst", remoteDir: "/cases/incoming" };

const server = (over: Partial<McpServer> = {}, delivery: Partial<McpDelivery> = {}): McpServer => ({
  id: "sift", label: "SIFT", url: "http://192.168.1.50:8080/mcp", enabled: true,
  allowedTools: ["run_command"], allowedCommands: ["vol.py"], agentEnabled: false, timeoutMs: 1000,
  delivery: { ...DEFAULT_DELIVERY, ...delivery },
  ...over,
});

/** An MCP endpoint that handshakes and echoes a canned tool result. */
function fakeClient(opts: { text?: string; isError?: boolean; calls?: unknown[] } = {}): McpClient {
  const transport: McpHttpTransport = {
    async send(req): Promise<McpHttpResponse> {
      if (req.method === "DELETE") return { status: 204, headers: {}, body: "" };
      const msg = JSON.parse(req.body ?? "{}") as { id?: number; method?: string; params?: unknown };
      if (msg.id === undefined) return { status: 202, headers: {}, body: "" };
      if (msg.method === "tools/call") opts.calls?.push(msg.params);
      const result = msg.method === "initialize"
        ? { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "sift-mcp", version: "1" } }
        : { content: [{ type: "text", text: opts.text ?? "ok" }], isError: opts.isError === true };
      return {
        status: 200,
        headers: { "content-type": "application/json", "mcp-session-id": "s1" },
        body: JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }),
      };
    },
  };
  return new McpClient({ url: "http://192.168.1.50:8080/mcp", transport, timeoutMs: 1000 });
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
    const calls: unknown[] = [];
    const outcome = await runMcpTool(
      { server: server({}, SCP), client: fakeClient({ text: "pid 4 System", calls }), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>", "pslist"] }, targetPath: "/cases/c1/mem.raw" },
    );

    expect(transfers[0].binary).toBe("scp");
    expect(calls[0]).toMatchObject({
      name: "run_command",
      arguments: { command: ["vol.py", "-f", "/cases/incoming/mem.raw", "pslist"] },
    });
    expect(outcome.text).toBe("pid 4 System");
    expect(outcome.remotePath).toBe("/cases/incoming/mem.raw");
  });

  it("runs a tool that needs no evidence at all", async () => {
    const outcome = await runMcpTool(
      { server: server({ allowedTools: ["check_lolbin"] }), client: fakeClient({ text: "{}" }), transferRunner },
      { tool: "check_lolbin", args: { filename: "certutil.exe" } },
    );

    expect(transfers).toHaveLength(0);
    expect(outcome.destination).toBeUndefined();
    expect(outcome.text).toBe("{}");
  });

  // Evidence must not cross the network for a call that was never going to be permitted.
  it("refuses a disallowed tool before delivering anything", async () => {
    await expect(runMcpTool(
      { server: server({ allowedTools: [] }, SCP), client: fakeClient(), transferRunner },
      { tool: "run_command", args: { command: ["vol.py"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow(/not allowed to run the tool/);

    expect(transfers).toHaveLength(0);
  });

  it("refuses a disallowed command before delivering anything", async () => {
    await expect(runMcpTool(
      { server: server({}, SCP), client: fakeClient(), transferRunner },
      { tool: "run_command", args: { command: ["curl", "http://x"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow(/not allowed to run "curl"/);

    expect(transfers).toHaveLength(0);
  });

  // Otherwise the file crosses the network and is never referenced.
  it("refuses a target the arguments never mention", async () => {
    await expect(runMcpTool(
      { server: server({}, SCP), client: fakeClient(), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "pslist"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow(/never reference <target>/);

    expect(transfers).toHaveLength(0);
  });

  // A tool's own error message is a diagnostic, not an artifact — ingesting it would file it in the
  // case timeline as evidence.
  it("fails rather than returning a tool-reported error for ingest", async () => {
    await expect(runMcpTool(
      { server: server({}, SCP), client: fakeClient({ text: "unsupported profile", isError: true }), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow(/reported a failure: unsupported profile/);
  });

  it("records the custody transfer with the destination", async () => {
    const seen: string[] = [];
    await runMcpTool(
      {
        server: server({}, SCP), client: fakeClient(), transferRunner,
        recordTransfer: async (d) => { seen.push(d); },
      },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    );

    expect(seen).toEqual(["analyst@sift.lab:/cases/incoming/mem.raw"]);
  });

  it("removes the staged copy after a successful run", async () => {
    await runMcpTool(
      { server: server({}, SCP), client: fakeClient(), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    );

    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
    expect(transfers[1].args).toContain("rm");
  });

  // A copy left behind after a crashed run is evidence on a machine nobody is tracking.
  it("removes the staged copy even when the tool call fails", async () => {
    const client = fakeClient({ text: "boom", isError: true });

    await expect(runMcpTool(
      { server: server({}, SCP), client, transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/cases/c1/mem.raw" },
    )).rejects.toThrow();

    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
  });

  it("reports progress through the phases", async () => {
    const steps: string[] = [];
    await runMcpTool(
      { server: server({}, SCP), client: fakeClient(), transferRunner, onProgress: (d) => steps.push(d) },
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
    const calls: unknown[] = [];

    const outcome = await runMcpTool(
      { server: s, client: fakeClient({ calls }), transferRunner },
      { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: "/srv/cases/c1/mem.raw" },
    );

    expect(transfers).toHaveLength(0);
    expect(calls[0]).toMatchObject({ arguments: { command: ["vol.py", "-f", "/mnt/dfir/c1/mem.raw"] } });
    expect(outcome.remotePath).toBe("/mnt/dfir/c1/mem.raw");
  });
});
