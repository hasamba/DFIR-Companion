import { describe, it, expect, beforeEach } from "vitest";
import { mkdir, mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runMcpTool, substituteTarget, mentionsTarget } from "../../src/integrations/mcp/mcpRun.js";
import type { ClaudeRunner, ClaudeRunOptions } from "../../src/providers/claudeRunner.js";
import type { DeliverySource, TransferRunner } from "../../src/integrations/mcp/mcpDelivery.js";
import { aclStub } from "../helpers/aclStub.js";
import {
  DEFAULT_DELIVERY,
  type McpServer,
  type McpDelivery,
} from "../../src/integrations/mcp/mcpServerStore.js";

const SCP = { mode: "scp" as const, host: "sift.example.com", user: "analyst", remoteDir: "/cases/incoming" };

const server = (over: Partial<McpServer> = {}, delivery: Partial<McpDelivery> = {}): McpServer => ({
  id: "sift-mcp",
  label: "SIFT",
  enabled: true,
  allowedTools: ["run_command"],
  allowedCommands: ["vol.py"],
  agentEnabled: false,
  timeoutMs: 1000,
  delivery: { ...DEFAULT_DELIVERY, ...delivery },
  ...over,
});

/** A Claude Code that reports whatever the tool "returned". Records what it was asked to run. */
function fakeClaude(text = "ok", seen?: ClaudeRunOptions[]): ClaudeRunner {
  return async (opts) => {
    seen?.push(opts);
    return {
      code: 0,
      stderr: "",
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

// Delivery opens the target through the case-file guard (#1847), so the case and file are real.
let root: string;
let MEM: string;
let deliverySource: DeliverySource;
const STAGED = /^\/cases\/incoming\/[0-9a-f]{12}_mem\.raw$/;

beforeEach(async () => {
  transfers = [];
  root = await mkdtemp(join(tmpdir(), "dfir-mcprun-"));
  await mkdir(join(root, "c1"), { recursive: true });
  MEM = join(root, "c1", "mem.raw");
  await writeFile(MEM, "memory");
  deliverySource = { casesRoot: root, caseDir: join(root, "c1"), stagingDir: join(root, ".export-staging") };
});

describe("substituteTarget", () => {
  it("replaces the placeholder inside an argv array without re-splitting", () => {
    const out = substituteTarget(
      { command: ["vol.py", "-f", "<target>", "pslist"] },
      "/cases/incoming/mem raw.bin",
    );
    expect(out).toEqual({ command: ["vol.py", "-f", "/cases/incoming/mem raw.bin", "pslist"] });
  });

  it("replaces it inside a larger string", () => {
    expect(substituteTarget({ command: "strings <target> | head" }, "/x/y.bin")).toEqual({
      command: "strings /x/y.bin | head",
    });
  });

  it("replaces every occurrence", () => {
    expect(substituteTarget({ a: "<target>", b: ["<target>"] }, "/p")).toEqual({ a: "/p", b: ["/p"] });
  });

  it("leaves non-string values alone", () => {
    expect(substituteTarget({ timeout: 30, save: true, x: null }, "/p")).toEqual({
      timeout: 30,
      save: true,
      x: null,
    });
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
      {
        server: server({}, SCP),
        claudeRunner: fakeClaude("pid 4 System", calls),
        transferRunner,
        deliverySource,
        teamMode: false,
      },
      {
        tool: "run_command",
        args: { command: ["vol.py", "-f", "<target>", "pslist"] },
        targetPath: MEM,
      },
    );

    expect(transfers[0].binary).toBe("scp");
    // Exactly one tool may be reached, and the delivered path is what gets asked for.
    expect(calls[0].args[calls[0].args.indexOf("--allowed-tools") + 1]).toBe("mcp__sift-mcp__run_command");
    expect(outcome.remotePath).toMatch(STAGED);
    expect(argsAsked(calls[0])).toEqual({ command: ["vol.py", "-f", outcome.remotePath, "pslist"] });
    expect(outcome.text).toBe("pid 4 System");
  });

  it("runs a tool that needs no evidence at all", async () => {
    const outcome = await runMcpTool(
      {
        server: server({ allowedTools: ["check_lolbin"] }),
        claudeRunner: fakeClaude("{}"),
        transferRunner,
        deliverySource,
        teamMode: false,
      },
      { tool: "check_lolbin", args: { filename: "certutil.exe" } },
    );

    expect(transfers).toHaveLength(0);
    expect(outcome.destination).toBeUndefined();
    expect(outcome.text).toBe("{}");
  });

  // Evidence must not cross the network for a call that was never going to be permitted.
  it("refuses a disallowed tool before delivering anything", async () => {
    await expect(
      runMcpTool(
        {
          server: server({ allowedTools: ["check_tools"] }, SCP),
          claudeRunner: fakeClaude(),
          transferRunner,
          deliverySource,
          teamMode: false,
        },
        { tool: "run_command", args: { command: ["vol.py"] }, targetPath: MEM },
      ),
    ).rejects.toThrow(/not allowed to run the tool/);

    expect(transfers).toHaveLength(0);
  });

  it("refuses a disallowed command before delivering anything", async () => {
    await expect(
      runMcpTool(
        {
          server: server({}, SCP),
          claudeRunner: fakeClaude(),
          transferRunner,
          deliverySource,
          teamMode: false,
        },
        { tool: "run_command", args: { command: ["curl", "http://x"] }, targetPath: MEM },
      ),
    ).rejects.toThrow(/not allowed to run "curl"/);

    expect(transfers).toHaveLength(0);
  });

  // Otherwise the file crosses the network and is never referenced.
  it("refuses a target the arguments never mention", async () => {
    await expect(
      runMcpTool(
        {
          server: server({}, SCP),
          claudeRunner: fakeClaude(),
          transferRunner,
          deliverySource,
          teamMode: false,
        },
        { tool: "run_command", args: { command: ["vol.py", "pslist"] }, targetPath: MEM },
      ),
    ).rejects.toThrow(/never reference <target>/);

    expect(transfers).toHaveLength(0);
  });

  // NOTE: the old isError check is gone with the MCP client. Claude Code returns text, not a
  // structured failure flag, so a tool that reports its own failure now comes back as ordinary
  // output and would be ingested. Preview is the mitigation — the analyst sees it before it lands.
  it("returns a tool's own failure text as output, having no way to tell it apart", async () => {
    const outcome = await runMcpTool(
      {
        server: server({}, SCP),
        claudeRunner: fakeClaude("unsupported profile"),
        transferRunner,
        deliverySource,
        teamMode: false,
      },
      {
        tool: "run_command",
        args: { command: ["vol.py", "-f", "<target>"] },
        targetPath: MEM,
      },
    );
    expect(outcome.text).toBe("unsupported profile");
  });

  it("records the custody transfer with the destination", async () => {
    const seen: string[] = [];
    await runMcpTool(
      {
        server: server({}, SCP),
        claudeRunner: fakeClaude(),
        transferRunner,
        deliverySource,
        teamMode: false,
        recordTransfer: async (d) => {
          seen.push(d);
        },
      },
      {
        tool: "run_command",
        args: { command: ["vol.py", "-f", "<target>"] },
        targetPath: MEM,
      },
    );

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/^analyst@sift\.example\.com:\/cases\/incoming\/[0-9a-f]{12}_mem\.raw$/);
  });

  it("removes the staged copy after a successful run", async () => {
    await runMcpTool(
      {
        server: server({}, SCP),
        claudeRunner: fakeClaude(),
        transferRunner,
        deliverySource,
        teamMode: false,
      },
      {
        tool: "run_command",
        args: { command: ["vol.py", "-f", "<target>"] },
        targetPath: MEM,
      },
    );

    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
    expect(transfers[1].args).toContain("rm");
  });

  // A copy left behind after a crashed run is evidence on a machine nobody is tracking.
  it("removes the staged copy even when the tool call fails", async () => {
    const failing: ClaudeRunner = async () => {
      throw new Error("claude exploded");
    };

    await expect(
      runMcpTool(
        { server: server({}, SCP), claudeRunner: failing, transferRunner, deliverySource, teamMode: false },
        {
          tool: "run_command",
          args: { command: ["vol.py", "-f", "<target>"] },
          targetPath: MEM,
        },
      ),
    ).rejects.toThrow();

    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
  });

  it("reports progress through the phases", async () => {
    const steps: string[] = [];
    await runMcpTool(
      {
        server: server({}, SCP),
        claudeRunner: fakeClaude(),
        transferRunner,
        deliverySource,
        teamMode: false,
        onProgress: (d) => steps.push(d),
      },
      {
        tool: "run_command",
        args: { command: ["vol.py", "-f", "<target>"] },
        targetPath: MEM,
      },
    );

    expect(steps).toEqual([
      "delivering evidence to SIFT",
      "running run_command on SIFT",
      "removing the staged copy",
    ]);
  });

  it("refuses to deliver a target without the case it belongs to (#1847)", async () => {
    await expect(
      runMcpTool(
        { server: server({}, SCP), claudeRunner: fakeClaude(), transferRunner, teamMode: false },
        { tool: "run_command", args: { command: ["vol.py", "-f", "<target>"] }, targetPath: MEM },
      ),
    ).rejects.toThrow(/needs the case it belongs to/);
    expect(transfers).toHaveLength(0);
  });

  it("uses a shared mount without copying anything", async () => {
    const s = server({}, { mode: "remote-path", localPrefix: root, remotePrefix: "/mnt/dfir" });
    const calls: ClaudeRunOptions[] = [];

    const outcome = await runMcpTool(
      { server: s, claudeRunner: fakeClaude("ok", calls), transferRunner, deliverySource, teamMode: false },
      {
        tool: "run_command",
        args: { command: ["vol.py", "-f", "<target>"] },
        targetPath: MEM,
      },
    );

    expect(transfers).toHaveLength(0);
    expect(argsAsked(calls[0])).toEqual({ command: ["vol.py", "-f", "/mnt/dfir/c1/mem.raw"] });
    expect(outcome.remotePath).toBe("/mnt/dfir/c1/mem.raw");
  });

  // #1856: team mode hands the host a private copy on the share, removed whatever the run did.
  describe("team-mode remote-path copy", () => {
    const shared = { mode: "remote-path" as const, localPrefix: "", remotePrefix: "" };
    const copies = async (): Promise<string[]> => readdir(join(root, ".mcp-delivery")).catch(() => []);
    const input = () => ({
      tool: "run_command",
      args: { command: ["vol.py", "-f", "<target>"] },
      targetPath: MEM,
    });

    it("hands the tool the copy's path and removes the copy after the run", async () => {
      const calls: ClaudeRunOptions[] = [];
      let during: string[] = [];
      const claude: ClaudeRunner = async (opts) => {
        during = await copies();
        return fakeClaude("ok", calls)(opts);
      };
      const outcome = await runMcpTool(
        {
          server: server({}, shared),
          claudeRunner: claude,
          transferRunner,
          deliverySource,
          teamMode: true,
          aclRunner: aclStub(),
        },
        input(),
      );

      expect(during).toHaveLength(1);
      expect(outcome.remotePath).toContain(join(root, ".mcp-delivery"));
      expect(argsAsked(calls[0])).toEqual({ command: ["vol.py", "-f", outcome.remotePath] });
      expect(await copies()).toEqual([]);
    });

    it("passes the ACL runner through to the Windows check (#1863)", async () => {
      const real = Object.getOwnPropertyDescriptor(process, "platform")!;
      Object.defineProperty(process, "platform", { ...real, value: "win32" });
      const seen: string[][] = [];
      try {
        await runMcpTool(
          {
            server: server({}, shared),
            claudeRunner: fakeClaude("ok", []),
            transferRunner,
            deliverySource,
            teamMode: true,
            aclRunner: aclStub(() => [], seen),
          },
          input(),
        );
      } finally {
        Object.defineProperty(process, "platform", real);
      }

      expect(seen).toHaveLength(1);
    });

    it("removes the copy even when the tool call fails", async () => {
      const failing: ClaudeRunner = async () => {
        throw new Error("claude exploded");
      };
      await expect(
        runMcpTool(
          {
            server: server({}, shared),
            claudeRunner: failing,
            transferRunner,
            deliverySource,
            teamMode: true,
            aclRunner: aclStub(),
          },
          input(),
        ),
      ).rejects.toThrow(/claude exploded/);

      expect(await copies()).toEqual([]);
    });
  });
});
