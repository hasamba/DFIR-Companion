import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, realpath, stat, utimes } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, posix, relative } from "node:path";
import {
  openCaseFile,
  snapshotCaseFile,
  type CaseFileSnapshot,
  type CaseScope,
} from "../../storage/caseFileRead.js";
import { SHARED_DELIVERY_DIRNAME } from "../../storage/exportStaging.js";
import { retryTransientSpawn } from "../velociraptor/velociraptorApi.js";
import { getServerLogger } from "../../logging/serverLogger.js";
import type { McpServer } from "./mcpServerStore.js";

// Getting evidence onto the analysis host (#296 §6). This layer, not MCP, is the hard part: a
// multi-gigabyte memory image cannot travel inside a JSON-RPC argument, and MCP has no file-transfer
// primitive. Phase 0 confirmed it — sift-mcp has no ingestion tool at all, only `run_command`
// referencing paths that must ALREADY be on the SIFT box.
//
// Two modes:
//   remote-path  the file is already visible to the server over a shared mount; rewrite the local
//                prefix to the remote one and hand over the path. Nothing is copied in single-user
//                mode. In team mode a private copy on the share is handed over instead (#1856).
//   scp          push the bytes, run, then delete the staged copy.
//
// Spawn discipline is the external tool runner's, verbatim in substance: NO shell, every argument a
// discrete argv element, windowsHide, a timeout that kills the child, and the shared transient-spawn
// retry for the AV/sync-client EPERM lock. The runner is injected so no test spawns a real process.
//
// KNOWN LIMITS of the scp mode, stated rather than discovered:
//   - Progress is measured by polling the staged file size over SSH. A host without GNU `stat`
//     still transfers correctly, but reports only the source size and elapsed time.
//   - No resume. A dropped connection means starting over.
//   - Host keys must already be trusted. BatchMode is on and StrictHostKeyChecking is NOT disabled,
//     so an unknown host fails closed with a clear error rather than trusting whatever answered.
//     That is the correct trade: silently accepting an unverified key would hand evidence to
//     whatever holds the address.

export interface TransferResult {
  stdout: string;
  stderr: string;
  code: number;
}

/**
 * Spawns `binary` with the given argv and resolves with its exit code. Injected rather than
 * constructed inline — the same discipline ToolRunner uses — so delivery is testable without a
 * network or an ssh key.
 */
export type TransferRunner = (
  binary: string,
  args: string[],
  opts: { timeoutMs: number; signal?: AbortSignal },
) => Promise<TransferResult>;

export interface DeliveredTarget {
  /** The path to hand the MCP tool — on the analysis host, not here. */
  remotePath: string;
  /** Human-readable "where it went", for the custody chain and the activity log. */
  destination: string;
  /** Removes the staged copy. Absent for remote-path, where nothing was staged. */
  cleanup?: () => Promise<void>;
}

/**
 * The case the evidence belongs to (#1847). The file is opened through storage/caseFileRead.ts — no
 * link at the file or above it, no FIFO, no hard link — and scp sends a private SNAPSHOT taken from
 * that open handle, never the case path: scp opens its source by name, and a name can be swapped for
 * a link to another case's file between any check and scp's own open. The snapshot lives in its own
 * mkdtemp folder under `stagingDir` and is removed whatever happens.
 */
export interface DeliverySource extends CaseScope {
  stagingDir: string;
}

export interface DeliveryContext {
  runner: TransferRunner;
  source: DeliverySource;
  /**
   * Team auth is on (#1856). The analysis host opens a remote-path target BY NAME, later, and in team
   * mode a second writer could swap that name for a link after the check — so team mode hands over a
   * private copy on the share instead. Required and passed by the caller: this module reads no env.
   */
  teamMode: boolean;
  signal?: AbortSignal;
  /** Byte progress for SCP delivery. Raw SSH diagnostics are never exposed. */
  onProgress?: (done: number, total: number) => void;
  /** Injectable only to keep the progress-polling test fast. */
  progressIntervalMs?: number;
  /** Injectable only to keep the keep-alive test fast. */
  keepAliveMs?: number;
  /** Injectable only to simulate a delivery folder this process cannot tighten (a 0777 CIFS mount). */
  chmod?: (path: string, mode: number) => Promise<void>;
  /**
   * Records that the evidence left this machine. Called after the bytes land and BEFORE the remote
   * path is handed back, so a transfer that succeeded always has its chain entry — wiring custody
   * at the call site instead would make it forgettable, and a custody chain that omits "this left
   * the building" is not a custody chain (#231).
   */
  recordTransfer?: (destination: string, sent?: { sha256: string }) => Promise<void>;
}

/**
 * A filename safe to put in a remote command.
 *
 * ssh runs its remote argument through a shell on the far side, so a filename carrying shell
 * metacharacters is remote command injection — and filenames here come from evidence, which is
 * attacker-influenced by definition. Rather than relying on quoting being right, the name is
 * reduced to a charset with nothing to quote. Mirrors persistEvidence's rule for stored evidence.
 */
export function safeRemoteName(localPath: string): string {
  const cleaned = basename(localPath)
    .replace(/[^\w.\-]+/g, "_")
    .slice(0, 120);
  // "." and ".." survive the charset filter and are not filenames.
  return /^\.+$/.test(cleaned) ? "evidence.dat" : cleaned || "evidence.dat";
}

/**
 * Single-quote a string for a POSIX shell. Belt to safeRemoteName's braces: the remote path is
 * already metacharacter-free, and this makes it not matter if that ever regresses.
 */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Where a rewritten local path lands on the analysis host, or an error explaining why it cannot. */
export function rewriteToRemote(server: McpServer, localPath: string): string {
  const { localPrefix, remotePrefix } = server.delivery;
  // No prefixes configured = the mount is at the same path on both sides, which is the common
  // NFS/SMB case and needs no rewriting.
  if (!localPrefix && !remotePrefix) return localPath;
  if (!localPath.startsWith(localPrefix)) {
    throw new Error(
      `"${localPath}" is not under this server's local prefix "${localPrefix}", so the analysis host cannot reach it`,
    );
  }
  const rest = localPath
    .slice(localPrefix.length)
    .replace(/^[/\\]+/, "")
    .split(/[/\\]+/)
    .filter(Boolean);
  return posix.join(remotePrefix || "/", ...rest);
}

function scpBaseArgs(server: McpServer): string[] {
  const args: string[] = [
    // Never prompt: no password, no host-key confirmation. Without this a first connection to an
    // unknown host hangs forever on a prompt nobody can answer.
    "-o",
    "BatchMode=yes",
  ];
  if (server.delivery.identityFile) args.push("-i", server.delivery.identityFile);
  return args;
}

function remoteLogin(server: McpServer): string {
  const { user, host } = server.delivery;
  return user ? `${user}@${host}` : host;
}

/**
 * Put `localPath` where `server` can read it, and return the path to hand its tools.
 *
 * Call this BEFORE the tool call, and the returned cleanup AFTER it — the staged copy is deleted
 * best-effort, because failing an analysis whose result already arrived, over a leftover temp file,
 * helps nobody.
 */
export async function deliver(
  server: McpServer,
  localPath: string,
  ctx: DeliveryContext,
): Promise<DeliveredTarget> {
  if (server.delivery.mode === "remote-path") {
    if (ctx.teamMode) return deliverSharedCopy(server, localPath, ctx);
    const remotePath = rewriteToRemote(server, localPath);
    // Nothing is read here, but the file must be one this case may hand over: a link, a FIFO or a
    // hard link is refused before the path leaves. The analysis host still opens the path by name
    // later — a shared mount cannot carry a handle. Single-user mode accepts that: no second writer
    // exists to swap the name (#1856, owner decision).
    const judged = await openCaseFile(ctx.source, localPath);
    await judged.handle.close();
    const destination = `${server.label} (shared path ${remotePath})`;
    // Nothing is copied, but the evidence is being handed to another system to read, so the chain
    // records it. Over-recording a custody event is recoverable; under-recording one is not.
    await ctx.recordTransfer?.(destination);
    return { remotePath, destination };
  }
  const snapshot = await snapshotCaseFile(ctx.source, localPath, ctx.source.stagingDir, {
    name: safeRemoteName(localPath),
    ...(ctx.signal ? { signal: ctx.signal } : {}),
  });
  try {
    return await sendSnapshot(server, localPath, snapshot, ctx);
  } finally {
    const left = await snapshot.dispose();
    if (left) getServerLogger().warn(`MCP delivery could not remove its local snapshot: ${left}`);
  }
}

/** How often a team-mode copy's folder is touched, so the day-old staging sweep never takes a live one. */
const SHARED_KEEPALIVE_MS = 60 * 60 * 1000;

function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * The shared delivery folder, checked (#1856): a real directory at `<casesRoot>/.mcp-delivery`, not a
 * link, and on POSIX writable by nobody but this process's user — a folder another user can write is
 * one where the copy could be renamed away and a link put in its place before the host opens it.
 * Resolves with its path as the prefix rewrite sees it, and its real path for the after-copy check.
 */
async function sharedDeliveryRoot(
  server: McpServer,
  ctx: DeliveryContext,
): Promise<{ root: string; rootReal: string }> {
  const { casesRoot } = ctx.source;
  const { localPrefix } = server.delivery;
  // Outside every case folder, and reachable by the host. A prefix below the cases root would put
  // the copy inside a case, where a case writer could reach it — refused rather than risked.
  if (localPrefix && !isInside(localPrefix, casesRoot)) {
    throw new Error(
      `team mode copies evidence into the cases root before handing it over, but the cases root is not inside ` +
        `the local prefix "${localPrefix}" of ${server.label} — set the local prefix to the cases root or above it`,
    );
  }
  const root = join(casesRoot, SHARED_DELIVERY_DIRNAME);
  rewriteToRemote(server, root); // fails before anything is copied if the host cannot reach it
  await mkdir(root, { recursive: true, mode: 0o755 });
  let info = await lstat(root);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(
      `the MCP delivery folder ${root} is not a plain folder — refusing to copy evidence there`,
    );
  }
  if (process.platform !== "win32") {
    // Whoever can write the cases root can rename .mcp-delivery away and put a link in its place,
    // unless the sticky bit stops them renaming entries they do not own.
    const parent = await stat(casesRoot);
    if ((parent.mode & 0o022) !== 0 && (parent.mode & 0o1000) === 0) {
      throw new Error(
        `other users can write the cases root ${casesRoot}, so a copy handed over from it could be swapped ` +
          `before the analysis host reads it — make it writable by the Companion's user only, or set the sticky bit`,
      );
    }
    // mkdir's mode is masked by umask (a 0700 folder the host cannot enter) and an existing folder
    // keeps its own: set it outright, then check what actually stuck.
    await (ctx.chmod ?? chmod)(root, 0o755).catch(() => undefined);
    info = await lstat(root);
    if (info.isSymbolicLink() || (info.mode & 0o022) !== 0) {
      throw new Error(
        `other users can write the MCP delivery folder ${root}, so a copy there could be swapped before ` +
          `the analysis host reads it — make it writable by the Companion's user only`,
      );
    }
  }
  return { root, rootReal: await realpath(root) };
}

/** Read bits for group/other only where the original file had them, so the copy is never MORE readable. */
function sharedModes(originalMode: number): { file: number; dir: number } {
  const file = 0o400 | (originalMode & 0o044);
  const dir = 0o700 | (originalMode & 0o040 ? 0o050 : 0) | (originalMode & 0o004 ? 0o005 : 0);
  return { file, dir };
}

/**
 * Team-mode remote-path delivery (#1856): copy the checked bytes into a private folder on the share,
 * hand the host THAT path, record the copy's hash, and remove it after the run — or at once, when
 * anything after the copy fails. The case path can be swapped afterwards; the copy cannot, because
 * only this process's user can write its folder.
 */
async function deliverSharedCopy(
  server: McpServer,
  localPath: string,
  ctx: DeliveryContext,
): Promise<DeliveredTarget> {
  const { root, rootReal } = await sharedDeliveryRoot(server, ctx);
  const snapshot = await snapshotCaseFile(ctx.source, localPath, root, {
    name: uniqueRemoteName(localPath),
    ...(ctx.signal ? { signal: ctx.signal } : {}),
  });
  const folder = dirname(snapshot.path);
  let keepAlive: NodeJS.Timeout | undefined;
  const dispose = async (): Promise<string | null> => {
    if (keepAlive) clearInterval(keepAlive);
    keepAlive = undefined;
    const left = await snapshot.dispose();
    if (left) getServerLogger().warn(`MCP delivery could not remove its shared copy: ${left}`);
    return left;
  };
  try {
    // The copy's folder must still be where it was made: a root swapped for a link mid-copy is refused.
    if ((await realpath(folder)) !== join(rootReal, basename(folder))) {
      throw new Error(
        `the MCP delivery folder moved while evidence was copied into it — refusing to hand it over`,
      );
    }
    const modes = sharedModes(snapshot.mode);
    await chmod(snapshot.path, modes.file);
    await chmod(folder, modes.dir);
    const remotePath = rewriteToRemote(server, snapshot.path);
    const destination = `${server.label} (copied to shared path ${remotePath})`;
    await ctx.recordTransfer?.(destination, { sha256: snapshot.sha256 });
    // A long run must not look like a day-old leftover to the staging sweep.
    keepAlive = setInterval(() => {
      const now = new Date();
      void utimes(folder, now, now).catch(() => undefined);
    }, ctx.keepAliveMs ?? SHARED_KEEPALIVE_MS);
    keepAlive.unref();
    return {
      remotePath,
      destination,
      // Best-effort, like the SCP cleanup — a leftover is logged and swept after a day.
      cleanup: async () => {
        await dispose();
      },
    };
  } catch (err) {
    const left = await dispose();
    if (left === null) throw err;
    throw new Error(
      `${(err as Error).message} — and the shared copy could not be removed (${left}); remove it by hand`,
      { cause: err },
    );
  }
}

/** A remote name no other delivery shares, so concurrent jobs never overwrite or delete each other's copy. */
function uniqueRemoteName(localPath: string): string {
  return `${randomBytes(6).toString("hex")}_${safeRemoteName(localPath)}`;
}

function sshArgsFor(server: McpServer): string[] {
  const { port } = server.delivery;
  const sshArgs = [...scpBaseArgs(server)];
  if (port && port !== 22) sshArgs.push("-p", String(port));
  return sshArgs;
}

/** Removes the remote copy. Resolves with an error message, or null when it is gone. Never throws. */
async function removeRemote(
  server: McpServer,
  ctx: DeliveryContext,
  remotePath: string,
): Promise<string | null> {
  const sshArgs = sshArgsFor(server);
  // `--` then a quoted path: rm must not read a filename beginning with "-" as a flag, and the far
  // side runs this through a shell.
  sshArgs.push(remoteLogin(server), "rm", "-f", "--", shellQuote(remotePath));
  try {
    const r = await ctx.runner("ssh", sshArgs, { timeoutMs: server.delivery.timeoutMs });
    return r.code === 0 ? null : `ssh rm exited ${r.code}`;
  } catch (err) {
    return (err as Error).message;
  }
}

async function sendSnapshot(
  server: McpServer,
  localPath: string,
  snapshot: CaseFileSnapshot,
  ctx: DeliveryContext,
): Promise<DeliveredTarget> {
  const { remoteDir, port, timeoutMs } = server.delivery;
  const remotePath = posix.join(remoteDir, uniqueRemoteName(localPath));
  const login = remoteLogin(server);
  const destination = `${login}:${remotePath}`;

  const args = [...scpBaseArgs(server)];
  if (port && port !== 22) args.push("-P", String(port));
  args.push("--", snapshot.path, `${login}:${remotePath}`);

  const total = snapshot.bytes;
  if (total > 0) ctx.onProgress?.(0, total);
  let probing = false;
  const probe = async (): Promise<void> => {
    if (probing || !ctx.onProgress || total <= 0) return;
    probing = true;
    const sshArgs = sshArgsFor(server);
    sshArgs.push(login, "stat", "-c", "%s", "--", shellQuote(remotePath));
    try {
      const measured = await ctx.runner("ssh", sshArgs, {
        timeoutMs: Math.min(timeoutMs, 10_000),
        ...(ctx.signal ? { signal: ctx.signal } : {}),
      });
      const bytes = Number(measured.stdout.trim());
      if (measured.code === 0 && Number.isFinite(bytes) && bytes >= 0) {
        ctx.onProgress(Math.min(bytes, total), total);
      }
    } catch {
      // Progress is advisory. SCP remains authoritative and will report its own failure.
    } finally {
      probing = false;
    }
  };
  const progressTimer =
    ctx.onProgress && total > 0
      ? setInterval(() => {
          void probe();
        }, ctx.progressIntervalMs ?? 2_000)
      : undefined;
  progressTimer?.unref();
  // From here on a copy may exist on the remote host (scp can fail, time out or be cancelled after
  // writing part of it). Any failure removes it before the error reaches the caller — a copy nobody
  // tracks is evidence sitting on a machine outside the custody chain.
  try {
    let result: TransferResult;
    try {
      result = await retryTransientSpawn(() => ctx.runner("scp", args, { timeoutMs, signal: ctx.signal }));
    } finally {
      if (progressTimer) clearInterval(progressTimer);
    }
    if (result.code !== 0) {
      throw new Error(
        `scp to ${destination} failed (exit ${result.code})` +
          `${result.stderr.trim() ? `: ${result.stderr.trim().split("\n").slice(0, 3).join(" ")}` : ""}`,
      );
    }
    if (total > 0) ctx.onProgress?.(total, total);
    await ctx.recordTransfer?.(destination, { sha256: snapshot.sha256 });
  } catch (err) {
    const left = await removeRemote(server, ctx, remotePath);
    if (left === null) throw err;
    throw new Error(
      `${(err as Error).message} — and the copy at ${destination} could not be removed (${left}); remove it by hand`,
      { cause: err },
    );
  }

  return {
    remotePath,
    destination,
    // Best-effort by design — see the note on deliver().
    cleanup: async () => {
      await removeRemote(server, ctx, remotePath);
    },
  };
}

/** How long a stopped transfer gets to exit after each signal. */
const STOP_GRACE_MS = 5_000;

/**
 * The real transfer runner. Mirrors spawnToolOnce's discipline: no shell, discrete argv,
 * windowsHide, a timeout that kills the child. Adds an AbortSignal, which a tool run does not need
 * but a multi-gigabyte copy does — without it a 16 GB transfer would ignore the job's cancel button.
 */
export function spawnTransferRunner(): TransferRunner {
  return (binary, args, opts) =>
    new Promise<TransferResult>((resolve, reject) => {
      if (opts.signal?.aborted) {
        reject(new Error(`${binary} cancelled before it started`));
        return;
      }

      let child;
      try {
        child = spawn(binary, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
      } catch (e) {
        // Windows throws EPERM synchronously rather than via the 'error' event.
        const err = new Error(`cannot run "${binary}": ${(e as Error).message}`) as Error & {
          spawnCode?: string;
        };
        err.spawnCode = (e as NodeJS.ErrnoException).code || "ESPAWN";
        reject(err);
        return;
      }

      let stdout = "";
      let stderr = "";
      let done = false;
      const finish = (fn: () => void): void => {
        if (!done) {
          done = true;
          cleanup();
          fn();
        }
      };

      // A stopped transfer settles only once the child has EXITED (#1847): the caller removes the
      // remote copy next, and an scp still running could write it again after that removal. A
      // child that ignores the polite signal is killed hard; one that still does not exit is given
      // up on after a second grace period so the job cannot hang.
      let stopped: Error | undefined;
      const graceTimers: NodeJS.Timeout[] = [];
      const stop = (why: Error): void => {
        if (stopped || done) return;
        stopped = why;
        child.kill();
        graceTimers.push(
          setTimeout(() => child.kill("SIGKILL"), STOP_GRACE_MS),
          setTimeout(() => finish(() => reject(why)), 2 * STOP_GRACE_MS),
        );
      };
      const timer = setTimeout(
        () => stop(new Error(`${binary} timed out after ${opts.timeoutMs}ms`)),
        opts.timeoutMs,
      );

      const onAbort = (): void => stop(new Error(`${binary} cancelled`));
      opts.signal?.addEventListener("abort", onAbort, { once: true });

      function cleanup(): void {
        clearTimeout(timer);
        graceTimers.forEach(clearTimeout);
        opts.signal?.removeEventListener("abort", onAbort);
      }

      // A chunk boundary is a BYTE boundary, so a multi-byte character can straddle two chunks and
      // decoding each chunk on its own would leave U+FFFD in the middle of the remote path scp is
      // complaining about. setEncoding holds the incomplete tail back until the rest arrives.
      child.stdout?.setEncoding("utf8");
      child.stderr?.setEncoding("utf8");
      child.stdout?.on("data", (chunk: string) => {
        stdout += chunk;
      });
      // scp is quiet on success and terse on failure, so stderr is the whole diagnostic. Cap it so a
      // pathological failure loop cannot grow it without bound.
      child.stderr?.on("data", (chunk: string) => {
        if (stderr.length < 64 * 1024) stderr += chunk;
      });

      child.on("error", (e) => {
        const err = new Error(`cannot run "${binary}": ${e.message}`) as Error & { spawnCode?: string };
        err.spawnCode = (e as NodeJS.ErrnoException).code || "ESPAWN";
        finish(() => reject(err));
      });
      child.on("close", (code) =>
        finish(() => (stopped ? reject(stopped) : resolve({ stdout, stderr, code: code ?? 0 }))),
      );
    });
}
