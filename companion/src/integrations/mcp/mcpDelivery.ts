import { spawn } from "node:child_process";
import { basename, posix } from "node:path";
import { stat } from "node:fs/promises";
import { retryTransientSpawn } from "../velociraptor/velociraptorApi.js";
import type { McpServer } from "./mcpServerStore.js";

// Getting evidence onto the analysis host (#296 §6). This layer, not MCP, is the hard part: a
// multi-gigabyte memory image cannot travel inside a JSON-RPC argument, and MCP has no file-transfer
// primitive. Phase 0 confirmed it — sift-mcp has no ingestion tool at all, only `run_command`
// referencing paths that must ALREADY be on the SIFT box.
//
// Two modes:
//   remote-path  the file is already visible to the server over a shared mount; rewrite the local
//                prefix to the remote one and hand over the path. Nothing is copied.
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

export interface DeliveryContext {
  runner: TransferRunner;
  signal?: AbortSignal;
  /** Byte progress for SCP delivery. Raw SSH diagnostics are never exposed. */
  onProgress?: (done: number, total: number) => void;
  /** Injectable only to keep the progress-polling test fast. */
  progressIntervalMs?: number;
  /**
   * Records that the evidence left this machine. Called after the bytes land and BEFORE the remote
   * path is handed back, so a transfer that succeeded always has its chain entry — wiring custody
   * at the call site instead would make it forgettable, and a custody chain that omits "this left
   * the building" is not a custody chain (#231).
   */
  recordTransfer?: (destination: string) => Promise<void>;
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
    const remotePath = rewriteToRemote(server, localPath);
    const destination = `${server.label} (shared path ${remotePath})`;
    // Nothing is copied, but the evidence is being handed to another system to read, so the chain
    // records it. Over-recording a custody event is recoverable; under-recording one is not.
    await ctx.recordTransfer?.(destination);
    return { remotePath, destination };
  }

  const { remoteDir, port, timeoutMs } = server.delivery;
  const remotePath = posix.join(remoteDir, safeRemoteName(localPath));
  const login = remoteLogin(server);
  const destination = `${login}:${remotePath}`;

  const args = [...scpBaseArgs(server)];
  if (port && port !== 22) args.push("-P", String(port));
  args.push("--", localPath, `${login}:${remotePath}`);

  const total = await stat(localPath)
    .then((s) => s.size)
    .catch(() => 0);
  if (total > 0) ctx.onProgress?.(0, total);
  let probing = false;
  const probe = async (): Promise<void> => {
    if (probing || !ctx.onProgress || total <= 0) return;
    probing = true;
    const sshArgs = [...scpBaseArgs(server)];
    if (port && port !== 22) sshArgs.push("-p", String(port));
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

  await ctx.recordTransfer?.(destination);

  return {
    remotePath,
    destination,
    cleanup: async () => {
      const sshArgs = [...scpBaseArgs(server)];
      if (port && port !== 22) sshArgs.push("-p", String(port));
      // `--` then a quoted path: rm must not read a filename beginning with "-" as a flag, and the
      // far side runs this through a shell.
      sshArgs.push(login, "rm", "-f", "--", shellQuote(remotePath));
      try {
        await ctx.runner("ssh", sshArgs, { timeoutMs });
      } catch {
        // Best-effort by design — see the note on deliver().
      }
    },
  };
}

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

      const timer = setTimeout(() => {
        child.kill();
        finish(() => reject(new Error(`${binary} timed out after ${opts.timeoutMs}ms`)));
      }, opts.timeoutMs);

      const onAbort = (): void => {
        child.kill();
        finish(() => reject(new Error(`${binary} cancelled`)));
      };
      opts.signal?.addEventListener("abort", onAbort, { once: true });

      function cleanup(): void {
        clearTimeout(timer);
        opts.signal?.removeEventListener("abort", onAbort);
      }

      child.stdout?.on("data", (d: Buffer) => {
        stdout += d.toString();
      });
      // scp is quiet on success and terse on failure, so stderr is the whole diagnostic. Cap it so a
      // pathological failure loop cannot grow it without bound.
      child.stderr?.on("data", (d: Buffer) => {
        if (stderr.length < 64 * 1024) stderr += d.toString();
      });

      child.on("error", (e) => {
        const err = new Error(`cannot run "${binary}": ${e.message}`) as Error & { spawnCode?: string };
        err.spawnCode = (e as NodeJS.ErrnoException).code || "ESPAWN";
        finish(() => reject(err));
      });
      child.on("close", (code) => finish(() => resolve({ stdout, stderr, code: code ?? 0 })));
    });
}
