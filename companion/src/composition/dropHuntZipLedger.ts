/**
 * Resume state for a hunt-export zip in the drop folder (#2714):
 * `state/drop-zip-progress/<archive id>.jsonl`. The first line names the zip; then one line per
 * member as soon as its outcome is known — imported, or failed with the reason (a failed member is
 * already extracted to `_failed/`, so a resume must neither import nor extract it again).
 *
 * A crash or restart mid-zip leaves the file behind; the next run of the same archive skips every
 * member it names. The zip handler never deletes it — the zip has not moved yet when the handler
 * returns, and a crash between the two would replay the whole archive. A later sweep removes it once
 * no listed zip matches (`pruneHuntZipLedgers`).
 *
 * The id is the zip's relpath plus its size and every central-directory entry's raw name, CRC and
 * sizes: a different archive dropped under the same name never inherits another's progress.
 *
 * Residual window, the same one every dropped file has between its import and its move: a crash
 * after a member's import finished and before its line is appended imports that member again.
 */
import { createHash } from "node:crypto";
import { appendFile, mkdir, readdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import type { DropFileStat } from "../analysis/dropScan.js";
import type { ZipMember } from "../storage/zipMembers.js";
import { withCaseWrite } from "../storage/caseIncarnation.js";
import type { ImportCounts } from "../analysis/importNotification.js";

export const HUNT_ZIP_LEDGER_DIR = "drop-zip-progress";

export interface MemberOutcome {
  ok: boolean;
  reason?: string;
  /** An imported member's caveat (a guessed format, a streamed import's coverage disclosure). */
  warning?: string;
  /** Skipped by the analyst under #2746 (records written before #2755): neither imported nor failed. */
  skipped?: boolean;
  /** Over a size limit, extracted to drop/_held/ for the analyst (#2755): neither imported nor failed. */
  held?: boolean;
  /** An imported member's settled counts (#2982), kept so a resumed zip still reports them. */
  counts?: ImportCounts;
}

export interface HuntZipLedger {
  /** Outcomes already recorded, by member name. */
  readonly done: Map<string, MemberOutcome>;
  record(member: string, outcome: MemberOutcome): Promise<void>;
}

/** The archive's identity: relpath, size, and the whole central directory's names, CRCs and sizes. */
export function huntZipId(relpath: string, size: number, members: readonly ZipMember[]): string {
  const h = createHash("sha256").update(`${relpath}\0${size}\0`);
  for (const m of members) {
    const e = m.entry;
    h.update(e.fileNameRaw ?? Buffer.from(m.name));
    h.update(`\0${e.crc32}\0${e.compressedSize}\0${e.uncompressedSize}\n`);
  }
  return h.digest("hex").slice(0, 32);
}

/** Open (or start) the ledger of one archive. */
export async function openHuntZipLedger(
  stateDir: string,
  id: string,
  zip: { relpath: string; size: number },
): Promise<HuntZipLedger> {
  const dir = join(stateDir, HUNT_ZIP_LEDGER_DIR);
  const path = join(dir, `${id}.jsonl`);
  const done = new Map<string, MemberOutcome>();
  let text = "";
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  for (const line of text.split("\n")) parseLine(line, done);
  const append = (obj: object): Promise<void> =>
    withCaseWrite(path, async () => {
      await mkdir(dir, { recursive: true });
      await appendFile(path, JSON.stringify(obj) + "\n", "utf8");
    });
  if (!text) await append({ zip: zip.relpath, size: zip.size });
  return {
    done,
    record: async (member, outcome) => {
      await append({
        member,
        ok: outcome.ok,
        ...(outcome.reason ? { reason: outcome.reason } : {}),
        ...(outcome.warning ? { warning: outcome.warning } : {}),
        ...(outcome.skipped ? { skipped: true } : {}),
        ...(outcome.held ? { held: true } : {}),
        ...(outcome.counts ? { counts: outcome.counts } : {}),
      });
      done.set(member, outcome);
    },
  };
}

function parseLine(line: string, done: Map<string, MemberOutcome>): void {
  if (!line.trim()) return;
  try {
    const v = JSON.parse(line) as {
      member?: unknown;
      ok?: unknown;
      reason?: unknown;
      warning?: unknown;
      skipped?: unknown;
      held?: unknown;
      counts?: unknown;
    };
    if (typeof v.member !== "string" || typeof v.ok !== "boolean") return;
    done.set(v.member, {
      ok: v.ok,
      ...(typeof v.reason === "string" ? { reason: v.reason } : {}),
      ...(typeof v.warning === "string" ? { warning: v.warning } : {}),
      ...(v.skipped === true ? { skipped: true } : {}),
      ...(v.held === true ? { held: true } : {}),
      ...countsField(v.counts),
    });
  } catch {
    /* a torn last line (crash mid-append) */
  }
}

/** A recorded member's counts, read back only when well-formed — a line without them stays unknown (#2982). */
function countsField(v: unknown): { counts?: ImportCounts } {
  if (!v || typeof v !== "object") return {};
  const c = v as Record<string, unknown>;
  const count = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0;
  if (!count(c.added) || !count(c.highCritical)) return {};
  return {
    counts: {
      added: c.added,
      highCritical: c.highCritical,
      ...(count(c.superAdded) ? { superAdded: c.superAdded } : {}),
    },
  };
}

/** Remove every ledger whose zip is no longer listed in drop/ (it was moved to _processed/_failed). */
export async function pruneHuntZipLedgers(stateDir: string, listing: readonly DropFileStat[]): Promise<void> {
  const dir = join(stateDir, HUNT_ZIP_LEDGER_DIR);
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return; // no ledgers
  }
  const listed = new Set(listing.map((f) => `${f.relpath.replace(/\\/g, "/")}\0${f.size}`));
  for (const name of names) {
    if (!name.endsWith(".jsonl")) continue;
    const path = join(dir, name);
    const head = await readFile(path, "utf8").then(
      (t) => t.split("\n", 1)[0],
      () => "",
    );
    let zip: { zip?: unknown; size?: unknown } = {};
    try {
      zip = JSON.parse(head) as typeof zip;
    } catch {
      /* unreadable head: treat as orphaned */
    }
    if (listed.has(`${String(zip.zip)}\0${String(zip.size)}`)) continue;
    await withCaseWrite(path, () => rm(path, { force: true })).catch(() => undefined);
  }
}
