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

export const HUNT_ZIP_LEDGER_DIR = "drop-zip-progress";

export interface MemberOutcome {
  ok: boolean;
  reason?: string;
}

export interface HuntZipLedger {
  /** Outcomes already recorded, by member name. */
  readonly done: ReadonlyMap<string, MemberOutcome>;
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
      await append({ member, ok: outcome.ok, ...(outcome.reason ? { reason: outcome.reason } : {}) });
      done.set(member, outcome);
    },
  };
}

function parseLine(line: string, done: Map<string, MemberOutcome>): void {
  if (!line.trim()) return;
  try {
    const v = JSON.parse(line) as { member?: unknown; ok?: unknown; reason?: unknown };
    if (typeof v.member !== "string" || typeof v.ok !== "boolean") return;
    done.set(v.member, { ok: v.ok, ...(typeof v.reason === "string" ? { reason: v.reason } : {}) });
  } catch {
    /* a torn last line (crash mid-append) */
  }
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
