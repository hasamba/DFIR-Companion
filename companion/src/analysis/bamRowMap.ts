// Mapping for a BAM (Background Activity Moderator) finding — Velociraptor's Windows.Forensics.Bam
// artifact. Four columns: SID, UserName, Binary, Bam_time — the last execution time of a binary,
// attributed to the Windows account that ran it.
//
// Its own module because analysis/velociraptorImport.ts is frozen by the file-size ledger (#384).
// Reuses the SAME return shape mapGeneric() already threads for a THOR row (thorRowMap.ts's
// ThorFields) so the two special cases share one line in mapGeneric() — `thorFields(...) ??
// bamFields(...)` — rather than each needing its own conditional threading through every field.
//
// Unlike a THOR/YARA finding, BAM carries no verdict and no severity of its own — it is execution
// EVIDENCE (the same family as Prefetch/UserAssist), not a detection. downloadExecution.ts
// classifies it as kind "execution", not "detection": it has an observation time to order against
// a download mark's anchor, and the existing flat-High execution raise already fits it exactly.
import { getCI, isObject, str } from "./siemImport.js";
import type { ThorFields } from "./thorRowMap.js";
import { neutral } from "./downloadCorroborationShared.js";

type Row = Record<string, unknown>;

function baseName(s: string): string {
  return s.trim().split(/[\\/]/).pop() || s.trim();
}

function oneLine(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

/**
 * Read one row as a BAM finding, or `undefined` when it is not one.
 *
 * Column-only detection risks a false claim on a mixed row stream — SID and Binary are generic
 * Windows column names other artifacts could share — so a row must also come from an artifact
 * whose name contains "bam" (Windows.Forensics.Bam), mirroring thorFields()'s own reasoning for
 * requiring more than common column names alone.
 */
export function bamFields(
  row: unknown,
  ctx: { artifact?: string; host?: string } = {},
): ThorFields | undefined {
  if (!isObject(row)) return undefined;
  const r: Row = row;
  const sid = str(getCI(r, "SID")).trim();
  const binary = str(getCI(r, "Binary")).trim();
  const bamTime = str(getCI(r, "Bam_time")).trim();
  if (!sid || !binary || !bamTime) return undefined;
  if (!/\bbam\b/i.test(ctx.artifact ?? "")) return undefined;

  const userName = str(getCI(r, "UserName")).trim();
  const who = userName || sid;
  // binary is the BAM registry value — attacker-influenced (whatever ran on the endpoint). neutral()
  // folds brackets to parens so a crafted filename can never forge a registered derived-note marker
  // like "[ran a download-marked file: ...]" (#1238), the same trust boundary downloadExecution.ts
  // already applies to every other endpoint-named description source.
  const subject = neutral(baseName(binary));

  // Self-prefixed "Velociraptor BAM: " so the generic artifact-prefix injection (velociraptorImport
  // .ts's mapRowToEvents) produces "Velociraptor [<artifact>] BAM: ..." — the space-not-colon shape
  // downloadExecution.ts's detector expects — exactly the technique mapYara already uses for its
  // own "Velociraptor YARA: " prefix. Verified directly against the real injection output (#985
  // item 2/3 design review): an UNprefixed description gets the colon-separated generic wrap
  // instead, which no anchored detector here can parse.
  const description = oneLine(
    `Velociraptor BAM: ${subject} last run ${bamTime} (user ${who})`.replace(/ - /g, " — "),
  );

  return {
    severity: "Info", // no verdict of its own — Prefetch's own default, corroboration gives it weight
    description: description.slice(0, 600),
    detail: `SID: ${sid}${userName ? `\nUserName: ${userName}` : ""}\nBinary: ${binary}\nBam_time: ${bamTime}`,
    // Deliberately excludes Bam_time: the registry key holds only the LAST execution time per
    // binary per SID, no history, so a later re-collection's updated time is the same finding's
    // current state, not a new one (mirrors Prefetch's own path+host keying, which omits its run
    // count from the key for the identical reason).
    aggKey: `bam|${(ctx.host ?? "").toLowerCase()}|${sid.toLowerCase()}|${binary.toLowerCase()}`.slice(
      0,
      400,
    ),
    mitre: [],
    path: binary,
  };
}
