// What a quarantine attribute and a quarantine database record agree on, fact by fact (#1037).
//
// Shared by the within-upload join (quarantineJoin.ts, link 1) and the merge-time persistence
// link (quarantinePersistenceLink.ts, link 2), and filed with the shared vocabulary because the
// second lives in the timeline tier and may not reach into ingest. Pure functions over the block
// types: the agent (the attribute keeps a name, the database a name and a bundle id), the time (a
// band, never a verdict — the attribute is written when the file is created, the record when the
// agent logs the event; both encodings are named) and the download flag.

import { gapBand } from "./canonicalDns.js";
import type { QuarantineBlock, QuarantineTimeAgreement } from "./canonicalQuarantine.js";

const S = 1000;

export type QuarantineAgentAgreement = "agrees" | "differs" | "not compared";

export function quarantineAgentAgreement(
  markAgent: string,
  db: Pick<QuarantineBlock, "agent" | "bundleId">,
): QuarantineAgentAgreement {
  if (!db.agent && !db.bundleId) return "not compared";
  const a = markAgent.trim().toLowerCase();
  return a === (db.agent ?? "").trim().toLowerCase() || a === (db.bundleId ?? "").trim().toLowerCase()
    ? "agrees"
    : "differs";
}

export function quarantineTimeAgreement(
  markIso: string,
  dbIso: string,
  databaseEncoding: QuarantineBlock["timeEncoding"],
): QuarantineTimeAgreement {
  const db = Date.parse(dbIso);
  const mark = Date.parse(markIso);
  if (databaseEncoding === "unreadable" || !Number.isFinite(db))
    return { state: "not compared", reason: "the database time is not readable" };
  if (!Number.isFinite(mark)) return { state: "not compared", reason: "the attribute time is not readable" };
  const diff = mark - db;
  const encodings = { attributeEncoding: "unix-hex-seconds" as const, databaseEncoding };
  if (Math.abs(diff) < S) return { state: "same second", ...encodings };
  return {
    state: diff > 0 ? "marked after the record" : "marked before the record",
    band: gapBand(Math.abs(diff)),
    ...encodings,
  };
}

/** The flag word as the attribute has it: the download bit, and whether the word is exactly the sandbox bit. */
export function quarantineFlagFacts(flags: { named: readonly string[]; unnamed?: string }): {
  downloadFlag: boolean;
  sandboxOnly?: true;
} {
  const downloadFlag = flags.named.includes("download");
  const sandboxOnly =
    !downloadFlag && flags.named.length === 1 && flags.named[0] === "sandbox" && !flags.unnamed;
  return { downloadFlag, ...(sandboxOnly ? { sandboxOnly: true as const } : {}) };
}

const ENCODING_WORDS: Record<string, string> = {
  "cocoa-seconds": "Cocoa seconds",
  iso: "ISO 8601",
  "unix-seconds": "Unix seconds",
  "unix-ms": "Unix milliseconds",
  unreadable: "not readable",
};

export function timeWords(t: QuarantineTimeAgreement): string {
  if (t.state === "not compared") return `time not compared: ${t.reason}`;
  const encodings = `(attribute: Unix hex; database: ${ENCODING_WORDS[t.databaseEncoding]})`;
  if (t.state === "same second") return `marked and recorded in the same second ${encodings}`;
  return `marked ${t.band} ${t.state === "marked after the record" ? "after" : "before"} the record ${encodings}`;
}

/** The download bit as the record has it; "sandbox mark only" only when the sandbox bit is the whole word. */
export function flagTags(join: { downloadFlag?: boolean; sandboxOnly?: boolean }): string[] {
  if (join.downloadFlag === true) return ["download flag set"];
  if (join.downloadFlag === false)
    return [join.sandboxOnly ? "download flag not set — sandbox mark only" : "download flag not set"];
  return [];
}
