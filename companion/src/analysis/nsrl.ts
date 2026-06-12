// NSRL (National Software Reference Library) known-good hash checking — issue #63.
//
// NSRL publishes the Reference Data Set (RDS): hashes of *known* software (OS files, common
// applications, dev tools). The classic DFIR use is to filter known-good files out of the noise so
// the analyst focuses on the unknown — "flag files that match known-good hashes to reduce false
// positives in findings". A forensic event whose file hash, or an IOC whose value, is in the NSRL
// set is auto-marked LEGITIMATE on import (reusing the legitimate machinery, so it's reversible and
// shows in the "Confirmed Legitimate" panel). The store (nsrlStore.ts) holds the hash set; the
// auto-mark wiring lives in the /import route — exactly mirroring the IOC whitelist (#35).
//
// Pure logic only (normalize + parse + match) so it unit-tests without I/O.
//
// CAUTION (DFIR): NSRL is "known", not strictly "known-good" — historic RDS sets have included some
// hacktools, and a known hash can still be malicious in context (DLL side-loading, a renamed LOLBin).
// So this is opt-in and never default (the store starts empty), mirroring the whitelist's posture:
// "Missing a real threat is worse than leaving noise" (CLAUDE.md). Matches are reversible.

import type { ForensicEvent, IOC } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";

const HEX = /^[0-9a-f]+$/;

// A valid file hash, normalized for set membership: lowercased, 0x/whitespace stripped, and exactly
// MD5 (32) / SHA-1 (40) / SHA-256 (64) hex chars. Anything else (CRC32, file sizes, names, IPv6) is
// rejected → null, so parsing/matching never trips on non-hash tokens.
export function normalizeHash(raw: string): string | null {
  const v = String(raw ?? "").trim().toLowerCase().replace(/^0x/, "");
  if (v.length !== 32 && v.length !== 40 && v.length !== 64) return null;
  return HEX.test(v) ? v : null;
}

// Header names (punctuation-stripped) that hold a usable hash in an RDS / hashdeep CSV.
const HASH_HEADERS = new Set(["sha1", "sha256", "md5", "sha", "hash", "hashvalue", "fuzzy"]);

// Parse known-good hashes out of pasted/loaded NSRL data. Tolerant of the common shapes:
//   • NSRLFile.txt (RDS): CSV with a header like "SHA-1","MD5","CRC32","FileName",… → pull the
//     hash columns.
//   • hashdeep / other CSV exports with a sha256/md5/hash column.
//   • a plain hash-per-line list, or comma/space-separated hashes, or a JSON dump — every token is
//     scanned and kept when it is a valid MD5/SHA-1/SHA-256.
// Returns the deduplicated, normalized hashes. Malformed tokens are silently dropped.
export function parseNsrlText(text: string): string[] {
  const t = (text ?? "").trim();
  if (!t) return [];
  const out = new Set<string>();

  // CSV-with-header path: only when the first line names a hash column, so we don't mis-parse a bare
  // hash list (whose first line is itself a hash) as a header row.
  const nl = t.indexOf("\n");
  const firstLine = nl === -1 ? t : t.slice(0, nl);
  if (firstLine.includes(",") && /sha-?(1|256)|md5|hash/i.test(firstLine)) {
    const { headers, rows } = parseCsv(t);
    const hashCols = headers
      .map((h, i) => ({ i, key: h.trim().toLowerCase().replace(/[^a-z0-9]/g, "") }))
      .filter((c) => HASH_HEADERS.has(c.key))
      .map((c) => c.i);
    if (hashCols.length > 0) {
      for (const row of rows) {
        for (const i of hashCols) {
          const n = normalizeHash(row[i] ?? "");
          if (n) out.add(n);
        }
      }
      return [...out];
    }
  }

  // Generic path: scan every token. Length+hex validation means only real hashes survive.
  for (const tok of t.split(/[\s,;"'|:]+/)) {
    const n = normalizeHash(tok);
    if (n) out.add(n);
  }
  return [...out];
}

// IOCs of type "hash" whose value is in the NSRL set, paired with the matched hash (for the marker
// note). Other IOC types are never NSRL-matchable.
export function nsrlMatchIocs(
  iocs: readonly IOC[],
  hashes: ReadonlySet<string>,
): Array<{ ioc: IOC; hash: string }> {
  if (hashes.size === 0) return [];
  const out: Array<{ ioc: IOC; hash: string }> = [];
  for (const ioc of iocs) {
    if (ioc.type !== "hash") continue;
    const n = normalizeHash(ioc.value);
    if (n && hashes.has(n)) out.push({ ioc, hash: n });
  }
  return out;
}

// Forensic events whose file hash (sha256 preferred, else md5) is in the NSRL set — i.e. a
// known-good file. Paired with the matched hash for the marker note.
export function nsrlMatchEvents(
  events: readonly ForensicEvent[],
  hashes: ReadonlySet<string>,
): Array<{ event: ForensicEvent; hash: string }> {
  if (hashes.size === 0) return [];
  const out: Array<{ event: ForensicEvent; hash: string }> = [];
  for (const event of events) {
    const sha = normalizeHash(event.sha256 ?? "");
    const md5 = normalizeHash(event.md5 ?? "");
    const matched = sha && hashes.has(sha) ? sha : md5 && hashes.has(md5) ? md5 : null;
    if (matched) out.push({ event, hash: matched });
  }
  return out;
}
