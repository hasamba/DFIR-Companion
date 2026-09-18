// #1265: every writer of `canonical.network.source.address` whose value is the log source's own
// recorder edge observing its peer (never client-supplied content) must stamp
// `provenance: "edge-observed"` alongside it. A category-based reader filter is unsound
// (exchangeAuditImport.ts/mailboxChain.ts are genuinely edge-observed but share
// `category: "email"` with the one confirmed-forgeable writer, emailImport.ts), so the reader in
// proxyWorkstationChain.ts fail-closes on the flag instead.
//
// WHAT THIS CHECKS. Every file under src/analysis/ is scanned for `source: { ... address: ... }`
// object literals. Each file that has one must appear in exactly one of two lists below:
//   - SITES: audited edge-observed, every literal must carry the stamp;
//   - EXEMPT: deliberately unstamped, with the reason recorded here, every literal must NOT carry
//     the stamp (so a stamp cannot creep in without revisiting the reason).
// A file with such a literal in neither list fails — that is the "new writer forgot to decide"
// case this sweep exists to catch. #1184/#1267's own audit claimed 13 sites; this scan found 28
// across 23 files, because the audit matched the dotted-string form `network.source.address`
// and missed the object-literal form most importers actually use.
//
// WHAT THIS DOES NOT CHECK. It is plain-text, not AST-based: property shorthand (`{ address }`),
// a computed key, or a write routed through a helper that builds the object elsewhere are
// invisible to it, and a stray brace inside a string/comment within the literal can confuse the
// balanced-brace slice. Files outside src/analysis/ are not scanned. It verifies the two literals
// sit together, not that the stamped value is genuinely edge-observed — that judgement is the
// audit's, recorded per site in RECOMMENDATION-1265.md.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ANALYSIS_DIR = fileURLToPath(new URL("../../src/analysis/", import.meta.url));

/** Audited edge-observed writers: file -> number of `source: { address }` literals it holds.
 * The count makes a file with more than one site require every one to be stamped. */
const SITES: Record<string, number> = {
  // #1267's own audit (12 files)
  "awsImport.ts": 1,
  "awsComputeRow.ts": 1,
  "awsLineage.ts": 1,
  "azureStorageLogImport.ts": 1,
  "cloudActivityImport.ts": 2,
  "gcpRow.ts": 1,
  "googleWorkspaceImport.ts": 2,
  "m365Import.ts": 1,
  "entraAuditImport.ts": 2,
  "exchangeAuditImport.ts": 1,
  "mailboxChain.ts": 1,
  "passwordSprayFanout.ts": 1,
  // #993/#1156's own Zeek/Squid pair
  "webChainRows.ts": 1,
  "combinedLogImport.ts": 1,
  // Found by this sweep, each verified against the file's own raw-field read (#1265):
  "siemImport.ts": 1, // Windows EVTX IpAddress/SourceIp/SourceAddress — OS kernel-level
  "awsFlowLogImport.ts": 1, // VPC Flow Log srcaddr — AWS network plane
  "dnsWireRows.ts": 1, // Zeek dns.log id.orig_h
  "exporterFlowImport.ts": 1, // nfdump src4_addr — exporter-observed
  "networkImport.ts": 3, // Zeek notice.log src / conn.log id.orig_h / Suricata eve src_ip
  "smbChainRows.ts": 1, // Suricata smb src_ip
  "tlsSession.ts": 1, // Zeek ssl.log id.orig_h (id.resp_h when flipped) / Suricata src_ip
  "auditdImport.ts": 1, // Linux auditd SOCKADDR saddr= — decoded from the kernel audit record
  "ecarImport.ts": 1, // ECAR EDR src_ip — endpoint-sensor-observed (already trusted by #1267 as passwordSprayFanout input)
};

/** Deliberately unstamped: file -> { occurrences, why }. */
const EXEMPT: Record<string, { occurrences: number; why: string }> = {
  "canonicalEvent.ts": {
    occurrences: 2,
    why:
      "legacy ForensicEvent -> canonical upgrade path: copies whatever srcIp/logon.sourceIp the " +
      "ORIGINAL pre-canonical importer wrote, whose provenance is unknowable at upgrade time — " +
      "fail-closed is the honest answer, and this is the already-disclosed pre-#1265 persisted-data case",
  },
};

/** Every `source: { ... }` object-literal slice that contains an `address:` key, found by
 * balanced-brace matching from each `source: {` so a multi-key literal is captured whole
 * regardless of key order. */
function sourceLiterals(source: string): string[] {
  const literals: string[] = [];
  const marker = /source:\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = marker.exec(source))) {
    const start = m.index + m[0].length - 1;
    let depth = 0;
    let end = -1;
    for (let i = start; i < source.length; i++) {
      if (source[i] === "{") depth++;
      else if (source[i] === "}" && --depth === 0) {
        end = i;
        break;
      }
    }
    if (end < 0) throw new Error(`unbalanced source: { literal at offset ${start}`);
    const literal = source.slice(start, end + 1);
    if (/\baddress\s*:/.test(literal)) literals.push(literal);
  }
  return literals;
}

const STAMP = /provenance:\s*"edge-observed"/;
const read = (file: string): string => readFileSync(path.join(ANALYSIS_DIR, file), "utf8");

describe("network.source.address writers decide on provenance (#1265)", () => {
  const files = readdirSync(ANALYSIS_DIR).filter((f) => f.endsWith(".ts"));

  it("every src/analysis file with a source:{address} literal is registered in SITES or EXEMPT", () => {
    const unregistered = files.filter(
      (f) => !(f in SITES) && !(f in EXEMPT) && sourceLiterals(read(f)).length > 0,
    );
    expect(unregistered).toEqual([]);
  });

  it("nothing in SITES or EXEMPT names a file that no longer has such a literal", () => {
    const stale = [...Object.keys(SITES), ...Object.keys(EXEMPT)].filter(
      (f) => !files.includes(f) || sourceLiterals(read(f)).length === 0,
    );
    expect(stale).toEqual([]);
  });

  for (const [file, occurrences] of Object.entries(SITES)) {
    it(`${file} stamps provenance: "edge-observed" at every address write site`, () => {
      const literals = sourceLiterals(read(file));
      expect(literals.length).toBe(occurrences);
      for (const literal of literals) expect(literal).toMatch(STAMP);
    });
  }

  for (const [file, { occurrences }] of Object.entries(EXEMPT)) {
    it(`${file} is deliberately unstamped at every address write site`, () => {
      const literals = sourceLiterals(read(file));
      expect(literals.length).toBe(occurrences);
      for (const literal of literals) expect(literal).not.toMatch(STAMP);
    });
  }

  it("emailImport.ts does not write canonical.network.source.address at all (#1184's own fix, pinned)", () => {
    expect(sourceLiterals(read("emailImport.ts"))).toEqual([]);
  });
});
