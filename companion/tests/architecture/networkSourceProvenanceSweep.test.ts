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
//
// READER SIDE (#1313). The writer sweep made every new writer decide; nothing made a new READER
// decide, and #1313 found one reader (dnsEndpointCrossUploadConnJoin.ts) resolving the address to
// a host name through the same resolveIpAtTime call #1265 guarded, with no gate. Every file under
// src/analysis/ that reads the field — property access `source?.address` / `source.address`, or
// the canonical path string "network.source.address" used as a VALUE (a fieldProvenance map KEY is
// a write, not a read) — must appear in READERS as one of:
//   - gated: fail-closes on `provenance === "edge-observed"` — the identity-attribution class,
//     where the address becomes a HOST NAME claim; the guard's presence is asserted;
//   - agnostic: reads the value regardless of provenance, with the reason recorded here — display
//     attributes, join keys, search and already-caveated detections, where a wrong value degrades
//     a lead but never names a host, and where a gate would DROP genuine legacy sensor evidence
//     (Cisco ASA, Security Onion, memory netscan, legacy 4624) to defend against a forged-address
//     producer that does not exist on master; the guard's absence is asserted, so a gate cannot
//     creep in without revisiting the reason;
//   - tracked: the decision is deferred to a named open issue.
// Comments are stripped before scanning, so a header that merely mentions the field is not a read.
// Same plain-text limits as the writer sweep: a read through an intermediate variable
// (`const s = c.network?.source; s?.address`) or a helper is invisible to it.
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

type ReaderKind = "gated" | "agnostic" | "tracked";

/** Readers of `canonical.network.source.address` (#1313 audit): file -> { kind, why }. */
const READERS: Record<string, { kind: ReaderKind; why: string }> = {
  "proxyWorkstationChain.ts": {
    kind: "gated",
    why: "address -> host name via resolveIpAtTime; the identity-attribution claim #1265 hardened (#1310)",
  },
  "dnsEndpointCrossUploadConnJoin.ts": {
    kind: "gated",
    why: "connection source -> host name via the same resolveIpAtTime call; the lead reports 'this host connected' (#1313)",
  },
  "hostBinding.ts": {
    kind: "tracked",
    why: "IP -> workstation-name index (byIp) that both gated readers resolve against; the index side is #1292, open",
  },
  "dnsCrossUploadConnJoin.ts": {
    kind: "agnostic",
    why: "src|dst address-pair join key against a sensor DNS row's own client|answer; a wrong value yields a spurious pair, never a host claim, and the header already says 'never a proven same-host'",
  },
  "loginGraph.ts": {
    kind: "agnostic",
    why: "sourceIp display attribute + risk hint on a parsed logon; it upgrades legacy logons itself to recover exactly this field, so a gate would empty sourceIp for every legacy 4624",
  },
  "cloudMetadataAccess.ts": {
    kind: "agnostic",
    why: "public-address modifier on an ARN-gated High finding with an in-band NAT caveat; falls back to flat e.srcIp, so a canonical-only gate is a no-op",
  },
  "cloudBulkRead.ts": {
    kind: "agnostic",
    why: "grouping/display sourceIp; already falls back to flat e.srcIp and to description parsing — the weakest trust class on purpose",
  },
  "evidenceGraph.ts": {
    kind: "agnostic",
    why: "network_flow edge srcIp -> dstIp:port — a graph of what the records say, mapped through the legacy upgrader itself",
  },
  "accessIndexes.ts": {
    kind: "agnostic",
    why: "sourceAddress display detail on a logon-session index entry (sensitiveAccess.ts), scoped to authentication/logon",
  },
  "kerberoastChain.ts": {
    kind: "agnostic",
    why: "intra-chain address match between a 4769 ticket request and its family rows — an address-to-address cross-match, never a host name",
  },
  "remediationVerify.ts": {
    kind: "agnostic",
    why: "'does this event still mention IOC X' — one of six fields, description included, so weaker fields already count",
  },
  "huntQueryFields.ts": {
    kind: "agnostic",
    why: "analyst hunt field source.ip (fallback event.srcIp) and the free-text index — analyst search over what the records say",
  },
};

/** Fail-closed reader gate, as proxyWorkstationChain.ts writes it. */
const READER_GATE = /provenance\s*===\s*"edge-observed"/;
const MAP_KEY = /"network\.source\.address"\s*:/g;
const PATH_VALUE = /"network\.source\.address"/g;
const PROPERTY_READ = /\bsource\??\.address\b/g;

/** Comment-free source, so a header that mentions the field does not count as a read. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

/** Number of reads of `canonical.network.source.address` in a file: property accesses plus the
 * canonical path string used as a value, never a fieldProvenance map key. */
function readCount(source: string): number {
  const code = stripComments(source).replace(MAP_KEY, "");
  const pathReads = (code.match(PATH_VALUE) ?? []).length;
  const propertyReads = (code.replace(PATH_VALUE, "").match(PROPERTY_READ) ?? []).length;
  return pathReads + propertyReads;
}

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

describe("network.source.address readers decide on provenance (#1313)", () => {
  const files = readdirSync(ANALYSIS_DIR).filter((f) => f.endsWith(".ts"));

  it("every src/analysis file that reads the field is registered in READERS", () => {
    const unregistered = files.filter((f) => !(f in READERS) && readCount(read(f)) > 0);
    expect(unregistered).toEqual([]);
  });

  it("nothing in READERS names a file that no longer reads the field", () => {
    const stale = Object.keys(READERS).filter((f) => !files.includes(f) || readCount(read(f)) === 0);
    expect(stale).toEqual([]);
  });

  it("counts code reads only: comments and fieldProvenance map keys are not reads", () => {
    expect(readCount('// c.network?.source?.address\n/* "network.source.address" */\n')).toBe(0);
    expect(readCount("const ip = c.network?.source?.address;")).toBe(1);
    expect(readCount('canonicalPath(event, "network.source.address")')).toBe(1);
    expect(readCount('{ "network.source.address": ["srcIp"] }')).toBe(0);
  });

  for (const [file, { kind }] of Object.entries(READERS)) {
    if (kind === "gated") {
      it(`${file} fail-closes on provenance === "edge-observed" before it names a host`, () => {
        expect(stripComments(read(file))).toMatch(READER_GATE);
      });
    } else {
      it(`${file} is provenance-agnostic by recorded decision (${kind}) and carries no reader gate`, () => {
        expect(stripComments(read(file))).not.toMatch(READER_GATE);
      });
    }
  }
});
