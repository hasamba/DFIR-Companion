import { describe, it, expect } from "vitest";
import {
  staticReportMatches,
  reportEventsByFingerprint,
  isAnalystSideRow,
  STATIC_REPORT_ATTESTATION_CAVEAT,
  PATH_JOIN_CONTRACT,
  type StaticReportEventShape,
} from "../../src/analysis/staticReportMatch.js";
import { parseOlevbaResult } from "../../src/analysis/olevbaResultImport.js";
import type { StaticReportAttestation } from "../../src/analysis/staticReportAttestationStore.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";

const FP = "a".repeat(64);
const SHA = "1".repeat(64);
const OTHER_SHA = "2".repeat(64);

let seq = 0;
function ev(over: Partial<StaticReportEventShape> = {}): StaticReportEventShape {
  seq += 1;
  return { id: `e${seq}`, timestamp: `2026-09-1${seq % 9}T00:00:00Z`, sources: ["Sysmon"], ...over };
}

function olevbaLead(documentPath: string, fp = FP): StaticReportEventShape {
  return ev({
    sources: ["olevba"],
    timestamp: "",
    canonical: { olevbaCompoundLead: { reportFingerprint: fp, documentPath } },
  });
}

function attestation(over: Partial<StaticReportAttestation> = {}): StaticReportAttestation {
  return {
    id: "att-1",
    reportFingerprint: FP,
    tool: "olevba",
    subjectHost: "WS-01",
    digestCrossCheck: "none",
    attestedBy: "a.analyst",
    attestedAt: "2026-09-18T00:00:00Z",
    ...over,
  };
}

const index = buildHostAliasIndex([], {});

describe("reportEventsByFingerprint", () => {
  it("finds the events carrying a fingerprint on any of the six static-analysis blocks and names the tool", () => {
    const events = [
      olevbaLead("E:\\Users\\bob\\invoice.docm"),
      ev({
        sources: ["capa"],
        canonical: {
          capaMatch: { reportFingerprint: "b".repeat(64), sampleHash: { hashUnavailable: true } },
        },
      }),
      ev({
        sources: ["FLOSS"],
        canonical: {
          decodedString: {
            reportFingerprint: "c".repeat(64),
            sampleHash: { sha256: SHA, hashUnavailable: false },
          },
        },
      }),
      ev(),
    ];
    expect(reportEventsByFingerprint(events, FP)).toEqual({
      tool: "olevba",
      events: [events[0]],
      toolReportedSha256: undefined,
      toolReportedMd5: undefined,
    });
    expect(reportEventsByFingerprint(events, "c".repeat(64))).toMatchObject({
      tool: "floss",
      toolReportedSha256: SHA,
    });
    expect(reportEventsByFingerprint(events, "d".repeat(64))).toBeNull();
  });

  it("#1363 — a MobSF requested-permission block resolves as tool mobsf with the APK's own reported sha256", () => {
    const events = [
      ev({
        sources: ["mobsf"],
        canonical: {
          mobileRequestedPermission: {
            reportFingerprint: "e".repeat(64),
            sampleHash: { sha256: SHA, md5: "f".repeat(32), hashUnavailable: false },
          },
        },
      }),
      ev(),
    ];
    expect(reportEventsByFingerprint(events, "e".repeat(64))).toEqual({
      tool: "mobsf",
      events: [events[0]],
      toolReportedSha256: SHA,
      toolReportedMd5: "f".repeat(32),
    });
    // A MobSF row is an analyst-side artifact (a lab report about an APK), like the other five.
    expect(isAnalystSideRow(events[0])).toBe(true);
  });
});

describe("staticReportMatches — path kind (olevba only)", () => {
  it("matches the flagship case: staged E:\\..., victim C:\\..., mountPoint E:, originalVolume C: (review H-1)", () => {
    const victim = ev({ asset: "ws-01", path: "C:\\Users\\bob\\invoice.docm" });
    const events = [olevbaLead("E:\\Users\\bob\\invoice.docm"), victim];
    const out = staticReportMatches({
      attestation: attestation({
        evidenceVolume: {
          mountPoint: { volume: "e", volumeKind: "drive" },
          originalVolume: { volume: "c", volumeKind: "drive" },
        },
      }),
      events,
      aliasIndex: index,
    });
    expect(out.path.rows).toHaveLength(1);
    expect(out.path.rows[0]).toMatchObject({
      eventId: victim.id,
      host: "ws-01",
      hostIsAttestedSubject: true,
      identity: "path-only",
      victimPath: "C:\\Users\\bob\\invoice.docm",
    });
    expect(out.path.rows[0].basis).toContain("attested by a.analyst");
    expect(out.path.rows[0].basis).toContain("not hash-verified");
    expect(out.caveat).toBe(STATIC_REPORT_ATTESTATION_CAVEAT);
    expect(out.diagnostics.reportPresent).toBe(true);
    expect(out.diagnostics.subjectHostKnown).toBe(true);
  });

  it("does not match the same path on a different host, and counts a same-path row with no asset instead of dropping it (M-5)", () => {
    const events = [
      olevbaLead("C:\\Users\\bob\\invoice.docm"),
      ev({ asset: "ws-99", path: "C:\\Users\\bob\\invoice.docm" }),
      ev({ path: "C:\\Users\\bob\\invoice.docm" }),
    ];
    const out = staticReportMatches({ attestation: attestation(), events, aliasIndex: index });
    expect(out.path.rows).toHaveLength(0);
    expect(out.diagnostics.unattributedHostRows).toBe(1);
  });

  it("resolves the attested host through the alias index at read time", () => {
    const merged = buildHostAliasIndex([], { "ws-01": "ws-01.corp.local" });
    const victim = ev({ asset: "WS-01.corp.local", path: "C:\\x\\a.docm" });
    const out = staticReportMatches({
      attestation: attestation({ subjectHost: "ws-01" }),
      events: [olevbaLead("C:\\x\\a.docm"), victim],
      aliasIndex: merged,
    });
    expect(out.path.rows.map((r) => r.eventId)).toEqual([victim.id]);
  });

  it("without an originalVolume mapping a drive-letter mismatch is counted, not silently zero (M-5a)", () => {
    const events = [
      olevbaLead("E:\\Users\\bob\\invoice.docm"),
      ev({ asset: "ws-01", path: "C:\\Users\\bob\\invoice.docm" }),
    ];
    const out = staticReportMatches({ attestation: attestation(), events, aliasIndex: index });
    expect(out.path.rows).toHaveLength(0);
    expect(out.diagnostics.volumeMismatchWithoutMapping).toBe(1);
  });

  it("does not substitute when the staged document is not under the attested mount, and says so (H-2)", () => {
    const events = [
      olevbaLead("F:\\staging\\invoice.docm"),
      ev({ asset: "ws-01", path: "C:\\staging\\invoice.docm" }),
      // A drive-letter coincidence on the subject host: compared as written it WOULD match, and the
      // row would read exactly like a mapping-earned one (code review #2) — it must not be emitted.
      ev({ asset: "ws-01", path: "F:\\staging\\invoice.docm" }),
    ];
    const out = staticReportMatches({
      attestation: attestation({
        evidenceVolume: {
          mountPoint: { volume: "e", volumeKind: "drive" },
          originalVolume: { volume: "c", volumeKind: "drive" },
        },
      }),
      events,
      aliasIndex: index,
    });
    expect(out.path.rows).toHaveLength(0);
    expect(out.diagnostics.documentOutsideAttestedMount).toBe(true);
    expect(out.diagnostics.pathJoinSkipped).toMatch(/not under the attested mount/);
  });

  it("flags outside-mount even when only a mountPoint (no originalVolume) is attested (code review #3)", () => {
    const out = staticReportMatches({
      attestation: attestation({ evidenceVolume: { mountPoint: { volume: "e", volumeKind: "drive" } } }),
      events: [
        olevbaLead("C:\\Users\\bob\\invoice.docm"),
        ev({ asset: "ws-01", path: "C:\\Users\\bob\\invoice.docm" }),
      ],
      aliasIndex: index,
    });
    expect(out.path.rows).toHaveLength(0);
    expect(out.diagnostics.documentOutsideAttestedMount).toBe(true);
  });

  it("with a mountPoint but no originalVolume, a staged path under the mount is compared as written", () => {
    const victim = ev({ asset: "ws-01", path: "E:\\Users\\bob\\invoice.docm" });
    const out = staticReportMatches({
      attestation: attestation({ evidenceVolume: { mountPoint: { volume: "e", volumeKind: "drive" } } }),
      events: [olevbaLead("E:\\Users\\bob\\invoice.docm"), victim],
      aliasIndex: index,
    });
    expect(out.path.rows.map((r) => r.eventId)).toEqual([victim.id]);
    expect(out.diagnostics.documentOutsideAttestedMount).toBe(false);
  });

  it("counts a same-relative-path victim on the subject host whose volume disagrees DESPITE a mapping (code review #7)", () => {
    const out = staticReportMatches({
      attestation: attestation({
        evidenceVolume: {
          mountPoint: { volume: "e", volumeKind: "drive" },
          originalVolume: { volume: "c", volumeKind: "drive" },
        },
      }),
      events: [
        olevbaLead("E:\\Users\\bob\\invoice.docm"),
        ev({ asset: "ws-01", path: "D:\\Users\\bob\\invoice.docm" }),
        ev({ asset: "ws-99", path: "D:\\Users\\bob\\invoice.docm" }), // other host: not counted
        ev({
          asset: "ws-01",
          path: "D:\\Users\\bob\\invoice.docm",
          sources: ["YARA"],
          description: "YARA: r matched x",
        }), // analyst-side: not counted
      ],
      aliasIndex: index,
    });
    expect(out.path.rows).toHaveLength(0);
    expect(out.diagnostics.volumeMismatchDespiteMapping).toBe(1);
    expect(out.diagnostics.volumeMismatchWithoutMapping).toBe(0);
  });

  it("names the reason distinctly when the report carries no document path at all (code review #4)", () => {
    const lead = ev({
      sources: ["olevba"],
      timestamp: "",
      canonical: { olevbaCompoundLead: { reportFingerprint: FP, documentPath: "" } },
    });
    const out = staticReportMatches({
      attestation: attestation(),
      events: [lead, ev({ asset: "ws-01", path: "C:\\x" })],
      aliasIndex: index,
    });
    expect(out.diagnostics.pathJoinSkipped).toBe("the report names no document path");
  });

  it("counts a volumeless staged path alongside a placeable one instead of dropping it silently (code review #11)", () => {
    const victim = ev({ asset: "ws-01", path: "C:\\x\\a.docm" });
    const events = [olevbaLead("C:\\x\\a.docm"), olevbaLead("b.docm"), victim];
    const out = staticReportMatches({ attestation: attestation(), events, aliasIndex: index });
    expect(out.path.rows.map((r) => r.eventId)).toEqual([victim.id]);
    expect(out.diagnostics.volumelessDocumentPaths).toBe(1);
    expect(out.diagnostics.pathJoinSkipped).toBeUndefined();
  });

  it("skips the path kind entirely when the staged path names no volume (M-6)", () => {
    const events = [olevbaLead("invoice.docm"), ev({ asset: "ws-01", path: "C:\\invoice.docm" })];
    const out = staticReportMatches({ attestation: attestation(), events, aliasIndex: index });
    expect(out.path.rows).toHaveLength(0);
    expect(out.diagnostics.pathJoinSkipped).toMatch(/names no volume/);
  });

  it("surfaces sameLocation's volumeNote verbatim when the victim row names no volume (L-2)", () => {
    const victim = ev({ asset: "ws-01", path: ".\\Users\\bob\\invoice.docm" });
    const out = staticReportMatches({
      attestation: attestation(),
      events: [olevbaLead("C:\\Users\\bob\\invoice.docm"), victim],
      aliasIndex: index,
    });
    expect(out.path.rows[0].volumeNote).toBe("volume not compared (one record names none)");
  });

  it("marks a path row whose own digest disagrees with the attested document as a digest conflict (H-3)", () => {
    const victim = ev({ asset: "ws-01", path: "C:\\x\\a.docm", sha256: OTHER_SHA });
    const out = staticReportMatches({
      attestation: attestation({ documentSha256: SHA }),
      events: [olevbaLead("C:\\x\\a.docm"), victim],
      aliasIndex: index,
    });
    expect(out.path.rows[0].digestConflict).toBe(true);
    expect(out.path.rows[0].basis).toMatch(/DISAGREES/);
  });

  it("says so when a path row's own digest AGREES with the attested document, and stays a path row (code review #5)", () => {
    const victim = ev({ asset: "ws-01", path: "C:\\x\\a.docm", sha256: SHA.toUpperCase() });
    const out = staticReportMatches({
      attestation: attestation({ documentSha256: SHA }),
      events: [olevbaLead("C:\\x\\a.docm"), victim],
      aliasIndex: index,
    });
    expect(out.path.rows[0].digestAgrees).toBe(true);
    expect(out.path.rows[0].digestConflict).toBeUndefined();
    expect(out.path.rows[0].identity).toBe("path-only");
    expect(out.path.rows[0].basis).toMatch(/AGREES/);
    expect(out.path.rows[0].basis).not.toMatch(/not hash-verified/);
  });

  it("excludes analyst-side rows and counts them: report rows, CLI-YARA, PE-sieve — but keeps a SO-CRATES YARA hit (M-4, L-3)", () => {
    const socrates = ev({
      asset: "ws-01",
      path: "C:\\x\\a.docm",
      sources: ["SO-CRATES", "YARA"],
      description: "YARA: evil on C:\\x\\a.docm",
    });
    const events = [
      olevbaLead("C:\\x\\a.docm"),
      ev({
        asset: "ws-01",
        path: "C:\\x\\a.docm",
        sources: ["YARA"],
        description: "YARA: evil matched C:\\x\\a.docm",
      }),
      ev({ asset: "ws-01", path: "C:\\x\\a.docm", sources: ["PE-sieve"] }),
      ev({
        asset: "ws-01",
        path: "C:\\x\\a.docm",
        sources: ["olevba"],
        canonical: { olevbaFinding: { reportFingerprint: "e".repeat(64), documentPath: "C:\\x\\a.docm" } },
      }),
      socrates,
    ];
    const out = staticReportMatches({ attestation: attestation(), events, aliasIndex: index });
    expect(out.path.rows.map((r) => r.eventId)).toEqual([socrates.id]);
    expect(out.path.excludedAnalystSide).toBe(3);
  });

  it("keeps a Velociraptor YARA hit and a hypothetical tool-source row paired with a victim-side source (code review #9)", () => {
    expect(
      isAnalystSideRow(ev({ sources: ["Velociraptor"], description: "Velociraptor YARA: r matched" })),
    ).toBe(false);
    expect(isAnalystSideRow(ev({ sources: ["SO-CRATES", "olevba"] }))).toBe(false);
    expect(isAnalystSideRow(ev({ sources: ["YARA"] }))).toBe(true);
    expect(isAnalystSideRow(ev({ sources: ["PE-sieve"] }))).toBe(true);
  });

  it("classifies the REAL olevba importer's own output as analyst-side by its sources string alone", () => {
    const parsed = parseOlevbaResult(
      JSON.stringify([
        { type: "MetaInformation", script_name: "olevba", version: "0.60.2" },
        {
          type: "OLE",
          file: "C:\\x\\a.docm",
          json_conversion_successful: true,
          macros: [],
          analysis: [{ type: "AutoExec", keyword: "AutoOpen", description: "d" }],
        },
      ]),
    );
    expect(parsed?.events.length).toBeGreaterThan(0);
    for (const e of parsed!.events) {
      // Strip the block so only the `sources` spelling can classify it.
      expect(isAnalystSideRow({ ...e, canonical: undefined })).toBe(true);
    }
  });

  it("does not count an analyst-side row as making the subject host known (code review #14)", () => {
    const out = staticReportMatches({
      attestation: attestation(),
      events: [
        olevbaLead("C:\\x\\a.docm"),
        ev({ asset: "ws-01", sources: ["YARA"], description: "YARA: r matched x", path: "C:\\y" }),
      ],
      aliasIndex: index,
    });
    expect(out.diagnostics.subjectHostKnown).toBe(false);
  });

  it("caps rows per kind and discloses the truncation", () => {
    const events = [olevbaLead("C:\\x\\a.docm")];
    for (let i = 0; i < 60; i++) events.push(ev({ asset: "ws-01", path: "C:\\x\\a.docm" }));
    const out = staticReportMatches({ attestation: attestation(), events, aliasIndex: index });
    expect(out.path.rows).toHaveLength(50);
    expect(out.path.truncated).toBe(10);
  });
});

describe("staticReportMatches — hash kind", () => {
  it("matches by attested sha256 on any host, carries the host and whether it is the attested subject (M-4)", () => {
    const a = ev({ asset: "ws-01", sha256: SHA.toUpperCase() });
    const b = ev({ asset: "ws-07", sha256: SHA });
    const out = staticReportMatches({
      attestation: attestation({ documentSha256: SHA, digestCrossCheck: "tool-sha256" }),
      events: [olevbaLead("C:\\x\\a.docm"), a, b, ev({ asset: "ws-01", sha256: OTHER_SHA })],
      aliasIndex: index,
    });
    expect(out.hash.rows.map((r) => [r.eventId, r.hostIsAttestedSubject])).toEqual([
      [a.id, true],
      [b.id, false],
    ]);
    expect(out.hash.rows[0].identity).toBe("analyst-attested-digest");
    expect(out.hash.rows[0].basis).toMatch(/corroborated by the tool's own sha256/);
  });

  it("states the basis honestly when no cross-check was possible, and counts md5-only victim rows it can never match (M-3, L-5)", () => {
    const out = staticReportMatches({
      attestation: attestation({ documentSha256: SHA, digestCrossCheck: "none" }),
      events: [olevbaLead("C:\\x\\a.docm"), ev({ asset: "ws-01", md5: "f".repeat(32) })],
      aliasIndex: index,
    });
    expect(out.hash.rows).toHaveLength(0);
    expect(out.diagnostics.md5OnlyVictimRows).toBe(1);
    expect(out.hash.basis).toMatch(/not cross-checked/);
  });

  it("produces no hash rows when neither the analyst nor the tool supplied a digest", () => {
    const out = staticReportMatches({
      attestation: attestation(),
      events: [olevbaLead("C:\\x\\a.docm"), ev({ asset: "ws-01", sha256: SHA })],
      aliasIndex: index,
    });
    expect(out.hash.rows).toHaveLength(0);
    expect(out.hash.skipped).toMatch(/no digest available/);
  });

  it("joins on the tool-reported digest when the analyst supplied none, and says the digest is the tool's, not the analyst's (code review #1)", () => {
    const victim = ev({ asset: "ws-07", sha256: SHA });
    const out = staticReportMatches({
      attestation: attestation({ tool: "capa", toolReportedSha256: SHA }),
      events: [
        ev({
          sources: ["capa"],
          canonical: {
            capaMatch: { reportFingerprint: FP, sampleHash: { sha256: SHA, hashUnavailable: false } },
          },
        }),
        victim,
      ],
      aliasIndex: index,
    });
    expect(out.hash.rows.map((r) => r.eventId)).toEqual([victim.id]);
    expect(out.hash.rows[0].identity).toBe("tool-reported-digest");
    expect(out.hash.rows[0].basis).toMatch(
      /read from the tool's own sample metadata, not hashed by the analyst/,
    );
    expect(out.hash.skipped).toBeUndefined();
  });

  it("counts md5-only victim rows regardless of an attested digest, never analyst-side ones, and unattributed hash rows (code review #8)", () => {
    const out = staticReportMatches({
      attestation: attestation({ documentSha256: SHA }),
      events: [
        olevbaLead("C:\\x\\a.docm"),
        ev({ asset: "ws-01", md5: "f".repeat(32) }),
        ev({ md5: "e".repeat(32), sources: ["FLOSS"] }),
        ev({ sha256: SHA }), // no asset
      ],
      aliasIndex: index,
    });
    expect(out.diagnostics.md5OnlyVictimRows).toBe(1);
    expect(out.hash.rows).toHaveLength(1);
    expect(out.hash.rows[0].host).toBe("");
    expect(out.diagnostics.unattributedHostRows).toBe(1);
    const none = staticReportMatches({
      attestation: attestation(),
      events: [ev({ asset: "ws-01", md5: "f".repeat(32) })],
      aliasIndex: index,
    });
    expect(none.diagnostics.md5OnlyVictimRows).toBe(1);
  });

  it("ships the path-join contract, which names the command-line blind spot (code review #12)", () => {
    const out = staticReportMatches({ attestation: attestation(), events: [], aliasIndex: index });
    expect(out.contract).toBe(PATH_JOIN_CONTRACT);
    expect(out.contract).toMatch(/command line/);
    expect(out.contract).toMatch(/never means/);
  });
});

describe("staticReportMatches — record annotations", () => {
  it("prefixes every basis with ATTESTATION REVOKED when the attestation is revoked (L-1)", () => {
    const out = staticReportMatches({
      attestation: attestation({ revokedAt: "2026-09-18T01:00:00Z", revokedBy: "b" }),
      events: [olevbaLead("C:\\x\\a.docm"), ev({ asset: "ws-01", path: "C:\\x\\a.docm" })],
      aliasIndex: index,
    });
    expect(out.attestationRevoked).toBe(true);
    expect(out.path.rows[0].basis.startsWith("ATTESTATION REVOKED — ")).toBe(true);
  });

  it("reports an absent report and an unknown host rather than an empty result that reads as 'nothing there' (M-5c)", () => {
    const out = staticReportMatches({
      attestation: attestation({ subjectHost: "typo-host" }),
      events: [ev({ asset: "ws-01", path: "C:\\x\\a.docm" })],
      aliasIndex: index,
    });
    expect(out.diagnostics.reportPresent).toBe(false);
    expect(out.diagnostics.subjectHostKnown).toBe(false);
    expect(out.path.rows).toHaveLength(0);
  });
});
