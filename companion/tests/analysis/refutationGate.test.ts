import { describe, it, expect } from "vitest";
import {
  requiredEvidenceClasses,
  collectedEvidenceClasses,
  collectedEvidenceClassesByHost,
  gateRefutedSeeds,
  EVIDENCE_CLASS_SOURCES,
  type EvidenceClass,
  type AttestedEvidenceClass,
} from "../../src/analysis/refutationGate.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import {
  hypothesesSchema,
  sanitizeHypotheses,
  type HypothesisSeed,
  type ResolvedSubjectScope,
} from "../../src/analysis/hypothesis.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, sources: string[], artifactName?: string, asset?: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-08-26T13:00:00.000Z",
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources,
    ...(artifactName ? { artifactName } : {}),
    ...(asset ? { asset } : {}),
  };
}

function seed(
  title: string,
  status: HypothesisSeed["status"] = "refuted",
  subjectScope?: ResolvedSubjectScope,
): HypothesisSeed {
  return {
    sourceKey: title.toLowerCase().replace(/\W+/g, "-"),
    title,
    description: "",
    expectedOutcome: "",
    status,
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    contradictingEventIds: [],
    discriminator: "",
    ...(subjectScope ? { subjectScope } : {}),
  };
}

describe("requiredEvidenceClasses", () => {
  it("maps an execution claim to the execution class", () => {
    expect(requiredEvidenceClasses("Ransomware encryption was executed on the host")).toContain("execution");
  });

  it("maps a file-outcome claim to the file-activity class", () => {
    const classes = requiredEvidenceClasses("Files on the share were encrypted and renamed");
    expect(classes).toContain("file-activity");
  });

  it("maps an exfiltration claim to the network class", () => {
    expect(requiredEvidenceClasses("Data was exfiltrated via OneDrive cloud sync")).toContain("network");
  });

  it("maps a persistence claim to the persistence class", () => {
    expect(requiredEvidenceClasses("The actor installed a service for persistence")).toContain("persistence");
  });

  it("returns nothing for a claim with no recognisable evidence class", () => {
    expect(requiredEvidenceClasses("The operator was an authorized red teamer")).toEqual([]);
  });
});

describe("collectedEvidenceClasses", () => {
  it("recognises historical execution sources", () => {
    const got = collectedEvidenceClasses([ev("a", ["Windows.Forensics.Prefetch"])]);
    expect(got.has("execution")).toBe(true);
  });

  it("does NOT count PowerShell command history as general execution evidence", () => {
    // PSReadline records what one interpreter was asked to do. It is silent about every other
    // binary on the box, so it cannot vouch that a dropped executable did or did not run.
    const got = collectedEvidenceClasses([ev("a", ["Velociraptor"], "Windows.Forensics.PSReadline")]);
    expect(got.has("execution")).toBe(false);
  });

  it("does NOT count a rule-hit detection feed as coverage", () => {
    // "DetectRaptor.Windows.Detection.Amcache" returns the Amcache rows that matched a rule, not
    // the hive. Its silence about anything else is the rule's silence, not the artifact's.
    const got = collectedEvidenceClasses([
      ev("a", ["Velociraptor"], "DetectRaptor.Windows.Detection.Amcache"),
      ev("b", ["Velociraptor"], "DetectRaptor.Windows.Detection.MFT"),
    ]);
    expect(got.has("execution")).toBe(false);
    expect(got.has("file-activity")).toBe(false);
  });

  it("counts the full collection of the same artifact", () => {
    const got = collectedEvidenceClasses([ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch")]);
    expect(got.has("execution")).toBe(true);
  });

  // This list decides when an absence is trustworthy enough to leave a refutation standing, so an
  // entry has to be able to show the event HAD IT HAPPENED (#909 item 1).
  //
  // ShimCache holds at most 1024 entries and evicts, and from Windows 8 onward it records metadata
  // gathered by directory ENUMERATION as well as execution — so its silence is not evidence the
  // binary did not run. Amcache has its own coverage limits. Counting either as full execution
  // coverage is how "no evidence it ran" becomes "it did not run".
  it("does NOT count ShimCache or Amcache as general execution coverage", () => {
    for (const artifact of [
      "Windows.Registry.AppCompatCache",
      "Windows.Forensics.Amcache",
      "AppCompatCacheParser",
    ]) {
      const got = collectedEvidenceClasses([ev("a", ["Velociraptor"], artifact)]);
      expect(got.has("execution"), `${artifact} must not vouch for an absence`).toBe(false);
    }
  });

  // They are still perfectly good POSITIVE evidence — this is only about what an ABSENCE proves.
  it("still downgrades a refutation when only ShimCache was collected", () => {
    const collection = [ev("a", ["Velociraptor"], "Windows.Registry.AppCompatCache")];
    const { seeds: out, downgraded } = gateRefutedSeeds(
      [seed("the dropped binary never executed")],
      collection,
    );
    expect(out[0].status).toBe("unknown");
    expect(downgraded[0].missing).toContain("execution");
  });

  it("does NOT count a live process list as historical execution evidence", () => {
    // Pstree and netstat show what is running NOW. They cannot show that a binary ran last week,
    // so they must not satisfy an execution claim — that is the mistake the gate exists to catch.
    const got = collectedEvidenceClasses([ev("a", ["Generic.System.Pstree"])]);
    expect(got.has("execution")).toBe(false);
  });

  it("recognises file-system sources", () => {
    const got = collectedEvidenceClasses([ev("a", ["Velociraptor"], "Windows.NTFS.MFT")]);
    expect(got.has("file-activity")).toBe(true);
  });

  it("does NOT count a signature scanner as file-system coverage", () => {
    // THOR and YARA report the files that matched a rule. Their silence about everything else is
    // the ruleset's silence, not the file system's, so they cannot establish that a file was absent.
    const got = collectedEvidenceClasses([
      ev("a", ["Velociraptor"], "Generic.Scanner.ThorZIP"),
      ev("b", ["Velociraptor"], "DetectRaptor.Generic.Detection.YaraFile"),
    ]);
    expect(got.has("file-activity")).toBe(false);
  });

  it("does NOT count a live socket table as network coverage", () => {
    // Netstat shows the sockets open at collection time — the same limitation as a live process
    // list, which is already excluded. It cannot show a connection made during the incident window.
    const got = collectedEvidenceClasses([ev("a", ["Velociraptor"], "Windows.Network.NetstatEnriched")]);
    expect(got.has("network")).toBe(false);
  });

  it("recognises historical network and persistence sources", () => {
    const got = collectedEvidenceClasses([
      ev("a", ["Velociraptor"], "Windows.Network.PacketCapture"),
      ev("b", ["Velociraptor"], "Windows.Forensics.PersistenceSniper"),
    ]);
    expect(got.has("network")).toBe(true);
    expect(got.has("persistence")).toBe(true);
  });

  // A Velociraptor collection stamps every row with the single coarse source "Velociraptor",
  // whatever artifact produced it — the artifact identity is in artifactName. Reading only `sources`
  // finds no classes at all, and the gate then downgrades EVERY refutation, including the ones the
  // collection genuinely supports.
  it("reads artifactName, not just the coarse importer label", () => {
    const got = collectedEvidenceClasses([
      ev("a", ["Velociraptor"], "Windows.Network.PacketCapture"),
      ev("b", ["Velociraptor"], "Windows.Forensics.PersistenceSniper"),
    ]);
    expect(got.has("network")).toBe(true);
    expect(got.has("persistence")).toBe(true);
    expect(got.has("execution")).toBe(false);
  });

  it("ignores events with no named source", () => {
    expect(collectedEvidenceClasses([ev("a", [])]).size).toBe(0);
  });

  it("exposes its source patterns for every class", () => {
    const classes: EvidenceClass[] = ["execution", "file-activity", "network", "persistence"];
    for (const c of classes) expect(EVIDENCE_CLASS_SOURCES[c].length).toBeGreaterThan(0);
  });
});

describe("gateRefutedSeeds", () => {
  // The INC-2026-003 collection: file-system and persistence coverage, no execution history, all on
  // one host — host-attributed (#1110) so a caseWide claim's own intersection-across-known-hosts has
  // something real to check against; a hostless collection can no longer support ANY caseWide claim
  // (see the dedicated per-host-scoping describe block below for that case).
  const collection = [
    ev("a", ["Velociraptor"], "Windows.NTFS.MFT", "host-1"),
    ev("b", ["Velociraptor"], "Windows.Forensics.PersistenceSniper", "host-1"),
    ev("c", ["Velociraptor"], "Generic.System.Pstree", "host-1"),
  ];

  it("downgrades a refutation the collection cannot support", () => {
    const { seeds, downgraded } = gateRefutedSeeds(
      [seed("Ransomware encryption was executed on the host")],
      collection,
    );
    expect(seeds[0].status).toBe("unknown");
    expect(downgraded).toHaveLength(1);
    expect(downgraded[0].missing).toContain("execution");
  });

  it("names the missing evidence class in the rationale so the analyst can collect it", () => {
    const { seeds } = gateRefutedSeeds([seed("Ransomware encryption was executed on the host")], collection);
    expect(seeds[0].description).toContain("execution");
    expect(seeds[0].description).toContain("no source of that kind was collected");
  });

  it("leaves a refutation the collection CAN support alone", () => {
    const { seeds, downgraded } = gateRefutedSeeds(
      [seed("The actor installed a service for persistence")],
      collection,
    );
    expect(seeds[0].status).toBe("refuted");
    expect(downgraded).toHaveLength(0);
  });

  it("never touches a supported or open hypothesis", () => {
    // The gate only ever weakens an assertion of absence. A positive claim rests on evidence that
    // IS present, so missing coverage elsewhere says nothing about it.
    const input = [
      seed("Data was exfiltrated via OneDrive", "supported"),
      seed("Something happened", "open"),
    ];
    const { seeds, downgraded } = gateRefutedSeeds(input, collection);
    expect(seeds.map((s) => s.status)).toEqual(["supported", "open"]);
    expect(downgraded).toHaveLength(0);
  });

  it("leaves a refutation with no recognisable evidence class alone", () => {
    const { seeds } = gateRefutedSeeds([seed("The operator was an authorized red teamer")], collection);
    expect(seeds[0].status).toBe("refuted");
  });

  it("returns the input unchanged when nothing is gated", () => {
    const input = [seed("Something happened", "open")];
    expect(gateRefutedSeeds(input, collection).seeds).toEqual(input);
  });
});

// #1110: refutationGate.ts scoped to a hypothesis's own declared subject host(s), fixing the
// case-wide-and-unscoped finding from #932.1's design review (a single matching source anywhere in
// the case used to grant coverage for every host).
describe("gateRefutedSeeds — per-host scoping (#1110)", () => {
  it("collectedEvidenceClassesByHost partitions by asset, ignoring hostless events", () => {
    const alias = buildHostAliasIndex([], {});
    const byHost = collectedEvidenceClassesByHost(
      [
        ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch", "ws-01"),
        ev("b", ["Velociraptor"], "Windows.NTFS.MFT", "ws-02"),
        ev("c", ["Velociraptor"], "Windows.Forensics.PersistenceSniper"), // no asset
      ],
      alias,
    );
    expect(byHost.get("ws-01")?.has("execution")).toBe(true);
    expect(byHost.get("ws-01")?.has("file-activity")).toBe(false);
    expect(byHost.get("ws-02")?.has("file-activity")).toBe(true);
    expect(byHost.has("")).toBe(false);
  });

  it("a 'hosts' scope requires coverage on EVERY named host — a claim about two hosts is not settled by one", () => {
    const events = [
      ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch", "ws-01"), // execution on ws-01 only
    ];
    const { seeds } = gateRefutedSeeds(
      [seed("No execution on ws-01 or ws-02", "refuted", { kind: "hosts", hosts: ["ws-01", "ws-02"] })],
      events,
    );
    // ws-02 has NO coverage at all, so the intersection is empty — the refutation is withheld even
    // though ws-01 alone would have supported it.
    expect(seeds[0].status).toBe("unknown");
  });

  it("a 'hosts' scope stands when EVERY named host has the required coverage", () => {
    const events = [
      ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch", "ws-01"),
      ev("b", ["Velociraptor"], "Windows.Forensics.Prefetch", "ws-02"),
    ];
    const { seeds } = gateRefutedSeeds(
      [seed("No execution on ws-01 or ws-02", "refuted", { kind: "hosts", hosts: ["ws-01", "ws-02"] })],
      events,
    );
    expect(seeds[0].status).toBe("refuted");
  });

  it("a genuinely 'caseWide' claim needs coverage on EVERY known host, not the old union", () => {
    const events = [
      ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch", "ws-01"), // execution, ws-01 only
      ev("b", ["Velociraptor"], "Windows.NTFS.MFT", "ws-02"), // file-activity, ws-02 only
    ];
    // The old union-based collectedEvidenceClasses(events) would contain "execution" (from ws-01),
    // which would have wrongly left this refutation standing for a claim about the WHOLE case.
    const { seeds } = gateRefutedSeeds(
      [seed("No execution anywhere in the case", "refuted", { kind: "caseWide" })],
      events,
    );
    expect(seeds[0].status).toBe("unknown");
  });

  it("a 'caseWide' claim downgrades when NO host-attributed events exist at all — never the old union (Codex code review finding #1110-H1)", () => {
    // Several importers (e.g. KAPE's MFT/Recycle Bin mappers) do not stamp `asset` today. A single
    // hostless Prefetch row proves Prefetch was collected SOMEWHERE, but not that it covers every
    // host a case-wide claim concerns — falling back to the old union here was found to reintroduce
    // the exact unscoped-coverage problem #1101's own review first identified, so this is a real,
    // accepted behavior change from before #1110, not a preserved compatibility floor.
    const events = [ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch")]; // no asset anywhere
    const { seeds } = gateRefutedSeeds(
      [seed("No execution anywhere in the case", "refuted", { kind: "caseWide" })],
      events,
    );
    expect(seeds[0].status).toBe("unknown");
  });

  it("an 'unknown' scope always downgrades — fail-closed when the claim's own subject could not be established", () => {
    // Even though the case has full execution coverage on every host, an unknown scope can never
    // rely on it: the model's own claim-subject attribution failed, so nothing is assumed collected.
    const events = [
      ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch", "ws-01"),
      ev("b", ["Velociraptor"], "Windows.Forensics.Prefetch", "ws-02"),
    ];
    const { seeds } = gateRefutedSeeds(
      [seed("No execution anywhere", "refuted", { kind: "unknown" })],
      events,
    );
    expect(seeds[0].status).toBe("unknown");
  });

  it("a seed with no subjectScope at all behaves exactly like today's case-wide check (backward compatible)", () => {
    const events = [ev("a", ["Velociraptor"], "Windows.Forensics.PersistenceSniper", "ws-01")];
    const { seeds } = gateRefutedSeeds([seed("The actor installed a service for persistence")], events);
    expect(seeds[0].status).toBe("refuted");
  });

  it("resolves differently-spelled host names through the SAME alias index on both sides", () => {
    const alias = buildHostAliasIndex([{ hostname: "ws-01", fqdn: "ws-01.corp.local" }], {});
    const events = [ev("a", ["Velociraptor"], "Windows.Forensics.Prefetch", "WS-01.corp.local")];
    const { seeds } = gateRefutedSeeds(
      [seed("No execution on ws-01", "refuted", { kind: "hosts", hosts: ["ws-01"] })],
      events,
      alias,
    );
    // Without shared alias resolution, "ws-01" (the seed's own scope) and "WS-01.corp.local" (the
    // event's own asset) would land in different buckets and this would wrongly downgrade.
    expect(seeds[0].status).toBe("refuted");
  });
});

// Codex code-review findings against the first implementation (H2, L1) — fixed, not just designed.
describe("hypothesis.ts / gateRefutedSeeds — code-review fixes (#1110)", () => {
  it("a malformed stored subjectScope does not erase the rest of the stored hypotheses array", () => {
    const good = {
      id: "h1",
      title: "A",
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
    };
    const badScope = {
      id: "h2",
      title: "B",
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      subjectScope: { kind: "bogus" },
    };
    const out = hypothesesSchema.parse([good, badScope]);
    // Before the fix, one malformed item's own parse failure bubbled up through the ARRAY schema's
    // own .catch([]), silently discarding every other analyst's hypothesis in the same file.
    expect(out).toHaveLength(2);
    expect(out[1].subjectScope).toEqual({ kind: "unknown" });
  });

  it("a wrong-typed subjectHosts (not an array) resolves to unknown scope instead of throwing", () => {
    const hostCtx = { resolve: (h: string) => h, knownHosts: new Set(["ws-01"]) };
    expect(() =>
      sanitizeHypotheses(
        [{ title: "Something", subjectScope: "hosts", subjectHosts: "ws-01" }],
        new Set(),
        new Set(),
        undefined,
        hostCtx,
      ),
    ).not.toThrow();
    const out = sanitizeHypotheses(
      [{ title: "Something", subjectScope: "hosts", subjectHosts: "ws-01" }],
      new Set(),
      new Set(),
      undefined,
      hostCtx,
    );
    expect(out[0].subjectScope).toEqual({ kind: "unknown" });
  });
});

// #1111: an analyst-attested EvidenceClass can stand in for automatic detection, with a mandatory
// disclosure when it is the one actually keeping a refutation standing.
describe("gateRefutedSeeds — analyst attestation (#1111)", () => {
  // File-system and persistence coverage, no execution history — same shape as the INC-2026-003
  // fixture above, redeclared here since that one is scoped to its own describe block. Host-stamped
  // (#1110) so a caseWide claim's own intersection-across-known-hosts has something to check against.
  const collection = [
    ev("a", ["Velociraptor"], "Windows.NTFS.MFT", "host-1"),
    ev("b", ["Velociraptor"], "Windows.Forensics.PersistenceSniper", "host-1"),
    ev("c", ["Velociraptor"], "Generic.System.Pstree", "host-1"),
  ];

  const attestation = (over: Partial<AttestedEvidenceClass> = {}): AttestedEvidenceClass => ({
    confirmedBy: "a.analyst@example.invalid",
    confirmedAt: "2026-08-13T09:41:00Z",
    reason: "Reviewed the full Prefetch and Sysmon export against the incident window",
    ...over,
  });

  it("an attestation lets a refutation stand that automatic detection alone would have withheld", () => {
    const attested = new Map([["execution", attestation()] as const]);
    const { seeds, downgraded } = gateRefutedSeeds(
      [seed("The payload never ran on the host")],
      [], // no automatic detection at all
      undefined,
      attested,
    );
    expect(seeds[0].status).toBe("refuted");
    expect(downgraded).toHaveLength(0);
  });

  it("discloses that an attestation, not automatic detection, is what kept the refutation standing", () => {
    const attested = new Map([
      ["execution", attestation({ confirmedBy: "b.reviewer@example.invalid" })] as const,
    ]);
    const { seeds } = gateRefutedSeeds(
      [seed("The payload never ran on the host")],
      [],
      undefined,
      attested,
    );
    expect(seeds[0].description).toContain("analyst-attested coverage");
    expect(seeds[0].description).toContain("b.reviewer@example.invalid");
    expect(seeds[0].description).toContain("execution");
  });

  it("does NOT disclose anything when automatic detection alone already covers the claim", () => {
    const attested = new Map([["execution", attestation()] as const]);
    const { seeds } = gateRefutedSeeds(
      [seed("The actor installed a service for persistence")],
      collection, // covers persistence, not execution
      undefined,
      attested, // execution is attested but not required by THIS claim
    );
    expect(seeds[0].description).toBe("");
  });

  it("still downgrades when neither automatic detection nor attestation covers the required class", () => {
    const attested = new Map([["network", attestation()] as const]); // wrong class attested
    const { seeds, downgraded } = gateRefutedSeeds(
      [seed("The payload never ran on the host")],
      [],
      undefined,
      attested,
    );
    expect(seeds[0].status).toBe("unknown");
    expect(downgraded).toHaveLength(1);
  });

  it("defaults to no attestations when the fourth argument is omitted (backward compatible)", () => {
    const { seeds } = gateRefutedSeeds([seed("The payload never ran on the host")], collection);
    expect(seeds[0].status).toBe("unknown");
  });
});
