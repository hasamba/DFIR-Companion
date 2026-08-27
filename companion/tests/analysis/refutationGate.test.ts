import { describe, it, expect } from "vitest";
import {
  requiredEvidenceClasses,
  collectedEvidenceClasses,
  gateRefutedSeeds,
  EVIDENCE_CLASS_SOURCES,
  type EvidenceClass,
} from "../../src/analysis/refutationGate.js";
import type { HypothesisSeed } from "../../src/analysis/hypothesis.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, sources: string[], artifactName?: string): ForensicEvent {
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
  };
}

function seed(title: string, status: HypothesisSeed["status"] = "refuted"): HypothesisSeed {
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
    const got = collectedEvidenceClasses([ev("a", ["Velociraptor"], "Windows.Forensics.Amcache")]);
    expect(got.has("execution")).toBe(true);
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
  // The INC-2026-003 collection: file-system and persistence coverage, no execution history.
  const collection = [
    ev("a", ["Velociraptor"], "Windows.NTFS.MFT"),
    ev("b", ["Velociraptor"], "Windows.Forensics.PersistenceSniper"),
    ev("c", ["Velociraptor"], "Generic.System.Pstree"),
  ];

  it("downgrades a refutation the collection cannot support", () => {
    const { seeds, downgraded } = gateRefutedSeeds(
      [seed("Ransomware encryption was executed on the host")],
      collectedEvidenceClasses(collection),
    );
    expect(seeds[0].status).toBe("unknown");
    expect(downgraded).toHaveLength(1);
    expect(downgraded[0].missing).toContain("execution");
  });

  it("names the missing evidence class in the rationale so the analyst can collect it", () => {
    const { seeds } = gateRefutedSeeds(
      [seed("Ransomware encryption was executed on the host")],
      collectedEvidenceClasses(collection),
    );
    expect(seeds[0].description).toContain("execution");
    expect(seeds[0].description).toContain("no source of that kind was collected");
  });

  it("leaves a refutation the collection CAN support alone", () => {
    const { seeds, downgraded } = gateRefutedSeeds(
      [seed("The actor installed a service for persistence")],
      collectedEvidenceClasses(collection),
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
    const { seeds, downgraded } = gateRefutedSeeds(input, collectedEvidenceClasses(collection));
    expect(seeds.map((s) => s.status)).toEqual(["supported", "open"]);
    expect(downgraded).toHaveLength(0);
  });

  it("leaves a refutation with no recognisable evidence class alone", () => {
    const { seeds } = gateRefutedSeeds(
      [seed("The operator was an authorized red teamer")],
      collectedEvidenceClasses(collection),
    );
    expect(seeds[0].status).toBe("refuted");
  });

  it("returns the input unchanged when nothing is gated", () => {
    const input = [seed("Something happened", "open")];
    expect(gateRefutedSeeds(input, collectedEvidenceClasses(collection)).seeds).toEqual(input);
  });
});
