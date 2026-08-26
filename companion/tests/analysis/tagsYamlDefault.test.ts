import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Guards the shipped default ruleset: a YAML typo, an unknown field, or a bad regex here would ship
// a broken default. This compiles data/tags.yaml exactly as the app does.
describe("bundled data/tags.yaml", () => {
  it("compiles cleanly and defines multiple rules", () => {
    const path = fileURLToPath(new URL("../../data/tags.yaml", import.meta.url));
    const text = readFileSync(path, "utf8");
    const rs = compileText(text);
    expect(rs.rules.length).toBeGreaterThan(5);
    // every rule carries at least one action
    for (const r of rs.rules) {
      const hasAction =
        r.tags.length > 0 || r.mitre.length > 0 || r.severity !== undefined || r.view !== undefined;
      expect(hasAction, `rule ${r.id} has no action`).toBe(true);
    }
  });
});

// Removable media is why this rule exists: a mass-storage mount arrives from Velociraptor ungraded,
// and anything left at Info never reaches the forensic timeline, so the AI cannot reason about it.
// The rule lifts it to Low — present in the record, without shouting.
describe("bundled data/tags.yaml — removable media", () => {
  const RULESET = compileText(
    readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
  );

  function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
    return {
      timestamp: "2026-06-01T00:00:00Z",
      description: "d",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      ...p,
    };
  }

  it("raises a mass-storage mount above Info and tags it", () => {
    const res = runTagger([ev({ id: "e1", artifactName: "Windows.Mounted.Mass.Storage" })], RULESET);
    const hit = res.perEvent.find((e) => e.eventId === "e1");
    expect(hit?.severity).toBe("Low");
    expect(hit?.tags).toContain("removable-media");
    expect(hit?.mitre).toContain("T1091");
  });

  it("matches USB registry evidence in a message, whatever the artifact is called", () => {
    const res = runTagger(
      [ev({ id: "e2", message: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk" })],
      RULESET,
    );
    expect(res.perEvent.find((e) => e.eventId === "e2")?.severity).toBe("Low");
  });

  it("leaves an unrelated event alone", () => {
    const res = runTagger([ev({ id: "e3", description: "user opened a document" })], RULESET);
    expect(res.perEvent.find((e) => e.eventId === "e3")).toBeUndefined();
  });
});

// PersistenceSniper enumerates every autostart on the box — mostly signed, first-party, and
// ordinary — so it's mapped at Info by design (analysis/persistenceSniperImport.ts) and left there
// unless one of its own anomaly markers is present. Without these rules NOTHING it finds ever
// reaches the forensic timeline, however suspicious.
describe("bundled data/tags.yaml — PersistenceSniper", () => {
  const RULESET = compileText(
    readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
  );

  function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
    return {
      timestamp: "2026-06-01T00:00:00Z",
      description: "d",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      ...p,
    };
  }

  it("raises a LOLBin persistence finding to High", () => {
    const res = runTagger(
      [
        ev({
          id: "e1",
          artifactName: "Windows.Forensics.PersistenceSniper",
          description: "Velociraptor: Persistence [Scheduled Task] — C:\\Windows\\System32\\rundll32.exe [lolbin]",
        }),
      ],
      RULESET,
    );
    const hit = res.perEvent.find((e) => e.eventId === "e1");
    expect(hit?.severity).toBe("High");
    expect(hit?.tags).toContain("lolbin");
  });

  it("raises an unsigned persistence target to Medium", () => {
    const res = runTagger(
      [
        ev({
          id: "e2",
          artifactName: "Windows.Forensics.PersistenceSniper",
          description: "Velociraptor: Persistence [Registry Run Key] — C:\\evil.exe [signature: NotSigned]",
        }),
      ],
      RULESET,
    );
    const hit = res.perEvent.find((e) => e.eventId === "e2");
    expect(hit?.severity).toBe("Medium");
    expect(hit?.tags).toContain("unsigned-binary");
  });

  it("leaves an ordinary, signed PersistenceSniper finding at Info (no flood)", () => {
    const res = runTagger(
      [
        ev({
          id: "e3",
          artifactName: "Windows.Forensics.PersistenceSniper",
          description: "Velociraptor: Persistence [Scheduled Task] — C:\\Windows\\System32\\svchost.exe (User)",
        }),
      ],
      RULESET,
    );
    expect(res.perEvent.find((e) => e.eventId === "e3")).toBeUndefined();
  });

  it("does not fire on an unrelated artifact that happens to contain '[lolbin]' text", () => {
    const res = runTagger(
      [ev({ id: "e4", artifactName: "Windows.Detection.Yara.Process", description: "match: [lolbin] rule" })],
      RULESET,
    );
    expect(res.perEvent.find((e) => e.eventId === "e4")).toBeUndefined();
  });
});
