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

// PersistenceSniper's grading (LOLBin -> High, non-valid signature -> Medium) is done directly in
// analysis/persistenceSniperImport.ts, from the module's own structured columns — see that file's
// tests. A tagger rule re-deriving the same verdict from the rendered description was tried first
// and reverted: it was spoofable via a crafted Value/Path (a file literally named "evil.exe
// [lolbin]" faked a High grade the module never gave) and lossy (the description's 600-char cap
// could truncate a genuine marker, leaving a real LOLBin at Info). There is deliberately no
// PersistenceSniper-specific rule in tags.yaml.
