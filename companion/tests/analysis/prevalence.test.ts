import { describe, it, expect } from "vitest";
import {
  commandShape,
  patternKey,
  buildPrevalenceIndex,
  eventPrevalence,
  prevalenceTag,
  rarityScore,
  isRare,
  isCommon,
} from "../../src/analysis/prevalence.js";
import { selectSynthesisEventsAnnotated } from "../../src/analysis/synthSelect.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(partial: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-01-02T10:00:00.000Z", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...partial };
}

describe("commandShape", () => {
  it("collapses volatile tokens so the same command on different hosts/paths fingerprints alike", () => {
    const a = commandShape("robocopy C:\\data\\1 \\\\srv1\\bak /mir /R:5");
    const b = commandShape("robocopy C:\\data\\2 \\\\srv2\\bak /mir /R:9");
    expect(a).toBe(b);
    expect(a).toContain("robocopy");
    expect(a).toContain("<path>");
    expect(a).toContain("<unc>");
  });
  it("masks hashes and guids", () => {
    expect(commandShape("load a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")).toContain("<hash>");
    expect(commandShape("id {12345678-1234-1234-1234-123456789abc}")).toContain("<guid>");
  });
});

describe("patternKey", () => {
  it("prefers a content hash, then process+shape, then description shape", () => {
    expect(patternKey(ev({ id: "e", sha256: "ABCDEF" }))).toBe("hash:abcdef");
    expect(patternKey(ev({ id: "e", processName: "robocopy.exe", description: "robocopy C:\\a \\\\s\\b" }))).toMatch(/^proc:robocopy\.exe\|/);
    expect(patternKey(ev({ id: "e", description: "some line" }))).toMatch(/^desc:/);
    expect(patternKey(ev({ id: "e" }))).toBe("");   // no stable pattern
  });
});

describe("buildPrevalenceIndex + eventPrevalence", () => {
  const events = [
    ...Array.from({ length: 30 }, (_, i) => ev({ id: `r${i}`, processName: "robocopy.exe", description: `robocopy C:\\d\\${i} \\\\srv${i % 12}\\bak`, asset: `HOST-${i % 12}`, timestamp: `2026-01-${String((i % 9) + 1).padStart(2, "0")}T02:00:00.000Z` })),
    ev({ id: "rare1", processName: "mimikatz.exe", description: "mimikatz sekurlsa::logonpasswords", asset: "DC01", timestamp: "2026-01-05T12:00:00.000Z" }),
  ];
  const index = buildPrevalenceIndex(events);

  it("counts occurrences, distinct hosts, and the day span of a common pattern", () => {
    const p = eventPrevalence(events[0], index)!;
    expect(p.count).toBe(30);
    expect(p.hostCount).toBe(12);
    expect(p.spanDays).toBeGreaterThanOrEqual(7);
    expect(isCommon(p)).toBe(true);
    expect(prevalenceTag(p)).toMatch(/^common: seen 30× on 12 hosts over \d+d$/);
  });

  it("flags a one-off pattern as rare", () => {
    const p = eventPrevalence(events[30], index)!;
    expect(p.count).toBe(1);
    expect(isRare(p)).toBe(true);
    expect(prevalenceTag(p)).toBe("rare: seen 1× on 1 host");
  });

  it("gives no tag to a mid-band pattern and a higher rarityScore to the rarer event", () => {
    const mid = Array.from({ length: 8 }, (_, i) => ev({ id: `m${i}`, description: "mid pattern here" }));
    const idx = buildPrevalenceIndex(mid);
    expect(prevalenceTag(eventPrevalence(mid[0], idx)!)).toBe("");
    expect(rarityScore(events[30], index)).toBeGreaterThan(rarityScore(events[0], index));
  });
});

describe("selectSynthesisEvents rarity bias (#15)", () => {
  it("gives a rare Info event a seat it would otherwise lose, and is a no-op without rarityOf", () => {
    // 40 common Info events + 1 rare Info event; cap forces selection.
    const common = Array.from({ length: 40 }, (_, i) => ev({ id: `c${i}`, description: "nightly backup run", severity: "Info", timestamp: `2026-01-02T10:${String(i).padStart(2, "0")}:00.000Z` }));
    const rare = ev({ id: "rareEvt", description: "psexec lateral tool copied", severity: "Info", timestamp: "2026-01-02T10:20:30.000Z" });
    const all = [...common, rare];
    const index = buildPrevalenceIndex(all);
    const rarityOf = (e: ForensicEvent) => rarityScore(e, index);

    const withBias = selectSynthesisEventsAnnotated(all, 20, rarityOf);
    expect(withBias.events.some((e) => e.id === "rareEvt")).toBe(true);
    expect(withBias.classOf.get("rareEvt")).toBe("rare");

    // Without rarityOf the counts carry no 'rare' class (behavior unchanged).
    const noBias = selectSynthesisEventsAnnotated(all, 20);
    expect(noBias.counts.rare).toBe(0);
  });
});
