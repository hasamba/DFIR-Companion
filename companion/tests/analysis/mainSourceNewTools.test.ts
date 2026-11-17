import { describe, expect, it } from "vitest";
import {
  computeMainSource,
  familyOfEvent,
  parseMainSourceOverride,
  SOURCE_FAMILIES,
  type SourceFamily,
} from "../../src/analysis/caseMainSource.js";
import {
  HUNT_LANGUAGES,
  huntLanguageFor,
  LANGUAGE_LABELS,
  LANGUAGE_PLATFORM,
  LANGUAGE_SCHEMA_HINTS,
  planHuntGroups,
} from "../../src/analysis/huntLanguage.js";
import {
  HUNT_PLATFORMS,
  normalizeHuntPlatform,
  resolveHuntPlatforms,
} from "../../src/analysis/huntPlatforms.js";
import {
  PLATFORM_LABELS,
  PLATFORM_SCHEMA_HINTS,
  renderPlatformGuide,
  sanitizeQueryTranslations,
} from "../../src/analysis/queryTranslate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2667: Carbon Black, Wazuh, SentinelOne, Cortex XDR and QRadar as main evidence sources, each with
// its own copy-ready hunt language.

let n = 0;
function ev(over: Partial<ForensicEvent>): ForensicEvent {
  n += 1;
  return {
    id: `e${n}`,
    timestamp: "2026-01-01T00:00:00Z",
    description: "row",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

const file = (batch: string, sources: string[], rows = 3): ForensicEvent[] =>
  Array.from({ length: rows }, () => ev({ importBatchId: batch, sources }));

const TOOLS = [
  { label: "Carbon Black", family: "carbonblack", language: "cbc", platform: "carbonblack" },
  { label: "Wazuh", family: "wazuh", language: "wazuh-dql", platform: "wazuh" },
  { label: "SentinelOne", family: "sentinelone", language: "s1-pq", platform: "sentinelone" },
  { label: "Cortex XDR", family: "cortex", language: "xql", platform: "cortex" },
  { label: "QRadar", family: "qradar", language: "aql", platform: "qradar" },
] as const;

const ALL = [...HUNT_PLATFORMS];

describe("the five tools are evidence families (#2667)", () => {
  it.each(TOOLS)("maps the importer label $label to $family", ({ label, family }) => {
    expect(familyOfEvent(ev({ sources: [label] }))).toBe(family);
    expect(familyOfEvent(ev({ sources: [label.toUpperCase()] }))).toBe(family);
  });

  it.each(TOOLS)("reads a generic SIEM row's '$label:' description prefix", ({ label, family }) => {
    expect(familyOfEvent(ev({ sources: ["SIEM import"], description: `${label}: process start` }))).toBe(
      family,
    );
  });

  it.each(TOOLS)("a $label export of cloud logs keeps its tool", ({ label, family }) => {
    expect(familyOfEvent(ev({ sources: [label, "AWS CloudTrail"] }))).toBe(family);
    expect(familyOfEvent(ev({ sources: [label], description: "Entra sign-in: alice" }))).toBe(family);
  });

  it("a case mostly from one of the tools has it as its main source, not host-other", () => {
    for (const t of TOOLS) {
      const events = [...file(`${t.family}-1`, [t.label]), ...file(`${t.family}-2`, [t.label])];
      expect(computeMainSource(events, null).auto).toBe(t.family);
    }
  });

  it("the existing families keep their tie-break order; the five sit after Splunk, before cloud", () => {
    expect(SOURCE_FAMILIES).toEqual([
      "velociraptor",
      "crowdstrike",
      "defender",
      "m365",
      "elastic",
      "splunk",
      "carbonblack",
      "wazuh",
      "sentinelone",
      "cortex",
      "qradar",
      "cloud-other",
      "host-other",
    ]);
    // A row with two tool labels takes the earlier family.
    expect(familyOfEvent(ev({ sources: ["Wazuh", "Splunk"] }))).toBe("splunk");
    expect(familyOfEvent(ev({ sources: ["QRadar", "Carbon Black"] }))).toBe("carbonblack");
  });

  it("an override naming a new tool is accepted, an unknown one refused", () => {
    for (const t of TOOLS) expect(parseMainSourceOverride(t.family)).toEqual({ ok: true, value: t.family });
    expect(parseMainSourceOverride("carbon black").ok).toBe(false);
  });
});

describe("hunt languages for the five tools (#2667)", () => {
  it.each(TOOLS)("$family → $language, platform $platform", ({ family, language, platform }) => {
    expect(huntLanguageFor(family as SourceFamily, ALL)).toEqual({ language, note: "" });
    expect(LANGUAGE_PLATFORM[language]).toBe(platform);
    expect(LANGUAGE_LABELS[language]).toBeTruthy();
  });

  it.each(TOOLS)(
    "$family falls back to VQL with a note when $platform is disabled",
    ({ family, language }) => {
      const c = huntLanguageFor(family, ["velociraptor"]);
      expect(c.language).toBe("vql");
      expect(c.note).toContain(LANGUAGE_LABELS[language]);
      expect(c.note).toMatch(/DFIR_HUNT_PLATFORMS/);
    },
  );

  it("the hunt path and the translator share one schema hint per tool", () => {
    for (const t of TOOLS) {
      expect(LANGUAGE_SCHEMA_HINTS[t.language]).toBe(PLATFORM_SCHEMA_HINTS[t.platform]);
      expect(PLATFORM_SCHEMA_HINTS[t.platform].length).toBeGreaterThan(80);
    }
  });

  it("VQL stays first and the existing languages keep their order", () => {
    expect(HUNT_LANGUAGES.slice(0, 6)).toEqual(["vql", "cql", "kql-device", "kql-cloud", "esql", "spl"]);
    expect(HUNT_LANGUAGES.slice(6)).toEqual(["cbc", "wazuh-dql", "s1-pq", "xql", "aql"]);
  });

  it("a mixed case lists every family's language; an override uses that tool's", () => {
    const items = TOOLS.map((t) => ({ id: t.family, family: t.family }));
    const plan = planHuntGroups(
      items,
      (i) => i.family,
      (i) => i.id,
      { effective: "mixed" },
      ALL,
    );
    expect(plan.groups.map((g) => g.language)).toEqual(["cbc", "wazuh-dql", "s1-pq", "xql", "aql"]);
    const over = planHuntGroups(
      items,
      (i) => i.family,
      (i) => i.id,
      { effective: "qradar" },
      ALL,
    );
    expect(over.groups).toEqual([{ language: "aql", ids: TOOLS.map((t) => t.family) }]);
  });
});

describe("hunt platforms for the five tools (#2667)", () => {
  it("are appended after the existing eight, whose display order is unchanged", () => {
    expect(HUNT_PLATFORMS).toEqual([
      "velociraptor",
      "defender",
      "elastic",
      "splunk",
      "sigma",
      "yara",
      "suricata",
      "crowdstrike",
      "carbonblack",
      "wazuh",
      "sentinelone",
      "cortex",
      "qradar",
    ]);
  });

  it("accept the language ids and common names as aliases", () => {
    for (const t of TOOLS) {
      expect(normalizeHuntPlatform(t.platform)).toBe(t.platform);
      expect(normalizeHuntPlatform(t.language)).toBe(t.platform);
    }
    expect(normalizeHuntPlatform("CB")).toBe("carbonblack");
    expect(normalizeHuntPlatform("s1")).toBe("sentinelone");
    expect(normalizeHuntPlatform("powerquery")).toBe("sentinelone");
    expect(normalizeHuntPlatform("XDR")).toBe("cortex");
    expect(normalizeHuntPlatform("dql")).toBe("wazuh");
  });

  it("DFIR_HUNT_PLATFORMS=velociraptor,wazuh enables only those two", () => {
    expect(resolveHuntPlatforms("velociraptor,wazuh")).toEqual(["velociraptor", "wazuh"]);
    const enabled = resolveHuntPlatforms("velociraptor,wazuh");
    expect(huntLanguageFor("wazuh", enabled).language).toBe("wazuh-dql");
    expect(huntLanguageFor("qradar", enabled).language).toBe("vql");
    expect(huntLanguageFor("crowdstrike", enabled).language).toBe("vql");
  });
});

describe("the Query Translator offers the five tools (#2667)", () => {
  it("labels and grounds each one", () => {
    for (const t of TOOLS) {
      expect(PLATFORM_LABELS[t.platform]).toBeTruthy();
      expect(renderPlatformGuide([t.platform])).toContain(PLATFORM_SCHEMA_HINTS[t.platform]);
    }
  });

  it("keeps a translation answered under a language id, mapped to its platform", () => {
    const out = sanitizeQueryTranslations(
      [
        {
          platform: "aql",
          label: "",
          query: "SELECT * FROM events LAST 1 DAYS",
          explanation: "",
          caveats: "",
          notApplicable: false,
        },
        {
          platform: "xql",
          label: "",
          query: "dataset = xdr_data | limit 5",
          explanation: "",
          caveats: "",
          notApplicable: false,
        },
      ],
      ["qradar", "cortex"],
    );
    expect(out.map((q) => q.platform)).toEqual(["cortex", "qradar"]);
    expect(out[1].label).toBe(PLATFORM_LABELS.qradar);
  });
});
