import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { LANGUAGE_LABELS } from "../../src/analysis/huntLanguage.js";
import { HUNT_PLATFORMS } from "../../src/analysis/huntPlatforms.js";
import { WATSON_PROMPT } from "../../src/analysis/ai/prompts/watson.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2667: the dashboard names the five new languages, and the Query Translator offers their tools.

interface Api {
  playbookHuntButton: (ms: unknown) => { text: string; title: string };
}

const load = () =>
  loadDashboardModule<Api>("dashboard-main-source.js", ["dashboard-escape.js"], {
    document: { getElementById: () => null },
    fetch: async () => ({ ok: true, json: async () => null }),
  });

const ms = (effective: string, language: string) => ({
  effective,
  override: null,
  totalFiles: 1,
  counts: [],
  families: [],
  language: { language, label: LANGUAGE_LABELS[language as keyof typeof LANGUAGE_LABELS], note: "" },
});

const root = new URL("../../../public/", import.meta.url);
const mainSourceJs = readFileSync(new URL("js/dashboard-main-source.js", root), "utf8");
const translatorJs = readFileSync(new URL("js/dashboard-query-translator.js", root), "utf8");

describe("main-source language cards (#2667)", () => {
  it.each([
    ["carbonblack", "cbc", "✨ Suggest Carbon Black queries"],
    ["wazuh", "wazuh-dql", "✨ Suggest Wazuh queries"],
    ["sentinelone", "s1-pq", "✨ Suggest SentinelOne queries"],
    ["cortex", "xql", "✨ Suggest XQL queries"],
    ["qradar", "aql", "✨ Suggest AQL queries"],
  ])("the playbook button names %s's language", (family, language, text) => {
    const b = load().playbookHuntButton(ms(family, language));
    expect(b.text).toBe(text);
    expect(b.title).toContain(LANGUAGE_LABELS[language as keyof typeof LANGUAGE_LABELS]);
  });

  it("the card labels match the server's language labels", () => {
    for (const [id, label] of Object.entries(LANGUAGE_LABELS)) {
      if (id === "vql") continue;
      expect(mainSourceJs).toContain(`${JSON.stringify(label)}`);
    }
  });
});

describe("Query Translator platforms (#2667)", () => {
  it("lists every hunt platform, in the server's order", () => {
    const order = /NLQ_PLATFORM_ORDER = \[([^\]]*)\]/.exec(translatorJs)?.[1] ?? "";
    expect([...order.matchAll(/"([a-z]+)"/g)].map((m) => m[1])).toEqual([...HUNT_PLATFORMS]);
    for (const p of HUNT_PLATFORMS) expect(translatorJs).toMatch(new RegExp(`\\b${p}:\\s*"`));
  });
});

describe("Watson's reply shape names the new languages (#2667)", () => {
  it("advertises each id alongside the old ones", () => {
    const line = WATSON_PROMPT.split("\n").find((l) => l.includes('"kind": "query"')) ?? "";
    for (const id of [
      "vql",
      "kql",
      "spl",
      "cql",
      "esql",
      "cbc",
      "wazuh-dql",
      "s1-pq",
      "xql",
      "aql",
      "sql",
      "other",
    ])
      expect(line).toContain(id);
  });
});
