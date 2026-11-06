import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { autoTagNewEvents } from "../../src/analysis/taggerAuto.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { RulePackStore } from "../../src/analysis/rulePackStore.js";
import type { AnalysisRunManifest } from "../../src/analysis/analysisRunTypes.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  taggerRuleSourcesIn,
  taggerRulesMarkdown,
  withTaggerRulesHtml,
} from "../../src/reports/taggerRulesProvenance.js";
import { RULES_V1, manifestFor } from "../analysis/rulePackFixtures.js";
import { parseRulePackManifest } from "../../src/analysis/rulePackManifest.js";

// #2349: every tagger run names the rules that graded it (bundled, a pack, an edited copy) in the
// analysis-run ledger, and the reports list them — the tagger's counterpart of the Sigma stamp.

const run = (rulePack?: string) =>
  ({
    configuration: { parameters: rulePack ? { analyzer: "tagger", rulePack } : { analyzer: "x" } },
  }) as unknown as AnalysisRunManifest;

describe("tagger rule provenance in reports", () => {
  it("lists each distinct rule source once, in first-seen order", () => {
    const runs = [
      run("bundled with the app (0.45.0)"),
      run(),
      run("rule pack rules-2026.11.05 (downloaded from GitHub)"),
      run("bundled with the app (0.45.0)"),
    ];
    expect(taggerRuleSourcesIn(runs)).toEqual([
      "bundled with the app (0.45.0)",
      "rule pack rules-2026.11.05 (downloaded from GitHub)",
    ]);
  });

  it("renders a Markdown section and an escaped HTML block, and nothing when no run recorded rules", () => {
    expect(taggerRulesMarkdown([])).toBe("");
    expect(taggerRulesMarkdown(["rule pack rules-2026.11.05"])).toMatch(
      /### Tagger rules[\s\S]*- rule pack rules-2026\.11\.05/,
    );
    const html = withTaggerRulesHtml("<html><body><p>x</p></body></html>", ["<b>pack</b>"]);
    expect(html).toMatch(/Tagger rules.*&lt;b&gt;pack&lt;\/b&gt;.*<\/section>\n<\/body>/s);
    expect(withTaggerRulesHtml("<body></body>", [])).toBe("<body></body>");
  });
});

describe("the import-time tagger run records its rule pack", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-tagger-prov-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("stamps the installed pack's version on the analysis run", async () => {
    const store = new CaseStore(dir);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const bundled = join(dir, "bundled.yaml");
    await writeFile(bundled, "b:\n  any:\n    - { field: message, contains: ['zz'] }\n  tags: ['z']\n");
    const packs = new RulePackStore(join(dir, "pack"), "0.45.0");
    const tag = "rules-2026.11.05";
    const staged = packs.stage({
      rulesText: RULES_V1,
      manifest: parseRulePackManifest(manifestFor(RULES_V1, tag)),
      origin: "downloaded",
      verifiedByGitHub: true,
    });
    await packs.install(staged.token);
    const recorded: unknown[] = [];
    const event: ForensicEvent = {
      id: "e1",
      timestamp: "2026-06-01T00:00:00Z",
      description: "d",
      message: "alpha",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    };
    await autoTagNewEvents(
      {
        taggerStore: new TaggerStore(join(dir, "user.yaml"), [bundled], { pack: packs }),
        tagsStore: new TagsStore(store),
        analysisRunStore: { record: async (_c: string, input: unknown) => recorded.push(input) } as never,
      },
      "c1",
      [event],
    );
    expect(recorded).toHaveLength(1);
    const params = (recorded[0] as { configuration: { parameters: Record<string, unknown> } }).configuration
      .parameters;
    expect(params.rulePack).toBe(`rule pack ${tag} (downloaded from GitHub)`);
  });
});
