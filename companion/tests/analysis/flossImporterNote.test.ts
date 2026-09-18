import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// Importer-level coverage for `importFlossResult` (#1303, #1304): the parser tests in
// flossResultImport.test.ts stop at `parseFlossResult`; nothing there exercises the empty-import
// guard or the analyst-visible timeline note. Both live one call up, in the ingest wrapper.
//
// Field names follow FLOSS's own results.py dataclasses (mandiant/flare-floss); all values below
// are synthetic.
const SHA256 = "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf";
const METADATA = {
  file_path: "/samples/malware.exe",
  md5: "",
  sha1: "",
  sha256: SHA256,
  version: "v2.2.0-0-g783dd8f",
  imagebase: 4194304,
  min_length: 4,
  runtime: { total: 1.2 },
  language: "",
  language_version: "",
  language_selected: "",
};

const DECODED_ENTRY = {
  address: 4198400,
  address_type: "absolute",
  string: "cmd.exe /c whoami",
  encoding: "ASCII",
  decoded_at: 4199118,
  decoding_routine: 4198722,
};
const LANGUAGE_ENTRY = { string: "runtime.gopanic", offset: 4096, encoding: "ASCII" };
const C2_URL = "http://c2.example.com/beacon";
const STATIC_C2_ENTRY = { string: C2_URL, offset: 1, encoding: "ASCII" };
const STATIC_PLAIN_ENTRY = { string: "CODE", offset: 2, encoding: "ASCII" };

function floss(overrides: {
  metadata?: Partial<typeof METADATA>;
  decoded?: unknown[];
  language?: unknown[];
  static_?: unknown[];
}): string {
  return JSON.stringify({
    metadata: { ...METADATA, ...(overrides.metadata ?? {}) },
    analysis: {},
    strings: {
      decoded_strings: overrides.decoded ?? [],
      stack_strings: [],
      tight_strings: [],
      language_strings: overrides.language ?? [],
      language_strings_missed: [],
      static_strings: overrides.static_ ?? [],
    },
  });
}

async function importDoc(doc: string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-floss-note-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(caseStore);
  const pipeline = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const state = await pipeline.importFlossResult("c1", doc, {
    label: "floss.json",
    idPrefix: "fl",
    importedAt: "2026-09-18T12:00:00.000Z",
  });
  const note = state.timeline.find((t) => t.description.startsWith("FLOSS results import:"))?.description;
  return { state, note: note ?? "" };
}

describe("importFlossResult — the ingest wrapper, end to end through a real state store", () => {
  it("a language-only report: the note names the language kind, not just decoded/stack/tight (#1303)", async () => {
    const { state, note } = await importDoc(
      floss({ metadata: { language: "go", language_version: "1.21" }, language: [LANGUAGE_ENTRY] }),
    );
    expect(state.forensicTimeline).toHaveLength(1);
    expect(state.forensicTimeline[0].description).toContain("language-runtime string");
    expect(note).toContain("1 decoded/stack/tight/language string(s) from 1 entry(ies)");
    expect(note).not.toContain("decoded/stack/tight string(s)");
    expect(note).not.toContain("static string(s)");
  });

  it("a static-only report keeps the IOCs the parser found — C2 url, domain, sample hash — instead of dropping them on the empty-import branch (#1304)", async () => {
    const { state, note } = await importDoc(floss({ static_: [STATIC_C2_ENTRY] }));
    expect(state.forensicTimeline).toHaveLength(0);
    const values = state.iocs.map((i) => i.value);
    expect(values).toContain(C2_URL);
    expect(values).toContain(SHA256);
    expect(state.iocs.filter((i) => i.type === "domain")).toHaveLength(1);
    expect(state.iocs).toHaveLength(3);
    expect(note).toContain("0 decoded/stack/tight/language string(s) from 0 entry(ies)");
    expect(note).toContain(
      "1 static string(s) not imported as events (IOC scan only: 1 of 1 visited, 2 IOC mention(s))",
    );
    expect(note).toContain("3 IOC(s)");
    expect(note).not.toContain("not imported by design");
    expect(note).not.toContain("nothing added to the case");
  });

  it("a mixed report: both the event count and the static IOC-scan clause appear in one note (#1304)", async () => {
    const { state, note } = await importDoc(
      floss({ decoded: [DECODED_ENTRY], static_: [STATIC_C2_ENTRY, STATIC_PLAIN_ENTRY] }),
    );
    expect(state.forensicTimeline).toHaveLength(1);
    expect(state.iocs.map((i) => i.value)).toContain(C2_URL);
    expect(note).toContain("1 decoded/stack/tight/language string(s) from 1 entry(ies)");
    expect(note).toContain(
      "2 static string(s) not imported as events (IOC scan only: 2 of 2 visited, 2 IOC mention(s))",
    );
    expect(note).toContain("3 IOC(s)");
  });

  it("a report with no events and no IOCs at all still takes the empty-import branch, with the static clause in the gap detail", async () => {
    const { state, note } = await importDoc(
      floss({ metadata: { sha256: "" }, static_: [STATIC_PLAIN_ENTRY] }),
    );
    expect(state.forensicTimeline).toHaveLength(0);
    expect(state.iocs).toHaveLength(0);
    expect(note).toContain("no events from 0 record(s) — nothing added to the case");
    expect(note).toContain(
      "1 static string(s) not imported as events (IOC scan only: 1 of 1 visited, 0 IOC mention(s))",
    );
    expect(note).not.toContain("not imported by design");
  });
});
