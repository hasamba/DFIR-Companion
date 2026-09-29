import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #12: a valid rule on a field no scoped event fills returned "Would match 0" and nothing else. The
// server now sends a coverage hint on a 0-match preview; the preview line must show it.

interface StubEl {
  value: string;
  textContent: string;
  innerHTML: string;
  hidden: boolean;
  style: { color: string; cssText: string };
  appendChild: (c: unknown) => void;
}

function el(value = ""): StubEl {
  return {
    value,
    textContent: "",
    innerHTML: "",
    hidden: true,
    style: { color: "", cssText: "" },
    appendChild: () => undefined,
  };
}

async function preview(body: Record<string, unknown>): Promise<string> {
  const els: Record<string, StubEl> = {
    caseId: el("c1"),
    taggerSuggestYaml: el("r: {}"),
    taggerSuggestResultMsg: el(),
    taggerSuggestMatches: el(),
  };
  const api = loadDashboardModule<{ previewTaggerRule: () => Promise<void> }>("dashboard-tagger.js", [], {
    document: { getElementById: (id: string) => els[id] ?? null, createElement: () => el() },
    fetch: async () => ({ ok: true, status: 200, json: async () => body }),
  });
  await api.previewTaggerRule();
  return els.taggerSuggestResultMsg.textContent;
}

describe("tagger preview — 0-match hint", () => {
  it("shows the server's coverage hint when nothing matched", async () => {
    const text = await preview({
      matched: 0,
      scope: "both",
      sample: [],
      fieldCoverage: { message: 0 },
      scanned: 7,
      hint: '0 of 7 events have "message"; try "description"',
    });
    expect(text).toContain("Would match 0 event(s)");
    expect(text).toContain('0 of 7 events have "message"; try "description"');
  });

  it("shows no hint when the rule matched", async () => {
    const text = await preview({ matched: 2, scope: "both", sample: [] });
    expect(text).toBe("Would match 2 event(s) in this case (scope: both).");
  });
});
