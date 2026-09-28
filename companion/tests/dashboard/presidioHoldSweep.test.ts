// A Presidio hold is a question for the analyst, not a failure (#1782).
//
// When the Presidio gate finds new values, every gated AI route answers 409
// `presidio_approval_required`. Many buttons showed that as a red "failed: … — restart the
// companion server if this 404s". The sweep below pins that every gated caller asks the shared
// presidioHold() predicate first; the behavioural cases prove the neutral wording reaches the
// screen and the failure wording does not.
import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const readJs = (file: string) => readFileSync(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");

/** Each swept file, and the gated routes its fetches hit. */
const GATED: Record<string, RegExp> = {
  "dashboard-explain-event.js": /\/explain`/g,
  "dashboard-super-timeline.js": /\/(starred-report|view-summary)`, \{ method: "POST"/g,
  "dashboard-derived-panels.js": /\/remediation-plan`/g,
  "dashboard-hypotheses.js": /\/(hypothesis-review|hypotheses|synthesize)`, \{/g,
  "dashboard-adversary-hints.js": /\/adversary-hints\/hunt-technique`/g,
  "dashboard-memory-next-steps.js": /\/memory\/next-steps`/g,
  "dashboard-query-translator.js": /\/translate-query`/g,
  "dashboard-gap-hypotheses.js": /\/timeline-gaps\/hypothesize`/g,
  "dashboard-tagger.js": /\/tagger\/suggest-rule`/g,
  "dashboard-playbook.js": /\/playbook\/suggest-hunts`/g,
  "dashboard-sessions.js": /\/summary`/g,
  "dashboard-hunts-jumps.js": /\/velociraptor\/suggest-hunts`/g,
  "dashboard-false-positive.js": /\/false-positive\/suggest`/g,
  "dashboard-second-opinion.js": /\/second-opinion\/apply(-all)?`/g,
  "dashboard-deep-pass.js": /\/deep-pass`, \{/g,
  "dashboard-second-look.js": /\/second-look`, \{/g,
};

describe("every gated AI caller treats a Presidio 409 as a hold (#1782)", () => {
  for (const [file, route] of Object.entries(GATED)) {
    it(`${file} asks presidioHold() at each gated fetch`, () => {
      const src = readJs(file);
      const fetches = (src.match(route) ?? []).length;
      expect(fetches, `no gated fetch found in ${file} — the sweep pattern is stale`).toBeGreaterThan(0);
      // false-positive shares one helper between its two fetches; every other file asks per fetch.
      const needed = file === "dashboard-false-positive.js" ? 1 : fetches;
      expect((src.match(/presidioHold\(/g) ?? []).length).toBeGreaterThanOrEqual(needed);
      expect(src).not.toContain("presidio_approval_required — restart");
      // The hold text is never painted in the failure colour.
      for (const line of src.split("\n").filter((l) => l.includes("presidioHoldText("))) {
        expect(line).not.toMatch(/sev-high|badge-danger|failed|restart/);
      }
    });
  }
});

const HOLD = {
  error: "presidio_approval_required",
  findings: [{ value: "WS-FINANCE-07", category: "HOST" }],
};

interface El {
  innerHTML: string;
  textContent: string;
  value: string;
  disabled: boolean;
  style: Record<string, string>;
}
const el = (value = ""): El => ({ innerHTML: "", textContent: "", value, disabled: false, style: {} });

/** A page with the given elements, a fetch that always answers the hold, and the real presidio module. */
function heldPage(elements: Record<string, El>, extra: Record<string, unknown> = {}) {
  const all: Record<string, El> = { caseId: el("case-1"), presidioPendingBadge: el(), ...elements };
  return {
    all,
    globals: {
      document: {
        getElementById: (id: string) => all[id] ?? null,
        querySelector: (): { value: string } | null => null,
        querySelectorAll: (): { value: string }[] => [],
        addEventListener: () => {},
      },
      // The hold itself, then the badge's re-read of the case's pending store.
      fetch: (url: string) =>
        url.endsWith("/presidio-pending")
          ? Promise.resolve({
              ok: true,
              status: 200,
              json: () => Promise.resolve({ pending: HOLD.findings }),
            })
          : Promise.resolve({ ok: false, status: 409, json: () => Promise.resolve(HOLD) }),
      ...extra,
    },
  };
}

const settle = () => new Promise((r) => setTimeout(r, 10));

function expectHeld(text: string, what: string) {
  expect(text).toContain(`${what} held for Presidio approval — review in Anonymization`);
  expect(text).not.toMatch(/failed|error|restart|sev-high/i);
}

describe("a held AI call reads as a hold on screen (#1782)", () => {
  it("gap hypotheses: neutral hold text, and the ⚠ Presidio badge counts the finding", async () => {
    const { all, globals } = heldPage({
      gapHypotheses: el(),
      hypothesizeGapsMsg: el(),
      hypothesizeGapsBtn: el(),
    });
    const api = loadDashboardModule<{ doHypothesizeGaps: () => void }>(
      "dashboard-gap-hypotheses.js",
      ["dashboard-escape.js", "dashboard-presidio.js"],
      globals,
    );
    api.doHypothesizeGaps();
    await settle();
    expectHeld(all.gapHypotheses.innerHTML, "Gap hypotheses");
    expect(all.gapHypotheses.innerHTML).toContain("var(--text-muted)");
    expect(all.presidioPendingBadge.textContent).toBe("⚠ Presidio: 1");
  });

  it("query translator: neutral hold text instead of an error", async () => {
    const { all, globals } = heldPage({
      nlqInput: el("find lateral movement"),
      nlqResult: el(),
      nlqBtn: el(),
    });
    globals.document.querySelectorAll = () => [{ value: "splunk" }];
    const api = loadDashboardModule<{ doTranslateQuery: () => void }>(
      "dashboard-query-translator.js",
      ["dashboard-escape.js", "dashboard-presidio.js"],
      globals,
    );
    api.doTranslateQuery();
    await settle();
    expectHeld(all.nlqResult.innerHTML, "Query translation");
    expect(all.nlqBtn.disabled).toBe(false);
  });

  it("deep pass: shown as guidance, not as 'Deep pass failed'", async () => {
    const { all, globals } = heldPage(
      { deepPassGuidance: el(), deepPassProgress: el(), deepPassResult: el() },
      { applyHeavyAiJobLock: () => {}, loadJobs: () => {}, loadSynthMeta: () => {}, render: () => {} },
    );
    globals.document.querySelector = () => ({ value: "High" });
    const api = loadDashboardModule<{ runDeepPass: () => void }>(
      "dashboard-deep-pass.js",
      ["dashboard-escape.js", "dashboard-presidio.js"],
      globals,
    );
    api.runDeepPass();
    await settle();
    expectHeld(all.deepPassGuidance.innerHTML, "Deep pass");
    expect(all.deepPassResult.innerHTML).not.toContain("Deep pass failed");
  });
});
