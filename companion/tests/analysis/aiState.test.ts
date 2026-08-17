import { describe, it, expect } from "vitest";
import { deriveAiState, type AiStateInput } from "../../src/analysis/aiState.js";
import type { Job } from "../../src/analysis/jobRegistry.js";
import type { CustomEntity } from "../../src/analysis/anonymize.js";

const PAIR = { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" as const };
const FINDING: CustomEntity = { value: "Jane Doe", category: "PERSON" };

function job(overrides: Partial<Job> = {}): Job {
  return {
    id: "j1",
    caseId: "c1",
    kind: "synthesis",
    status: "running",
    priority: "normal",
    queuedAt: "2026-08-16T10:00:00.000Z",
    updatedAt: "2026-08-16T10:00:00.000Z",
    ...overrides,
  } as Job;
}

const base: AiStateInput = { aiConfigured: true, enabled: true };

describe("deriveAiState — nothing configured, and the live toggle", () => {
  it("reports off only when no model is configured", () => {
    expect(deriveAiState({ ...base, aiConfigured: false })).toMatchObject({
      state: "off",
      detail: "no AI model configured",
    });
  });

  // `AiControl.enabled` gates the LIVE screenshot loop only — manual synthesis, deep pass and
  // imports all run with it off — and it DEFAULTS TO FALSE. Folding it into "off" would report
  // every fresh case as switched off. Caught by the route test, which saw a quiet case as "off".
  it("does not call a paused case off — the toggle is a fact, not a state", () => {
    const state = deriveAiState({ ...base, enabled: false });
    expect(state.state).toBe("idle");
    expect(state.livePaused).toBe(true);
    expect(state.detail).toContain("live analysis paused");
  });

  // The sharper half of the same mistake: a paused case can still be genuinely held, and reporting
  // "off" would hide a decision the analyst has to make before anything will run again.
  it("still reports blocked when a paused case is held at a gate", () => {
    const state = deriveAiState({ ...base, enabled: false, hostDuplicates: [PAIR] });
    expect(state.state).toBe("blocked");
    expect(state.livePaused).toBe(true);
    expect(state.holds).toHaveLength(1);
  });
});

describe("deriveAiState — gates", () => {
  it("is blocked on an unresolved duplicate pair, worded like the gate itself", () => {
    const state = deriveAiState({ ...base, hostDuplicates: [PAIR] });
    expect(state.state).toBe("blocked");
    expect(state.detail).toBe("1 possible duplicate host awaiting a merge decision");
  });

  it("is blocked on a pending Presidio finding", () => {
    const state = deriveAiState({ ...base, presidioPending: [FINDING] });
    expect(state.state).toBe("blocked");
    expect(state.detail).toContain("Presidio");
  });

  it("names both gates when both are pending", () => {
    const state = deriveAiState({ ...base, hostDuplicates: [PAIR], presidioPending: [FINDING] });
    expect(state.holds.map((h) => h.kind)).toEqual(["host-duplicates", "presidio"]);
    expect(state.detail).toContain("duplicate host");
    expect(state.detail).toContain("Presidio");
  });

  it("pluralises each gate's count", () => {
    const state = deriveAiState({
      ...base,
      hostDuplicates: [PAIR, { ...PAIR, other: "dc01", canonical: "dc01.windomain.local" }],
      presidioPending: [FINDING, { value: "John Smith", category: "PERSON" }],
    });
    expect(state.detail).toContain("2 possible duplicate hosts");
    expect(state.detail).toContain("2 Presidio findings");
  });

  // THE BUG THIS WHOLE MODULE EXISTS FOR (mode 3): a held case that is simply sitting there must
  // never derive as idle/ready. Before this, a page reload asked /health — which is server-wide and
  // cannot know about a case — and set the pill to "ready (waiting for activity)".
  it("never derives idle while a gate is pending", () => {
    for (const input of [
      { ...base, hostDuplicates: [PAIR] },
      { ...base, presidioPending: [FINDING] },
      {
        ...base,
        hostDuplicates: [PAIR],
        jobs: [job({ status: "succeeded", endedAt: "2026-08-16T11:00:00.000Z" })],
      },
    ]) {
      expect(deriveAiState(input).state).not.toBe("idle");
    }
  });
});

describe("deriveAiState — work in flight", () => {
  // A running import is real work even while synthesis is held. Reporting that as plain "blocked"
  // would hide it — the mirror of the bug where a held run was reported as "synthesizing".
  it("reports running work while still naming what is held", () => {
    const state = deriveAiState({
      ...base,
      hostDuplicates: [PAIR],
      jobs: [job({ kind: "import", label: "evtx import" })],
    });
    expect(state.state).toBe("analyzing");
    expect(state.detail).toBe("evtx import");
    expect(state.holds).toHaveLength(1);
    expect(state.holds[0].kind).toBe("host-duplicates");
  });

  it("counts a queued job as work in flight", () => {
    expect(deriveAiState({ ...base, jobs: [job({ status: "queued" })] }).state).toBe("analyzing");
  });

  it("lists every running job so the pill can name the work", () => {
    const state = deriveAiState({
      ...base,
      jobs: [job({ id: "a", kind: "import", label: "evtx" }), job({ id: "b", kind: "enrichment" })],
    });
    expect(state.running).toEqual([
      { kind: "import", label: "evtx" },
      { kind: "enrichment", label: "enrichment" },
    ]);
  });
});

describe("deriveAiState — failures", () => {
  it("reports the latest ended job when it failed", () => {
    const state = deriveAiState({
      ...base,
      jobs: [job({ status: "failed", endedAt: "2026-08-16T11:00:00.000Z", error: "model returned 500" })],
    });
    expect(state).toMatchObject({ state: "error", detail: "model returned 500" });
  });

  // A failure that has since been superseded by successful work must not pin the pill red forever;
  // run history belongs to the cockpit's activity cards, not to a live status indicator.
  it("clears once later work has succeeded", () => {
    const state = deriveAiState({
      ...base,
      jobs: [
        job({ id: "a", status: "failed", endedAt: "2026-08-16T11:00:00.000Z", error: "boom" }),
        job({ id: "b", kind: "import", status: "succeeded", endedAt: "2026-08-16T12:00:00.000Z" }),
      ],
    });
    expect(state.state).toBe("idle");
  });

  it("still prefers a pending gate over an old failure", () => {
    const state = deriveAiState({
      ...base,
      hostDuplicates: [PAIR],
      jobs: [job({ status: "failed", endedAt: "2026-08-16T11:00:00.000Z", error: "boom" })],
    });
    expect(state.state).toBe("blocked");
  });
});

describe("deriveAiState — the quiet case", () => {
  it("is idle with nothing pending, nothing running and nothing broken", () => {
    expect(deriveAiState(base)).toMatchObject({ state: "idle", holds: [], running: [] });
  });

  it("treats absent optional inputs as nothing, never as unknown", () => {
    expect(deriveAiState({ aiConfigured: true, enabled: true }).state).toBe("idle");
  });
});
