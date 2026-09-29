import { describe, it, expect, afterEach } from "vitest";
import { createCaseAppliers } from "../../src/composition/caseAppliers.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import type { Logger, LogContext } from "../../src/logging/logger.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { CaseStore } from "../../src/storage/caseStore.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { emptyUndoStack, applyUndo, type ImportUndoStack } from "../../src/analysis/importUndo.js";

// #qa-kimi B: a checkpoint above V8's maximum string length throws RangeError, and the catch around
// pushImportCheckpoint swallowed it silently — Undo stopped covering imports with no trace anywhere.
// The failure stays non-fatal (the import must still land) but must now reach the server log.

function captureLogger(): { logger: Logger; warns: Array<{ msg: string; ctx?: LogContext }> } {
  const warns: Array<{ msg: string; ctx?: LogContext }> = [];
  const noop = (): void => undefined;
  const logger: Logger = {
    debug: noop,
    info: noop,
    warn: (msg, ctx) => warns.push({ msg, ctx }),
    error: noop,
    getLevel: () => "debug",
    setLevel: noop,
    close: async () => undefined,
  };
  return { logger, warns };
}

describe("pushImportCheckpoint failure logging", () => {
  const original = getServerLogger();
  afterEach(() => setServerLogger(original));

  it("logs a failed checkpoint with the case id and the error, and does not throw", async () => {
    const { logger, warns } = captureLogger();
    setServerLogger(logger);
    let notified = false;
    const options = {
      importUndoStore: {
        depth: () => 10,
        byteBudget: () => 1024,
        mutate: async () => {
          throw new RangeError("Invalid string length");
        },
      },
      onImportUndo: () => {
        notified = true;
      },
    } as unknown as AppOptions;
    const appliers = createCaseAppliers({
      store: {} as CaseStore,
      options,
      runStateExclusive: (_id, fn) => fn(),
      nsrlDb: () => undefined,
    });

    await expect(
      appliers.pushImportCheckpoint("case-42", emptyState("case-42"), "thor (x.json)"),
    ).resolves.toBe(undefined);
    expect(notified).toBe(false);
    expect(warns).toHaveLength(1);
    expect(warns[0].ctx).toEqual({ caseId: "case-42" });
    expect(warns[0].msg).toContain("thor (x.json)");
    expect(warns[0].msg).toContain("Invalid string length");
  });

  it("logs a failed load of the post-import state and does not throw", async () => {
    const { logger, warns } = captureLogger();
    setServerLogger(logger);
    const options = {
      importUndoStore: { depth: () => 10, byteBudget: () => 1024, mutate: async () => undefined },
      stateStore: {
        load: async () => {
          throw new Error("disk gone");
        },
      },
    } as unknown as AppOptions;
    const appliers = createCaseAppliers({
      store: {} as CaseStore,
      options,
      runStateExclusive: (_id, fn) => fn(),
      nsrlDb: () => undefined,
    });
    await expect(appliers.pushImportCheckpoint("c9", emptyState("c9"), "x")).resolves.toBe(undefined);
    expect(warns).toHaveLength(1);
    expect(warns[0].msg).toContain("disk gone");
  });
});

// #1874 item 3: the checkpoint is a delta between the pre-import state and the post-import state.
describe("pushImportCheckpoint stores a delta", () => {
  const ev = (id: string) => ({
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description: id,
    severity: "High" as const,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  const before: InvestigationState = { ...emptyState("c1"), forensicTimeline: [ev("a")] };
  const after: InvestigationState = {
    ...emptyState("c1"),
    forensicTimeline: [ev("a"), ev("b")],
    lastSummary: "s",
  };

  function wire(stateStore?: { load: (id: string) => Promise<InvestigationState> }) {
    let stack: ImportUndoStack = emptyUndoStack();
    const options = {
      importUndoStore: {
        depth: () => 10,
        byteBudget: () => 10_000_000,
        mutate: async (_id: string, fn: (s: ImportUndoStack) => { stack: ImportUndoStack }) => {
          stack = fn(stack).stack;
        },
      },
      ...(stateStore ? { stateStore } : {}),
    } as unknown as AppOptions;
    const appliers = createCaseAppliers({
      store: {} as CaseStore,
      options,
      runStateExclusive: (_id, fn) => fn(),
      nsrlDb: () => undefined,
    });
    return { appliers, stack: () => stack };
  }

  it("diffs against the post-import state the caller passes", async () => {
    const { appliers, stack } = wire();
    await appliers.pushImportCheckpoint("c1", before, "imp", after);
    const top = stack().undo[0];
    expect(top.state).toBeUndefined();
    expect(top.counts).toEqual({ events: 1, iocs: 0, findings: 0 });
    expect(applyUndo(stack(), after)!.restore).toEqual(before);
  });

  it("loads the current state when the caller has none", async () => {
    const { appliers, stack } = wire({ load: async () => after });
    await appliers.pushImportCheckpoint("c1", before, "imp");
    expect(stack().undo[0].delta).toBeDefined();
    expect(applyUndo(stack(), after)!.restore).toEqual(before);
  });
});
