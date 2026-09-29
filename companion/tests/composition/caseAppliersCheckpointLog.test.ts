import { describe, it, expect, afterEach } from "vitest";
import { createCaseAppliers } from "../../src/composition/caseAppliers.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import type { Logger, LogContext } from "../../src/logging/logger.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { CaseStore } from "../../src/storage/caseStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

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
});
