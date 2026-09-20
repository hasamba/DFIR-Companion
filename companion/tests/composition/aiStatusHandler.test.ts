import { describe, it, expect, vi, beforeEach } from "vitest";
import { createAiStatusHandler } from "../../src/composition/aiStatusHandler.js";
import { redactAiStatusEvent } from "../../src/composition/aiStatusRedact.js";
import { createImportProgressThrottle } from "../../src/logging/importLog.js";
import type { AiStatusEvent } from "../../src/composition/appOptions.js";
import type { Logger } from "../../src/logging/logger.js";

// #1438 — the one seam every import's progress crosses. The handler must keep broadcasting the
// redacted event (the #1029 contract) and, on top, log ONLY the "<kind> import — done/total"
// progress shape, throttled per case, with the caseId so the line reaches the case log.

const ROOT = "/srv/dfir/cases";
const AT = "2026-09-20T00:00:00.000Z";

let logger: Logger;
let broadcast: ReturnType<typeof vi.fn>;
let clock: number;
let handler: (caseId: string, event: AiStatusEvent) => void;

beforeEach(() => {
  clock = 0;
  logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    getLevel: () => "info",
    setLevel: () => {},
    close: async () => {},
  };
  broadcast = vi.fn();
  handler = createAiStatusHandler({
    broadcast,
    logger,
    throttle: createImportProgressThrottle({ intervalMs: 10_000, now: () => clock }),
    redact: (e) => redactAiStatusEvent(e, [ROOT]),
  });
});

const extracting = (detail: string): AiStatusEvent => ({
  status: "analyzing",
  phase: "extracting",
  at: AT,
  detail,
});

describe("createAiStatusHandler", () => {
  it("broadcasts an import progress event and logs it with the caseId", () => {
    handler("c1", extracting("THOR import — 5000/12000"));
    expect(broadcast).toHaveBeenCalledWith("c1", extracting("THOR import — 5000/12000"));
    expect(logger.info).toHaveBeenCalledTimes(1);
    expect(logger.info).toHaveBeenCalledWith("[import] c1: THOR import — 5000/12000", { caseId: "c1" });
  });

  it("broadcasts but never logs a status that is not import progress", () => {
    const others = [
      extracting("enriching IOC 3/50"),
      extracting("importing (velociraptor) — min severity Low"),
      extracting("3 screenshot(s)"),
      extracting('importing email "Re: x"'),
      { status: "analyzing", phase: "synthesizing", at: AT, detail: "window 4" } as AiStatusEvent,
      { status: "analyzing", phase: "extracting", at: AT } as AiStatusEvent,
    ];
    for (const e of others) handler("c1", e);
    expect(broadcast).toHaveBeenCalledTimes(others.length);
    for (const [i, e] of others.entries()) expect(broadcast).toHaveBeenNthCalledWith(i + 1, "c1", e);
    expect(logger.info).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.debug).not.toHaveBeenCalled();
  });

  it("throttles a second progress line for the same import within the interval", () => {
    handler("c1", extracting("THOR import — 1/12000"));
    clock = 3000;
    handler("c1", extracting("THOR import — 5000/12000"));
    expect(broadcast).toHaveBeenCalledTimes(2);
    expect(logger.info).toHaveBeenCalledTimes(1);
    clock = 10_000;
    handler("c1", extracting("THOR import — 9000/12000"));
    expect(logger.info).toHaveBeenCalledTimes(2);
    expect(logger.info).toHaveBeenLastCalledWith("[import] c1: THOR import — 9000/12000", { caseId: "c1" });
  });

  it("an idle status clears the case so the next import logs at once", () => {
    handler("c1", extracting("THOR import — 1/10"));
    clock = 1000;
    handler("c1", { status: "idle", at: AT });
    expect(broadcast).toHaveBeenLastCalledWith("c1", { status: "idle", at: AT });
    clock = 1001;
    handler("c1", extracting("THOR import — 1/10"));
    expect(logger.info).toHaveBeenCalledTimes(2);
  });

  it("an error status clears the case too, and its detail is broadcast redacted", () => {
    handler("c1", extracting("KAPE import — 1/3"));
    handler("c1", { status: "error", at: AT, detail: `EACCES: permission denied, open '${ROOT}/c1/x'` });
    expect(broadcast).toHaveBeenLastCalledWith("c1", {
      status: "error",
      at: AT,
      detail: "EACCES: permission denied, open '<path>'",
    });
    handler("c1", extracting("KAPE import — 1/3"));
    expect(logger.info).toHaveBeenCalledTimes(2);
  });

  it("logs the redacted detail, never the raw one, when it names a path under the cases root", () => {
    handler("c1", extracting(`${ROOT}/c1/imports/0003_x.json import — 1/2`));
    expect(logger.info).toHaveBeenCalledWith("[import] c1: <path> import — 1/2", { caseId: "c1" });
    const logged = String((logger.info as ReturnType<typeof vi.fn>).mock.calls[0][0]);
    expect(logged).not.toContain(ROOT);
    expect(broadcast).toHaveBeenCalledWith("c1", extracting("<path> import — 1/2"));
  });

  it("keeps cases independent", () => {
    handler("c1", extracting("THOR import — 1/10"));
    clock = 100;
    handler("c2", extracting("THOR import — 1/10"));
    expect(logger.info).toHaveBeenNthCalledWith(1, "[import] c1: THOR import — 1/10", { caseId: "c1" });
    expect(logger.info).toHaveBeenNthCalledWith(2, "[import] c2: THOR import — 1/10", { caseId: "c2" });
  });

  it("resolves the logger lazily when given a getter", () => {
    const late: Logger = { ...logger, info: vi.fn() };
    const h = createAiStatusHandler({
      broadcast,
      logger: () => late,
      throttle: createImportProgressThrottle({ now: () => 0 }),
      redact: (e) => e,
    });
    h("c1", extracting("csv import — 1/1"));
    expect(late.info).toHaveBeenCalledWith("[import] c1: csv import — 1/1", { caseId: "c1" });
    expect(logger.info).not.toHaveBeenCalled();
  });
});
