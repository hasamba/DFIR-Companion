import { describe, it, expect } from "vitest";
import { benchChildEnv, classifyDropOutcome } from "../../scripts/bench-velo-bulk-import.js";
import { formatDropLogLines, type DropLogEntry } from "../../src/analysis/dropLog.js";
import { HOLD_REASON } from "../../src/composition/dropHuntHold.js";

// #2824 — the Velociraptor memory benchmarks must get their file imported, and say why when they do not.

const FILE = "Windows.Hayabusa.Notebook.json";
const AT = "2026-08-13T00:00:00.000Z";
const logOf = (...entries: DropLogEntry[]): string => formatDropLogLines(entries, AT).join("\n") + "\n";

describe("benchChildEnv", () => {
  it("turns both hunt artifact size limits off", () => {
    const env = benchChildEnv({}, { DFIR_PORT: "5000" });
    expect(env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB).toBe("0");
    expect(env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB).toBe("0");
  });

  it("wins over limits inherited from the shell", () => {
    const inherited = { DFIR_HUNT_ARTIFACT_HOST_MAX_MB: "50", DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB: "200" };
    const env = benchChildEnv(inherited, {});
    expect(env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB).toBe("0");
    expect(env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB).toBe("0");
    expect(inherited).toEqual({
      DFIR_HUNT_ARTIFACT_HOST_MAX_MB: "50",
      DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB: "200",
    });
  });

  it("keeps the inherited environment and lets the script's own keys win over it", () => {
    const env = benchChildEnv({ PATH: "/usr/bin", DFIR_PORT: "4773" }, { DFIR_PORT: "5000" });
    expect(env.PATH).toBe("/usr/bin");
    expect(env.DFIR_PORT).toBe("5000");
  });

  it("leaves the import memory guard as the caller set it", () => {
    expect(benchChildEnv({}, {})).not.toHaveProperty("DFIR_IMPORT_MEMORY_GUARD");
    expect(benchChildEnv({ DFIR_IMPORT_MEMORY_GUARD: "off" }, {}).DFIR_IMPORT_MEMORY_GUARD).toBe("off");
  });
});

describe("classifyDropOutcome", () => {
  it("is pending for an empty or missing log", () => {
    expect(classifyDropOutcome("", FILE)).toEqual({ outcome: "pending" });
  });

  it("reports a file held over the hunt artifact size limit, with the drop-log reason", () => {
    const reason = `held over the hunt artifact size limit — in _held/${FILE}`;
    expect(classifyDropOutcome(logOf({ status: "SKIPPED", relpath: FILE, reason }), FILE)).toEqual({
      outcome: "held",
      reason,
    });
  });

  it("reads the line the issue reported", () => {
    const line = `SKIPPED    ${FILE}  — held over the hunt artifact size limit — in _held/${FILE}`;
    expect(classifyDropOutcome(`${AT}  ${line}\n`, FILE).outcome).toBe("held");
  });

  it("reports a failed file, for example one the memory guard refused", () => {
    const reason =
      "not enough memory to import this file. To import anyway, set DFIR_IMPORT_MEMORY_GUARD=off.";
    expect(classifyDropOutcome(logOf({ status: "FAILED", relpath: FILE, reason }), FILE)).toEqual({
      outcome: "failed",
      reason,
    });
  });

  it("reports a file skipped for another reason", () => {
    const reason = "a link, not a file";
    expect(classifyDropOutcome(logOf({ status: "SKIPPED", relpath: FILE, reason }), FILE)).toEqual({
      outcome: "skipped",
      reason,
    });
  });

  it("stays pending for an imported file, a waiting file and another file's lines", () => {
    const log = logOf(
      { status: "IMPORTED", relpath: FILE },
      { status: "PENDING", relpath: FILE, reason: "awaiting tool run for .evtx (drop banner: Run)" },
      { status: "FAILED", relpath: "other.json", reason: `could not read ${FILE}` },
      { status: "SKIPPED", relpath: `sub/${FILE}`, reason: `held over the hunt artifact size limit` },
    );
    expect(classifyDropOutcome(log, FILE)).toEqual({ outcome: "pending" });
  });

  it("matches a zip's members, and names the member in the reason", () => {
    const member = "WKS-000-C.0000000000001000/results/Windows.Detection.Evtx.json";
    const held = logOf({ status: "SKIPPED", relpath: `hunt.zip!${member}`, reason: `${HOLD_REASON} — in x` });
    expect(classifyDropOutcome(held, "hunt.zip")).toEqual({
      outcome: "held",
      reason: `${member}: ${HOLD_REASON} — in x`,
    });
  });

  it("puts a held or failed member ahead of the zip's routine 'not read' line", () => {
    const routine: DropLogEntry = {
      status: "SKIPPED",
      relpath: "hunt.zip",
      reason: "Velociraptor hunt export: 3 member(s) not read — metadata",
    };
    expect(classifyDropOutcome(logOf(routine), "hunt.zip").outcome).toBe("skipped");
    const failed: DropLogEntry = { status: "FAILED", relpath: "hunt.zip!a/results/b.json", reason: "bad" };
    expect(classifyDropOutcome(logOf(routine, failed), "hunt.zip")).toEqual({
      outcome: "failed",
      reason: "a/results/b.json: bad",
    });
  });

  it("ignores a last line that is still being written", () => {
    const full = logOf({ status: "FAILED", relpath: FILE, reason: "bad" });
    expect(classifyDropOutcome(full.slice(0, full.indexOf(FILE) + 5), FILE)).toEqual({ outcome: "pending" });
  });
});
