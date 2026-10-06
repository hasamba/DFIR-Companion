// #1969 — the server log for a cut-short collect names the cheap fix (a time scope) as well as the
// row cap, and says which rows a windowed re-read kept.
import { describe, expect, it } from "vitest";
import { collectWarnings } from "../../src/analysis/veloHuntStore.js";

const cut = { name: "Windows.Forensics.Usn", kept: 100000, total: 100001 };

describe("collectWarnings — cut short", () => {
  it("an unscoped hunt is told to collect again with a time scope", () => {
    const [line] = collectWarnings("H.1", [], [cut], [], false);
    expect(line).toContain("DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS");
    expect(line).toContain("collect again with a time scope set to the incident window");
  });

  it("a hunt that already ran with a time scope is not told to add one", () => {
    const [line] = collectWarnings("H.1", [], [cut], [], true);
    expect(line).not.toContain("with a time scope");
  });

  it("a windowed re-read says it kept rows inside the incident window", () => {
    const [line] = collectWarnings(
      "H.1",
      [],
      [{ ...cut, windowStart: "2026-09-20T00:00:00.000Z", windowFull: false }],
    );
    expect(line).toContain("inside the incident window 2026-09-20T00:00:00.000Z to now");
  });
});
