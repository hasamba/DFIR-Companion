// F4: the time of a pasted line. An impossible date never rolls over into a real one, and the
// first timestamp in the line wins whichever of the two supported forms it is written in.
import { describe, expect, it } from "vitest";
import { lineTimestamp } from "../../../src/analysis/ai/watson/writers/pasteLineEvents.js";

describe("lineTimestamp", () => {
  it("reads an ISO time, with or without a zone", () => {
    expect(lineTimestamp("logon 2026-02-28T10:00:00Z ok")).toBe("2026-02-28T10:00:00.000Z");
    expect(lineTimestamp("2026-02-28T12:00:00+02:00 logon")).toBe("2026-02-28T10:00:00.000Z");
    expect(lineTimestamp("2026-02-28T10:00:00.250 logon")).toBe("2026-02-28T10:00:00.250Z");
    expect(lineTimestamp("2026-02-28 10:00:00 logon")).toBe("2026-02-28T10:00:00.000Z");
  });

  it("returns no time for an impossible date or clock time instead of rolling it over", () => {
    expect(lineTimestamp("2026-02-30T10:00:00Z logon")).toBe("");
    expect(lineTimestamp("2026-13-01 10:00:00 logon")).toBe("");
    expect(lineTimestamp("2026-04-31T10:00:00+02:00 logon")).toBe("");
    expect(lineTimestamp("2026-02-28 24:30:00 logon")).toBe("");
    expect(lineTimestamp("2026-02-28T10:61:00Z logon")).toBe("");
    expect(lineTimestamp("2028-02-29T10:00:00Z leap day")).toBe("2028-02-29T10:00:00.000Z");
  });

  it("takes the first timestamp in the line, whichever form it is", () => {
    expect(lineTimestamp("2026-01-01 08:00:00 seen, uploaded 2026-03-03T09:00:00Z")).toBe(
      "2026-01-01T08:00:00.000Z",
    );
    expect(lineTimestamp("2026-03-03T09:00:00Z seen, logged 2026-01-01 08:00:00")).toBe(
      "2026-03-03T09:00:00.000Z",
    );
  });

  it("returns no time when the line has none", () => {
    expect(lineTimestamp("no time here")).toBe("");
  });
});
