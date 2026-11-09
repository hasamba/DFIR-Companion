// #2399: every action targets the LOADED case, never a case merely picked in the picker.
//
// ~200 places read the case id from #caseId. The picker used to write it on every pick, before
// Connect, so with case A on screen Import, Re-synthesize, Close, Undo import, Promote and the
// Notebook all acted on the newly picked case B. #caseId now changes only when a case load starts
// (and is cleared when one is cancelled); the picker holds its choice separately. The picker's own
// half is behaviour-tested in dashboardCasePicker.test.ts — this pins the wiring on the case paths.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Normalised: a Windows checkout has CRLF line endings, and the slicing below looks for "\n  }\n".
const read = (f: string) =>
  readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8").replace(/\r\n/g, "\n");
const fnBody = (src: string, name: string) => {
  const start = src.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`no function ${name}`);
  return src.slice(start, src.indexOf("\n  }\n", start));
};

const CONNECT = read("dashboard-case-connect.js");
const PICKER = read("dashboard-case-picker.js");

describe("the loaded case, not the picked one, is what #caseId names (#2399)", () => {
  it("the picker never writes #caseId on a pick", () => {
    expect(fnBody(PICKER, "pushPickerToPick")).not.toMatch(/caseId/);
    expect(PICKER).not.toMatch(/pushPickerToCaseId/);
  });

  it("Connect loads the picker's choice", () => {
    expect(fnBody(CONNECT, "connect")).toMatch(/pickedCaseId\(\)/);
  });

  it("the case load commits the case, beside activeCaseId", () => {
    const body = fnBody(CONNECT, "proceedConnect");
    expect(body).toMatch(
      /activeCaseId = caseId;\s*\n(?:\s*\/\/.*\n)*\s*if \(typeof commitLoadedCase === "function"\) commitLoadedCase\(caseId\)/,
    );
  });

  it("a cancelled load clears the target before activeCaseId is dropped", () => {
    const body = fnBody(CONNECT, "abandonCaseLoad");
    const clear = body.indexOf("clearLoadedCase(cancelledCaseId)");
    expect(clear).toBeGreaterThan(-1);
    expect(clear).toBeLessThan(body.indexOf("activeCaseId = null"));
  });

  it("a deep link, a remembered case and the cross-case switch are picks, not loads", () => {
    const restore = fnBody(CONNECT, "restoreCaseFromUrl");
    expect(restore).toMatch(/setCasePick\(id\)/);
    expect(restore).toMatch(/choose\(remembered\)/);
    expect(restore).not.toMatch(/el\.value = remembered/);
    expect(fnBody(CONNECT, "initCaseConnect")).toMatch(/setCasePick\(foreignCaptureCase\)/);
  });

  it("a new, demo or imported case is picked and then connected, never written into #caseId first", () => {
    for (const f of ["dashboard-new-case.js", "dashboard-import-case.js"]) {
      const src = read(f);
      const picks = src.match(/setCasePick\(/g) ?? [];
      expect(picks.length, f).toBe(2);
      // the only remaining direct writes are the fallbacks for a page without the picker module
      const writes = src.match(/getElementById\("caseId"\)\.value = /g) ?? [];
      const fallbacks = src.match(/else document\.getElementById\("caseId"\)\.value = /g) ?? [];
      expect(writes.length, f).toBe(fallbacks.length);
    }
  });
});
