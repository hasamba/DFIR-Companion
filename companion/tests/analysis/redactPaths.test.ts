import { describe, it, expect } from "vitest";
import { homedir, tmpdir } from "node:os";
import { redactPaths, redactedErrorMessage } from "../../src/analysis/redactPaths.js";

describe("redactPaths", () => {
  it("redacts the absolute path out of a Node fs error", () => {
    const msg = "ENOENT: no such file or directory, open '/home/alice/cases/INC-1/imports/0001_alerts.json'";
    const out = redactPaths(msg);
    expect(out).not.toContain("/home/alice");
    expect(out).not.toContain("INC-1");
    expect(out).toBe("ENOENT: no such file or directory, open '<path>'");
  });

  it("redacts a configured cases root that no top-level allowlist would catch", () => {
    const out = redactPaths("failed to write /evidence/store/INC-9/state.json", ["/evidence/store"]);
    expect(out).toBe("failed to write <path>");
  });

  it("redacts this machine's home and tmp directories", () => {
    expect(redactPaths(`spill at ${homedir()}/notes.txt`)).toBe("spill at <path>");
    expect(redactPaths(`temp at ${tmpdir()}/dfir-x/y.bin`)).toBe("temp at <path>");
  });

  it("redacts Windows drive and UNC paths", () => {
    expect(redactPaths("cannot read C:\\Users\\bob\\cases\\INC-1\\a.json")).toBe("cannot read <path>");
    expect(redactPaths("cannot read \\\\fileserver\\eviershare\\a.json")).toBe("cannot read <path>");
  });

  it("leaves an http(s) endpoint intact so provider errors stay actionable", () => {
    const msg = "401 from https://api.openai.com/v1/chat/completions — check the key";
    expect(redactPaths(msg)).toBe(msg);
  });

  it("redacts a file:// URL — that is a filesystem path wearing a scheme", () => {
    expect(redactPaths("cannot load file:///home/alice/cases/x.json")).not.toContain("alice");
  });

  it("redacts a path that sits next to a URL without eating the URL", () => {
    const out = redactPaths("POST https://api.example.com/v1/x failed writing /var/lib/dfir/a.json");
    expect(out).toContain("https://api.example.com/v1/x");
    expect(out).not.toContain("/var/lib/dfir");
  });

  it("leaves route-shaped absolutes alone — they are not filesystem paths", () => {
    // The whole point of the top-level allowlist: an error naming a route must stay readable.
    expect(redactPaths("expected /cases/:id/import")).toBe("expected /cases/:id/import");
    expect(redactPaths("unknown endpoint /diagnostics/sizes")).toBe("unknown endpoint /diagnostics/sizes");
  });

  it("leaves ordinary prose and fractions alone", () => {
    expect(redactPaths("kept 50/50 of the rows and/or dropped them")).toBe("kept 50/50 of the rows and/or dropped them");
    expect(redactPaths("bad JSON at row 3")).toBe("bad JSON at row 3");
  });

  it("does not choke on empty or non-Error throwables", () => {
    expect(redactPaths("")).toBe("");
    expect(redactedErrorMessage(new Error("/home/alice/x/y.json is bad"))).toBe("<path> is bad");
    expect(redactedErrorMessage("plain string throw")).toBe("plain string throw");
    expect(redactedErrorMessage(undefined)).toBe("undefined");
  });
});
