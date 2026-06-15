import { describe, it, expect } from "vitest";
import { matrixToRows } from "../src/adapters/domTable.js";
import { buildArtifactFilename } from "../src/adapters/artifactName.js";

describe("matrixToRows", () => {
  it("maps headers onto cells, trimming whitespace", () => {
    expect(matrixToRows(["Host", "User"], [[" h1 ", "alice"], ["h2", " bob "]])).toEqual([
      { Host: "h1", User: "alice" },
      { Host: "h2", User: "bob" },
    ]);
  });

  it("synthesizes positional names for missing headers", () => {
    expect(matrixToRows([], [["a", "b"]])).toEqual([{ col1: "a", col2: "b" }]);
    expect(matrixToRows(["Only"], [["a", "b"]])).toEqual([{ Only: "a", col2: "b" }]);
  });

  it("de-duplicates repeated header names", () => {
    expect(matrixToRows(["X", "X"], [["1", "2"]])).toEqual([{ X: "1", X_2: "2" }]);
  });

  it("tolerates ragged rows (missing cells → empty string)", () => {
    expect(matrixToRows(["A", "B", "C"], [["1"]])).toEqual([{ A: "1", B: "", C: "" }]);
  });

  it("returns an empty array for no body rows", () => {
    expect(matrixToRows(["A"], [])).toEqual([]);
  });
});

describe("buildArtifactFilename", () => {
  it("embeds the adapter id and a filename-safe timestamp", () => {
    expect(buildArtifactFilename("splunk", new Date("2026-06-14T10:30:00.000Z"))).toBe("splunk-2026-06-14T10-30-00.json");
  });

  it("sanitizes a messy adapter id and falls back when blank", () => {
    expect(buildArtifactFilename("a/b c", new Date("2026-01-01T00:00:00.000Z"))).toBe("a_b_c-2026-01-01T00-00-00.json");
    expect(buildArtifactFilename("", new Date("2026-01-01T00:00:00.000Z"))).toBe("artifact-2026-01-01T00-00-00.json");
  });
});
