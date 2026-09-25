import { describe, expect, it } from "vitest";
import { parseEvalCli } from "./cli.js";

describe("parseEvalCli --runs (#1579)", () => {
  it("defaults to one run", () => {
    expect(parseEvalCli(["all"]).runs).toBe(1);
  });

  it("reads an integer run count", () => {
    expect(parseEvalCli(["all", "--real", "--runs", "3"]).runs).toBe(3);
  });

  it("does not take the run count as the mode positional", () => {
    const options = parseEvalCli(["--runs", "3", "synthesis"]);
    expect(options.mode).toBe("synthesis");
    expect(options.runs).toBe(3);
  });

  it("accepts the bounds 1 and 10", () => {
    expect(parseEvalCli(["--runs", "1"]).runs).toBe(1);
    expect(parseEvalCli(["--runs", "10"]).runs).toBe(10);
  });

  it.each([
    [["--runs"], /--runs requires/],
    [["--runs", "--real"], /--runs requires/],
    [["--runs", "2.5"], /--runs must be an integer/],
    [["--runs", "x"], /--runs must be an integer/],
    [["--runs", "3x"], /--runs must be an integer/],
    [["--runs", "0"], /--runs must be between 1 and 10/],
    [["--runs", "-1"], /--runs must be between 1 and 10/],
    [["--runs", "11"], /--runs must be between 1 and 10/],
    [["--runs", "2", "--runs", "3"], /--runs was given more than once/],
  ])("rejects %j", (argv, message) => {
    expect(() => parseEvalCli(argv)).toThrow(message);
  });

  it("keeps the other flags working", () => {
    const options = parseEvalCli([
      "all",
      "--real",
      "--runs",
      "3",
      "--output",
      "r.json",
      "--baseline",
      "b.json",
      "--require-baseline",
      "--attestation",
      "a.json",
    ]);
    expect(options).toMatchObject({
      mode: "all",
      real: true,
      runs: 3,
      outputPath: "r.json",
      baselinePath: "b.json",
      requireBaseline: true,
      attestationPath: "a.json",
    });
  });
});
