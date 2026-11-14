import { describe, expect, it } from "vitest";
import {
  ALREADY_RAN,
  HOST_NOT_IN_FLEET,
  STRING_REWRITTEN,
} from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import {
  REASON_RULES,
  classifyReason,
  plainRisk,
  ruleFor,
  splitReasons,
} from "../../../../src/analysis/ai/watson/velo/vqlRiskClass.js";
import { VQL_TOO_LONG } from "../../../../src/analysis/vqlInput.js";
import { FIXED_REASONS, SAMPLES, reasonsOf } from "./reasonSamples.js";

// Task 9 (user request 2026-11-14): risky Watson VQL can be approved by the analyst. Every reason the
// launch check can produce is classified HARD (refused, no approval) or RISKY (approvable); a reason
// no rule names is HARD. This file enumerates one VQL per reason shape and asserts its class.

describe("Watson launch reason classes (Task 9)", () => {
  it.each(SAMPLES)("%s → %s is %s", (vql, fragment, cls) => {
    const reasons = reasonsOf(vql);
    const hit = reasons.find((r) => r.includes(fragment));
    expect(hit, `no reason containing "${fragment}" in ${JSON.stringify(reasons)}`).toBeDefined();
    expect(ruleFor(hit!), `no rule names "${hit}"`).toBeDefined();
    expect(classifyReason(hit!)).toBe(cls);
  });

  it("every reason every sample produces is named by a rule (none falls to the default)", () => {
    const all = SAMPLES.flatMap(([vql]) => reasonsOf(vql));
    expect(all.length).toBeGreaterThan(SAMPLES.length - 1);
    expect(all.filter((r) => !ruleFor(r))).toEqual([]);
  });

  it.each([
    ["the VQL is empty", "hard"],
    ["unknown launch mode", "hard"],
    [VQL_TOO_LONG, "hard"],
    ["no runnable VQL", "hard"],
    [ALREADY_RAN, "hard"],
    [STRING_REWRITTEN, "hard"],
    [HOST_NOT_IN_FLEET, "hard"],
    ["host name matches more than one client in the case's Velociraptor fleet", "hard"],
    ["a fleet hunt does not take a host", "hard"],
    ["''' (a triple-quoted string) is not allowed", "hard"],
    ["a carriage return in the VQL", "hard"],
  ] as const)("the fixed reason %s is %s", (reason, cls) => {
    expect(ruleFor(reason)).toBeDefined();
    expect(classifyReason(reason)).toBe(cls);
  });

  it("every rule is matched by some produced or fixed reason (no dead or reworded rule)", () => {
    const fixed = FIXED_REASONS;
    const all = [...fixed, ...SAMPLES.flatMap(([vql]) => reasonsOf(vql))];
    const dead = REASON_RULES.filter((r) => !all.some((x) => r.test.test(x))).map((r) => String(r.test));
    expect(dead).toEqual([]);
  });

  it("no plain reason shown on an approvable card says refused or must", () => {
    const risky = SAMPLES.flatMap(([vql]) => reasonsOf(vql)).filter((r) => classifyReason(r) === "risky");
    expect(risky.map(plainRisk).filter((p) => /\brefused\b|\bmust\b|\bneeds\b/.test(p))).toEqual([]);
  });

  it("an unclassified reason is HARD (fail closed)", () => {
    expect(ruleFor("something nobody wrote a rule for")).toBeUndefined();
    expect(classifyReason("something nobody wrote a rule for")).toBe("hard");
  });

  it("a risky-looking reason with HARD text appended does not become risky", () => {
    expect(classifyReason("the VQL calls execve, which is not on Watson's read-only list; comments")).toBe(
      "hard",
    );
  });

  it("splitReasons: any HARD reason makes the set HARD", () => {
    const s = splitReasons([
      "the VQL calls execve, which is not on Watson's read-only list",
      "comments are not allowed",
    ]);
    expect(s.hard).toEqual(["comments are not allowed"]);
    expect(s.risky).toHaveLength(1);
  });

  it("every rule declares its class", () => {
    for (const r of REASON_RULES) expect(["hard", "risky"]).toContain(r.cls);
  });

  it("maps common calls to plain English, others to the reviewed-list fallback", () => {
    expect(plainRisk("the VQL calls execve, which is not on Watson's read-only list")).toBe(
      "runs a program on the endpoint (execve)",
    );
    expect(plainRisk("the VQL calls http_client, which is not on Watson's read-only list")).toBe(
      "sends data over the network (http_client)",
    );
    expect(plainRisk("the VQL calls frobnicate, which is not on Watson's read-only list")).toBe(
      "uses frobnicate, which is not on the reviewed safe list",
    );
    expect(plainRisk("the VQL calls artifact Windows.Evil, which is not on Watson's read-only list")).toBe(
      "uses artifact Windows.Evil, which is not on the reviewed safe list",
    );
    expect(plainRisk("a string that looks like a network path")).toBe(
      "a string that looks like a network path",
    );
  });
});
