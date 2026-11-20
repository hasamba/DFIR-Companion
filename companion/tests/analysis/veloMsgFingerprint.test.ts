import { describe, it, expect } from "vitest";
import { msgFingerprint } from "../../src/analysis/veloMsgFingerprint.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

// #2762 — the fingerprint kept only ASCII a-z, so a Russian or Chinese message hashed to "" (or to
// just its Latin words), no fingerprint reached the aggregation key, and two different localized
// detections under one rule title merged into one event.
describe("msgFingerprint — non-Latin letters (#2762)", () => {
  it("keeps Cyrillic words, so two Russian messages stay apart", () => {
    const a = msgFingerprint("Обнаружен mimikatz");
    const b = msgFingerprint("Обнаружен другой");
    expect(a).not.toBe("");
    expect(b).not.toBe("");
    expect(a).not.toBe(b);
    expect(a).not.toBe(msgFingerprint("mimikatz"));
  });

  it("keeps CJK text, so two Chinese messages stay apart", () => {
    const a = msgFingerprint("发现恶意软件");
    const b = msgFingerprint("检测到可疑进程");
    expect(a).not.toBe("");
    expect(b).not.toBe("");
    expect(a).not.toBe(b);
  });

  it("keeps accented letters inside a word", () => {
    expect(msgFingerprint("café")).not.toBe(msgFingerprint("cafe"));
  });

  it("keeps a word whole when it carries combining vowel signs", () => {
    // "ि" is a dependent vowel sign (a combining mark, not a letter). Treated as a separator it
    // would turn the one word "किताब" into "क ताब" — the same as the two words "कि ताब".
    expect(msgFingerprint("किताब")).not.toBe(msgFingerprint("कि ताब"));
  });

  it("treats composed and decomposed accents as the same message", () => {
    expect(msgFingerprint("café ouvert")).toBe(msgFingerprint("café ouvert"));
  });

  it("still drops volatile digits and GUIDs in a localized message", () => {
    expect(msgFingerprint("Обнаружен процесс 4242 {0f8fad5b-d9cb-469f-a165-70867728950e}")).toBe(
      msgFingerprint("Обнаружен процесс 77 {11111111-2222-4333-8444-555555555555}"),
    );
  });

  // Existing English aggregation keys must not move: these values were taken from the code before
  // the change.
  it.each([
    ["HackTool:Passview detected pid 123", "mt1n9n"],
    ["Mimikatz detected in process 4242 {0f8fad5b-d9cb-469f-a165-70867728950e}", "196tsv7"],
    ["Network connection from 10.0.0.5 to 192.168.1.9:445", "nnljxh"],
    ["!!! 123 ---", ""],
  ])("leaves the ASCII fingerprint of %j unchanged", (msg, expected) => {
    expect(msgFingerprint(msg)).toBe(expected);
  });
});

describe("parseVelociraptorJson — localized detections stay distinct (#2762)", () => {
  const row = (details: string): object => ({
    _Source: "Windows.Sigma.Base",
    Rule: { Title: "Suspicious Activity", Level: "high" },
    Computer: "WS-01",
    Timestamp: "2026-01-01T00:00:00Z",
    Details: details,
  });

  it("does NOT merge two rows whose only difference is Cyrillic text", () => {
    const parsed = parseVelociraptorJson(
      JSON.stringify([row("Обнаружен вредоносный файл"), row("Обнаружен другой процесс")]),
    );
    expect(parsed.events).toHaveLength(2);
  });
});
