import { describe, it, expect } from "vitest";
import { isSafeDropRelpath } from "../../src/storage/dropRelpath.js";

// #919. A drop-folder relpath has two producers: the recursive walk in composition/dropFolder.ts,
// which can only ever emit descendants of drop/, and `pendingRawInputs` in state/drop-status.json,
// which a whole-case archive import restores VERBATIM. The archive validator checks entry PATHS,
// not entry CONTENT, so that second producer is attacker-controlled. This is the rule both the
// schema and the destructive consumer (moveDropFile) apply to it.
describe("isSafeDropRelpath", () => {
  it.each([
    "evidence.json",
    "triage/prefetch.csv",
    // What path.relative() emits on win32 — the walk's own output must not be refused.
    "triage\\prefetch.csv",
    // A colon is an ordinary character in a Linux filename, and timestamps are common names.
    "2026-09-11T10:00:00.evtx",
    "a b (1).pcap",
    "hash.d41d8cd98f00b204e9800998ecf8427e",
  ])("accepts an ordinary descendant: %j", (relpath) => {
    expect(isSafeDropRelpath(relpath)).toBe(true);
  });

  it.each([
    ["empty", ""],
    ["bare dot-dot", ".."],
    ["leading dot-dot", "../x"],
    ["nested dot-dot", "a/../../x"],
    ["win32 dot-dot", "a\\..\\x"],
    ["posix absolute", "/etc/passwd"],
    ["win32 absolute", "C:\\x"],
    ["win32 drive-relative", "C:x"],
    ["UNC", "\\\\server\\share\\x"],
    ["empty segment", "a//b"],
    ["single-dot segment", "./a"],
    ["NUL byte", "a\u0000b"],
  ])("refuses %s: %j", (_label, relpath) => {
    expect(isSafeDropRelpath(relpath)).toBe(false);
  });
});
