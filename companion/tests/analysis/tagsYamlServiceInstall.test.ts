import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// `win_service_install` read a bare '4697' / '7045' in the message, so a hash or PID holding those
// digits graded a process launch as a service install (persistence). The message side now needs the
// id behind its key (`EventID: 7045`, `EID 4697`).
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

function ruleIds(fields: { message?: string; description?: string }): string[] {
  const event = {
    id: "e1",
    ...fields,
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: [],
  } as unknown as ForensicEvent;
  return runTagger([event], RULES).perEvent[0]?.ruleIds ?? [];
}

const AVG_LAUNCH_MESSAGE = [
  "Process Create:",
  "UtcTime: 2017-03-20 11:13:39.990",
  "ProcessId: 1068",
  "Image: \\\\198.51.100.6\\share\\Installs\\AVG_Protection_Free_1606.exe",
  'CommandLine: "\\\\198.51.100.6\\share\\Installs\\AVG_Protection_Free_1606.exe"',
  "User: CORP\\alice",
  "Hashes: SHA1=89ABCDEF0123456789ABCDEF0123456789ABCDEF,MD5=FFEEDDCCBBAA99887766554433221100," +
    "SHA256=AAAAAAAAAAAAAAAA4697BBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD," +
    "IMPHASH=00FF11EE22DD33CC44BB55AA66997788",
].join("\n");

describe("win_service_install", () => {
  it("does not match a process launch whose SHA256 contains 4697", () => {
    expect(
      ruleIds({
        message: AVG_LAUNCH_MESSAGE,
        description:
          "Sysmon Process create (EID 1) - Image=\\\\198.51.100.6\\share\\Installs\\AVG_Protection_Free_1606.exe",
      }),
    ).not.toContain("win_service_install");
  });

  it("does not match a bare 7045 inside a PID or hash", () => {
    expect(ruleIds({ message: "ProcessId: 7045\nHashes: MD5=AB7045CD" })).not.toContain(
      "win_service_install",
    );
  });

  it("matches a service install named by its description id", () => {
    expect(
      ruleIds({ description: "Windows System Service installed (EID 7045) - ServiceName=Example" }),
    ).toContain("win_service_install");
  });

  it("matches a service install named by an EventID key in the message", () => {
    expect(ruleIds({ message: "EventID: 7045\nServiceName: Example" })).toContain("win_service_install");
    expect(ruleIds({ message: '{"event_id": 4697}' })).toContain("win_service_install");
  });

  it("matches the Windows service-installed text", () => {
    expect(ruleIds({ message: "A new service was installed in the system." })).toContain(
      "win_service_install",
    );
  });
});
