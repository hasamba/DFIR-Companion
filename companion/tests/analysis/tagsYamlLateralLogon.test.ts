import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// `win_remote_logon` used to add `lateral-movement` and T1021 to every type 3 / type 10 logon, so a
// null session or a machine-account logon read as lateral movement. It now only says `remote-logon`;
// `win_lateral_logon` adds the lateral tag for RDP and for a named account that shows a source.
// The descriptions below are the shapes the Windows mapper renders for a real case.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

const HEAD = "Windows Security Successful logon (EID 4624) - ";

function tagsFor(tail: string): { tags: string[]; ruleIds: string[] } {
  const event = {
    id: "e1",
    description: `${HEAD}${tail}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  return { tags: proposal?.tags ?? [], ruleIds: proposal?.ruleIds ?? [] };
}

describe("remote logon vs lateral movement", () => {
  it("tags an anonymous network logon remote-logon only", () => {
    const r = tagsFor(
      "NT AUTHORITY\\ANONYMOUS LOGON - LogonType=3 - IpAddress=192.0.2.11 - WorkstationName=HOST-A @ H1 [Network from 192.0.2.11]",
    );
    expect(r.tags).toContain("remote-logon");
    expect(r.tags).not.toContain("lateral-movement");
  });

  it("tags a machine-account network logon remote-logon only", () => {
    const r = tagsFor("CORP\\HOST-A$ - LogonType=3 - IpAddress=192.0.2.11 @ H1 [Network from 192.0.2.11]");
    expect(r.tags).toContain("remote-logon");
    expect(r.tags).not.toContain("lateral-movement");
  });

  it("does not call a named-account logon with no source lateral movement", () => {
    const r = tagsFor("CORP\\bob - LogonType=3 @ H1 [Network]");
    expect(r.tags).toContain("remote-logon");
    expect(r.tags).not.toContain("lateral-movement");
  });

  it("does not call a loopback logon lateral movement", () => {
    const r = tagsFor("CORP\\alice - LogonType=3 - IpAddress=::1 @ H1 [Network]");
    expect(r.tags).not.toContain("lateral-movement");
  });

  it("tags a named-account network logon from another host as lateral movement", () => {
    const r = tagsFor(
      "CORP\\Administrator - LogonType=3 - IpAddress=192.0.2.11 @ H1 [Network from 192.0.2.11]",
    );
    expect(r.tags).toEqual(expect.arrayContaining(["remote-logon", "lateral-movement"]));
  });

  it("tags a named-account logon that shows only a workstation name as lateral movement", () => {
    const r = tagsFor("CORP\\Administrator - LogonType=3 - WorkstationName=DESKTOP-VOA929U @ H1 [Network]");
    expect(r.tags).toContain("lateral-movement");
  });

  it("tags RDP from another host as lateral movement, though a machine account is listed", () => {
    const r = tagsFor(
      "CORP\\administrator, CORP\\HOST-A$ - LogonType=10 - IpAddress=192.0.2.26 - WorkstationName=HOST-A @ H1 [RemoteInteractive/RDP from 192.0.2.26]",
    );
    expect(r.tags).toEqual(expect.arrayContaining(["remote-logon", "lateral-movement"]));
  });
});
