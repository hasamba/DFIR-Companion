import { describe, it, expect } from "vitest";
import { buildSharedHostLinks } from "../../src/analysis/sharedHostLinks.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// Hosts that share a binary or an account (#3085). These used to be chained into "lateral paths"
// in time order; they carry no direction, so they are now an unordered set of hosts. The
// installed-software and pseudo-principal filters came along unchanged from that rule.

const HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "",
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

function estateWide(path: string, extra: Partial<ForensicEvent> = {}) {
  const s = emptyState("c1");
  s.forensicTimeline.push(
    ev({ id: "e1", asset: "WS-01", sha256: HASH, path, timestamp: "2026-05-20T09:00:00Z", ...extra }),
    ev({ id: "e2", asset: "WS-02", sha256: HASH, path, timestamp: "2026-05-20T10:00:00Z" }),
    ev({ id: "e3", asset: "WS-03", sha256: HASH, path, timestamp: "2026-05-20T11:00:00Z" }),
  );
  return s;
}

describe("buildSharedHostLinks", () => {
  it("lists the hosts sharing a binary in first-sighting order, named by file", () => {
    const [link] = buildSharedHostLinks(estateWide("D:\\tools\\psexec.exe"));
    expect(link).toMatchObject({
      actor: "psexec.exe",
      actorKind: "binary",
      confidence: "high",
      hostIds: ["host:ws-01", "host:ws-02", "host:ws-03"],
      hosts: ["WS-01", "WS-02", "WS-03"],
      firstSeen: "2026-05-20T09:00:00Z",
      lastSeen: "2026-05-20T11:00:00Z",
      eventIds: ["e1", "e2", "e3"],
    });
  });

  it("falls back to a short hash when the binary's path was never recorded", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WS-01", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "WS-02", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
    );
    const [link] = buildSharedHostLinks(s);
    expect(HASH.startsWith(link.actor.replace(/…$/, ""))).toBe(true);
  });

  it("lists the hosts sharing an account, at medium confidence", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({
        id: "e1",
        asset: "HOST-A",
        description: "logon by CORP\\jdoe",
        timestamp: "2026-05-20T09:00:00Z",
      }),
      ev({
        id: "e2",
        asset: "HOST-B",
        description: "logon by CORP\\jdoe",
        timestamp: "2026-05-20T10:00:00Z",
      }),
    );
    expect(buildSharedHostLinks(s)).toEqual([
      expect.objectContaining({ actor: "CORP\\jdoe", actorKind: "account", confidence: "medium" }),
    ]);
  });

  it("needs two hosts", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "WS-01", sha256: HASH }));
    expect(buildSharedHostLinks(s)).toEqual([]);
  });

  it("leaves out vendor software installed across the estate, at any spread", () => {
    for (const path of [
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Windows\\System32\\svchost.exe",
      "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
      "C:/Users/user1/AppData/Local/Microsoft/OneDrive/OneDrive.exe",
      "C:/Users/user2/AppData/Roaming/Zoom/bin/Zoom.exe",
    ]) {
      expect(buildSharedHostLinks(estateWide(path)), path).toEqual([]);
    }
  });

  it("being flagged does NOT rescue vendor software (grading is not the discriminator)", () => {
    const withMitre = estateWide("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", {
      mitreTechniques: ["T1021"],
    });
    expect(buildSharedHostLinks(withMitre)).toEqual([]);
  });

  it("keeps a binary from a user-writable location, a High-graded LOLbin, and one with no path", () => {
    expect(
      buildSharedHostLinks(estateWide("C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost.exe")),
    ).toHaveLength(1);
    expect(
      buildSharedHostLinks(
        estateWide("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", { severity: "High" }),
      ),
    ).toHaveLength(1);
    const noPath = emptyState("c1");
    noPath.forensicTimeline.push(
      ev({ id: "e1", asset: "WS-01", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "WS-02", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
    );
    expect(buildSharedHostLinks(noPath)).toHaveLength(1);
  });

  it("does NOT treat Windows pseudo-principals as a shared account", () => {
    for (const acct of [
      "NT AUTHORITY\\LOCAL SERVICE",
      "NT AUTHORITY\\NETWORK SERVICE",
      "NT AUTHORITY\\ANONYMOUS LOGON",
      "NT SERVICE\\TrustedInstaller",
    ]) {
      const s = emptyState("c1");
      s.forensicTimeline.push(
        ev({ id: "e1", asset: "HOST-A", description: `logon by ${acct}`, timestamp: "2026-05-20T09:00:00Z" }),
        ev({ id: "e2", asset: "HOST-B", description: `logon by ${acct}`, timestamp: "2026-05-20T10:00:00Z" }),
      );
      expect(buildSharedHostLinks(s), acct).toEqual([]);
    }
  });

  it("respects the time window", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", sha256: HASH, timestamp: "2026-05-20T15:00:00Z" }),
    );
    expect(buildSharedHostLinks(s, { from: "2026-05-20T08:00:00Z", until: "2026-05-20T10:00:00Z" })).toEqual(
      [],
    );
  });
});
