import { describe, it, expect } from "vitest";
import {
  caseLookalike,
  flagCaseLookalikeRow,
  lookalikeCandidateName,
  LOOKALIKE_ACCOUNT_MARKER,
} from "../../src/analysis/lookalikeCaseAccount.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1971: a new account or a group member named one edit away from an account the case already holds
// ("svc-backupl" next to "svc-backup") is how an attacker hides a backdoor in plain sight.

describe("caseLookalike", () => {
  it("flags a one-edit copy of a case account", () => {
    expect(caseLookalike("svc-backupl", ["svc-backup"])).toBe("svc-backup");
  });

  it("strips a domain prefix and a UPN suffix on both sides", () => {
    expect(caseLookalike("CORP\\svc-backupl", ["svc-backup@corp.example.com"])).toBe("svc-backup");
  });

  it("catches a homoglyph copy", () => {
    // Cyrillic "а" (U+0430) in place of the Latin "a".
    expect(caseLookalike("svc-bаckup", ["svc-backup"])).toBe("svc-backup");
  });

  it("does not flag numbered accounts", () => {
    expect(caseLookalike("user2", ["user1"])).toBeNull();
    expect(caseLookalike("svc-backup2", ["svc-backup"])).toBeNull();
  });

  it("does not flag an initial + surname pair", () => {
    expect(caseLookalike("bsmith", ["asmith"])).toBeNull();
  });

  it("does not flag the account's own name", () => {
    expect(caseLookalike("svc-backup", ["svc-backup"])).toBeNull();
    expect(caseLookalike("CORP\\svc-backup", ["SVC-BACKUP@corp.example.com"])).toBeNull();
  });

  it("does not flag a short name", () => {
    expect(caseLookalike("abcd", ["abce"])).toBeNull();
  });

  it("skips machine and noise accounts", () => {
    expect(caseLookalike("PC01$", ["PC02$"])).toBeNull();
    expect(caseLookalike("websrv", ["websrv$"])).toBeNull();
    expect(caseLookalike("SYSTEMS", ["SYSTEM"])).toBeNull();
  });

  it("does not flag a name two edits away", () => {
    expect(caseLookalike("svc-backupxy", ["svc-backup"])).toBeNull();
  });
});

function ev(description: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-08-26T13:50:08.000Z",
    description,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("lookalikeCandidateName", () => {
  it("reads the new account of a 4720 and the member of a group add", () => {
    expect(
      lookalikeCandidateName(
        ev("Windows Security User account created (EID 4720) - CORP\\svc-backupl, CORP\\admin1 @ H1"),
      ),
    ).toBe("CORP\\svc-backupl");
    expect(
      lookalikeCandidateName(
        ev(
          "Windows Security Member added to local security group (EID 4732) - Users, CORP\\admin1 - MemberName=CN=svc-backupl,CN=Users,DC=example,DC=com @ H1",
        ),
      ),
    ).toBe("svc-backupl");
  });

  it("skips a member named only by SID, and every other event", () => {
    expect(
      lookalikeCandidateName(
        ev("Windows Security Member added to local security group (EID 4732) - Users - MemberName=- @ H1"),
      ),
    ).toBe("");
    expect(
      lookalikeCandidateName(ev("Windows Security Successful logon (EID 4624) - CORP\\svc-backup")),
    ).toBe("");
  });
});

describe("flagCaseLookalikeRow", () => {
  it("raises to High with one note, and is idempotent", () => {
    const once = flagCaseLookalikeRow(ev("User account created (EID 4720)"), "svc-backupl", "svc-backup");
    expect(once.severity).toBe("High");
    expect(once.description).toContain(LOOKALIKE_ACCOUNT_MARKER);
    expect(once.description).toContain('"svc-backupl" is one edit from case account "svc-backup"');
    expect(flagCaseLookalikeRow(once, "svc-backupl", "svc-backup")).toBe(once);
  });
});
