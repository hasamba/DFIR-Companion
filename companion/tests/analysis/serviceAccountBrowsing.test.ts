import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  classifyAccount,
  accountName,
  readBrowsing,
  corroborate,
  gradeBrowsing,
  markServiceAccountBrowsing,
  attributionNote,
  SERVICE_SIDS,
} from "../../src/analysis/serviceAccountBrowsing.js";
import { shellbagAccount } from "../../src/analysis/kapeImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const ev = (over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: `e${++seq}`,
  timestamp: "2026-01-01T10:00:00Z",
  description: "",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "FS-01",
  ...over,
});

const bag = (account: string, path = "C:\\Finance\\Payroll") =>
  ev({
    description: `Shellbag: ${path} [user: ${account}]`,
    sources: ["Shellbags"],
    path,
  });

// The shellbag importer had been dropping the account entirely (#908 item 10).
describe("shellbagAccount — who browsed survives the import", () => {
  it("reads a user column when the collection added one", () => {
    expect(shellbagAccount({ User: "svc_backup" })).toBe("svc_backup");
    expect(shellbagAccount({ SID: "S-1-5-21-1-2-3-1105" })).toBe("S-1-5-21-1-2-3-1105");
  });

  it("reads the account out of SBECmd's own output filename", () => {
    expect(shellbagAccount({ SourceFile: "20260102120000_UsrClass_alice.csv" })).toBe("alice");
    expect(shellbagAccount({ SourceFile: "20260102120000_NTUSER_bob.csv" })).toBe("bob");
  });

  it("reads it from a profile path", () => {
    expect(shellbagAccount({ SourceFile: "C:\\Triage\\C\\Users\\carol\\AppData\\UsrClass.dat" })).toBe(
      "carol",
    );
  });

  it("returns nothing rather than guessing", () => {
    expect(shellbagAccount({ AbsolutePath: "C:\\Finance" })).toBe("");
  });
});

describe("classifyAccount — explicitly noninteractive, never guessed", () => {
  it("recognises the built-in service identities", () => {
    for (const sid of SERVICE_SIDS) expect(classifyAccount(sid).noninteractive).toBe(true);
    for (const name of ["SYSTEM", "NT AUTHORITY\\SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]) {
      expect(classifyAccount(name).noninteractive).toBe(true);
    }
  });

  it("recognises a machine or group-managed service account", () => {
    const c = classifyAccount("CORP\\FS-01$");
    expect(c.noninteractive).toBe(true);
    expect(c.reason).toBe("machine-account");
  });

  it("accepts an analyst's identification", () => {
    const c = classifyAccount("backupd", { noninteractiveAccounts: ["BACKUPD"] });
    expect(c.noninteractive).toBe(true);
    expect(c.reason).toBe("analyst");
  });

  // A finding that accuses a named human of unauthorised browsing is not a small mistake.
  it("does not guess from a name by default", () => {
    expect(classifyAccount("svc_backup").noninteractive).toBe(false);
    expect(classifyAccount("svcHelpdesk").noninteractive).toBe(false);
    expect(classifyAccount("CORP\\alice").noninteractive).toBe(false);
  });

  it("uses a naming convention only when the caller opts in, and says the basis was the name", () => {
    const c = classifyAccount("svc_backup", { useNamingConvention: true });
    expect(c.noninteractive).toBe(true);
    expect(c.reason).toBe("naming-convention");
    expect(c.basis).toContain("not a property of the account");
  });

  it("lets an analyst override in the other direction", () => {
    const c = classifyAccount("svc_backup", {
      useNamingConvention: true,
      interactiveAccounts: ["svc_backup"],
    });
    expect(c.noninteractive).toBe(false);
    expect(c.basis).toContain("confirmed this account is interactive");
  });

  it("strips a domain prefix", () => {
    expect(accountName("CORP\\alice")).toBe("alice");
    expect(accountName("alice")).toBe("alice");
  });
});

describe("readBrowsing", () => {
  it("reads a shellbag and its account", () => {
    const r = readBrowsing(bag("CORP\\FS-01$"));
    expect(r?.kind).toBe("shellbag");
    expect(r?.account).toBe("CORP\\FS-01$");
    expect(r?.target).toBe("C:\\Finance\\Payroll");
  });

  // Allowing spaces in the share segment let the match run past the path and swallow the prose
  // after it: "\\\\FS-01\\Finance by CORP\\svc" came back as a share named "Finance by CORP".
  it("reads a share access", () => {
    const r = readBrowsing(
      ev({ description: "SMB share access to \\\\FS-01\\Finance by CORP\\FS-01$ [user: CORP\\FS-01$]" }),
    );
    expect(r?.kind).toBe("share");
    expect(r?.target).toBe("\\\\FS-01\\Finance");
  });

  it("marks a shellbag the collection could not attribute", () => {
    const r = readBrowsing(
      ev({
        description:
          "Shellbag: C:\\Finance [user: not recorded by this collection — a shellbag is per-user, so the account is unknown here, not absent]",
        sources: ["Shellbags"],
      }),
    );
    expect(r?.attributionMissing).toBe(true);
    expect(r?.account).toBe("");
  });

  it("ignores an unrelated event", () => {
    expect(readBrowsing(ev({ description: "Process created: notepad.exe" }))).toBeNull();
  });

  it("ignores an event whose time cannot be read", () => {
    expect(readBrowsing({ ...bag("SYSTEM"), timestamp: "not a date" })).toBeNull();
  });
});

describe("corroborate", () => {
  const record = readBrowsing(bag("svc_backup"))!;

  it("finds an interactive logon by the same account nearby", () => {
    const c = corroborate(record, [
      ev({ description: "Logon type 10 for svc_backup from 10.0.0.9", timestamp: "2026-01-01T09:30:00Z" }),
    ]);
    expect(c.logonId).not.toBeNull();
  });

  it("finds archiving by the same account nearby", () => {
    const c = corroborate(record, [
      ev({ description: "svc_backup ran 7z a out.7z C:\\Finance", timestamp: "2026-01-01T10:10:00Z" }),
    ]);
    expect(c.collectionId).not.toBeNull();
  });

  it("ignores activity by a different account", () => {
    const c = corroborate(record, [
      ev({ description: "Logon type 10 for alice", timestamp: "2026-01-01T10:00:00Z" }),
    ]);
    expect(c.logonId).toBeNull();
  });

  it("ignores activity far outside the window", () => {
    const c = corroborate(record, [
      ev({ description: "Logon type 10 for svc_backup", timestamp: "2026-01-05T10:00:00Z" }),
    ]);
    expect(c.logonId).toBeNull();
  });
});

describe("gradeBrowsing", () => {
  const record = readBrowsing(bag("CORP\\FS-01$"))!;
  const machine = classifyAccount("CORP\\FS-01$");

  it("says nothing about an account that is not noninteractive", () => {
    expect(gradeBrowsing(record, classifyAccount("CORP\\alice"))).toBeNull();
  });

  it("reports browsing by a machine account at Medium", () => {
    const v = gradeBrowsing(record, machine);
    expect(v?.severity).toBe("Medium");
    expect(v?.reason).toContain("neither can log on interactively");
  });

  it("raises when an interactive logon by the same account sits nearby", () => {
    expect(gradeBrowsing(record, machine, { logonId: "e9", collectionId: null })?.severity).toBe("High");
  });

  // Browsing and copying are different findings, and the artifact only supports the first.
  it("always says a shellbag does not establish that anything was copied", () => {
    const v = gradeBrowsing(record, machine, { logonId: null, collectionId: "e9" });
    expect(v?.reason).toContain("does NOT record that any file was read, copied or sent anywhere");
    expect(v?.reason).toContain("neither alone establishes it");
  });

  it("always states what the timestamp does and does not bound", () => {
    expect(gradeBrowsing(record, machine)?.reason).toContain("one timestamp can stand for months");
  });

  // A hint about a label is not a fact about the account.
  it("keeps a naming-convention match below Medium on its own", () => {
    const r = readBrowsing(bag("svc_backup"))!;
    const v = gradeBrowsing(r, classifyAccount("svc_backup", { useNamingConvention: true }));
    expect(v?.severity).toBe("Low");
  });
});

describe("markServiceAccountBrowsing — the timeline pass", () => {
  it("raises and explains browsing by a machine account", () => {
    const [out] = markServiceAccountBrowsing([bag("CORP\\FS-01$")]);
    expect(out.severity).toBe("Medium");
    expect(out.description).toContain("[noninteractive account browsing:");
    expect(out.mitreTechniques).toContain("T1078.003");
  });

  it("leaves a person's browsing alone", () => {
    const events = [bag("CORP\\alice")];
    expect(markServiceAccountBrowsing(events)).toBe(events);
  });

  it("leaves an unattributable shellbag alone rather than guessing", () => {
    const events = [
      ev({
        description: "Shellbag: C:\\Finance [user: not recorded by this collection — a shellbag is per-user]",
        sources: ["Shellbags"],
      }),
    ];
    expect(markServiceAccountBrowsing(events)).toBe(events);
  });

  it("is idempotent", () => {
    const once = markServiceAccountBrowsing([bag("SYSTEM")]);
    expect(markServiceAccountBrowsing(once)[0].description).toBe(once[0].description);
  });

  it("never lowers a severity the event already had", () => {
    const raised = [{ ...bag("SYSTEM"), severity: "Critical" as const }];
    expect(markServiceAccountBrowsing(raised)[0].severity).toBe("Critical");
  });

  it("returns the input untouched when nothing matches", () => {
    const events = [ev({ description: "Process created: notepad.exe" })];
    expect(markServiceAccountBrowsing(events)).toBe(events);
  });
});

// "No service-account browsing found" must not be reported when the records carry no account.
describe("attributionNote", () => {
  it("counts the records that carry no account", () => {
    const note = attributionNote([
      bag("alice"),
      ev({
        description: "Shellbag: C:\\x [user: not recorded by this collection]",
        sources: ["Shellbags"],
      }),
    ]);
    expect(note).toContain("1 of 2 browsing record(s) carry no account");
    expect(note).toContain("Re-collect the per-user hives");
  });

  it("says so plainly when everything is attributed", () => {
    expect(attributionNote([bag("alice")])).toContain("All 1 browsing record(s) carry an account");
  });

  it("says so plainly when there is no browsing evidence at all", () => {
    expect(attributionNote([])).toContain("no shellbag or share-access evidence");
  });
});

describe("reachability", () => {
  it("runs from the merge", () => {
    const merge = readFileSync(join(process.cwd(), "src/analysis/stateMerge.ts"), "utf8");
    expect(merge).toContain("markServiceAccountBrowsing");
  });

  it("has its marker stripped before correlation keys a duplicate", () => {
    const corr = readFileSync(join(process.cwd(), "src/analysis/correlate.ts"), "utf8");
    expect(corr).toContain("noninteractive account browsing");
  });

  // Two accounts that browsed the same folder used to collapse into one event.
  it("keys a shellbag on the account as well as the path", () => {
    const kape = readFileSync(join(process.cwd(), "src/analysis/kapeImport.ts"), "utf8");
    expect(kape).toContain("sb|${account.toLowerCase()}|${path.toLowerCase()}");
  });
});
