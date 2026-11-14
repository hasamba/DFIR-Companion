import { describe, expect, it } from "vitest";
import { rosterOf } from "../../../src/analysis/ai/watson/superRoster.js";
import type { ForensicEvent } from "../../../src/analysis/stateTypes.js";

// Task 3 fix round 1: explicit fields of a raw row give the roster the same forms the forensic path
// masks (I1, I2), while names only free text suggests keep the Task 2 precision rule.

const row = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "a",
  timestamp: "2026-01-01T10:00:00Z",
  description: "rclone",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});
const account = (name: string) => ({ canonical: { account: { name } } as never });

describe("explicit host fields give the host's first label (I1)", () => {
  it("an FQDN in asset, assetRecord or a network hostname also lists its short label", () => {
    const r = rosterOf([
      row({ asset: "FILESRV.acme.com", assetRecord: "dc01.corp.example.org" }),
      row({ canonical: { network: { source: { hostname: "Web-Gw.acme.com" } } } as never }),
    ]);
    expect(r.hosts).toEqual(expect.arrayContaining(["FILESRV.acme.com", "FILESRV", "dc01"]));
  });

  it("never labels an IP, a label under 3 characters or a common word", () => {
    const r = rosterOf([
      row({ asset: "10.9.8.7", assetRecord: "the.example.com" }),
      row({ asset: "db.acme.com" }),
    ]);
    expect(r.hosts).not.toEqual(expect.arrayContaining(["10"]));
    expect(r.hosts.map((h) => h.toLowerCase())).not.toContain("the");
    expect(r.hosts).not.toContain("db");
  });

  it("a host named only by free text (a UNC path) gets no label from the roster", () => {
    const r = rosterOf([row({ commandLine: "copy x \\\\files.acme.com\\share" })]);
    expect(r.hosts).toContain("files.acme.com");
    expect(r.hosts).not.toContain("files");
  });
});

describe("network hostnames are listed whole, never labelled (RI1)", () => {
  it("a destination like login.mega.example gives no 'login' entry", () => {
    const r = rosterOf([
      row({ canonical: { network: { destination: { hostname: "login.mega.example" } } } as never }),
      row({ canonical: { network: { source: { hostname: "raw.example.org" } } } as never }),
    ]);
    expect(r.hosts).toEqual(["login.mega.example", "raw.example.org"]);
  });
});

describe("an account field is split into its forms (I2)", () => {
  it("DOMAIN\\user lists the whole value, the user and the domain", () => {
    const r = rosterOf([row(account("ACME\\jdoe"))]);
    expect(r.users).toEqual(expect.arrayContaining(["ACME\\jdoe", "jdoe"]));
    expect(r.hosts).toContain("ACME");
  });

  it("user@domain lists the whole value, the user and the domain", () => {
    const r = rosterOf([row({ callerName: "mkowal@corp.acme.com" })]);
    expect(r.users).toEqual(expect.arrayContaining(["mkowal@corp.acme.com", "mkowal"]));
    expect(r.hosts).toContain("corp.acme.com");
  });

  it("WORKGROUP is not a domain; the user is kept", () => {
    const r = rosterOf([row(account("WORKGROUP\\jdoe"))]);
    expect(r.users).toEqual(expect.arrayContaining(["WORKGROUP\\jdoe", "jdoe"]));
    expect(r.hosts).toEqual([]);
  });

  it("a public mail domain is not listed; the user is", () => {
    for (const d of ["gmail.com", "Outlook.com", "proton.me"]) {
      const r = rosterOf([row({ callerName: `kate.r@${d}` })]);
      expect(r.users).toEqual(expect.arrayContaining([`kate.r@${d}`, "kate.r"]));
      expect(r.hosts).toEqual([]);
    }
  });

  it("a built-in principal gives no user and no domain", () => {
    const r = rosterOf([row(account("NT AUTHORITY\\SYSTEM")), row(account("BUILTIN\\Administrators"))]);
    expect(r.users).toEqual([]);
    expect(r.hosts).toEqual([]);
  });
});

describe("multi-word user folders (controller ruling: precision stands)", () => {
  it("are read from the path field and quoted paths only, never unquoted free text (a known limit)", () => {
    expect(rosterOf([row({ path: "C:\\Users\\Kate Smith\\x.txt" })]).users).toContain("Kate Smith");
    expect(rosterOf([row({ description: 'open "C:\\Users\\Kate Smith\\x.txt"' })]).users).toContain(
      "Kate Smith",
    );
    // Unquoted in a description or command: not listed. The hop still masks it by text extraction,
    // but a restored echo of it is not covered in later rounds.
    const loose = rosterOf([
      row({
        description: "C:\\Users\\Kate Smith\\Documents\\x.txt",
        commandLine: "type C:\\Users\\Kate Smith\\a",
      }),
    ]);
    expect(loose.users.map((u) => u.toLowerCase())).not.toContain("kate smith");
    expect(loose.users.map((u) => u.toLowerCase())).not.toContain("kate");
  });
});
