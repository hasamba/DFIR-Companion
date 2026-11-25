import { describe, expect, it } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { autorunsSignature, isAutorunsRow } from "../../src/analysis/veloAutorunsMap.js";
import { huntFieldsOf, huntItemKey } from "../../src/analysis/huntArtifactFields.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Windows.Sysinternals.Autoruns rows (#2731) get their own mapper: the entry, image path, signer
// verdict and hashes survive, and each row forms an autorun hunt item. Column names follow the
// autorunsc CSV output (-c -h -s); all values here are synthetic.
const SHA = "e".repeat(64);

const autorunsRow = (host: string, signer: string, extra: Record<string, unknown> = {}) => ({
  _Source: "Windows.Sysinternals.Autoruns",
  Fqdn: host,
  Time: "20260105-101500",
  "Entry Location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  Entry: "VendorUpdater",
  Enabled: "enabled",
  Category: "Logon",
  Profile: "System-wide",
  Description: "Vendor updater",
  Signer: signer,
  Company: "Vendor Inc",
  "Image Path": "c:\\program files\\vendor\\updater.exe",
  Version: "1.2.3",
  "Launch String": '"C:\\Program Files\\Vendor\\updater.exe" /background',
  MD5: "f".repeat(32),
  "SHA-1": "1".repeat(40),
  "SHA-256": SHA,
  ...extra,
});

const events = (rows: object[]): ForensicEvent[] =>
  parseVelociraptorJson(JSON.stringify(rows), { aggregate: true }).events.map((e) => ({
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...e,
  }));

describe("Autoruns mapper (#2731)", () => {
  it("keeps the entry, the image path, the location and the SHA-256", () => {
    const [e] = events([autorunsRow("WS-01", "(Verified) Vendor Inc")]);
    expect(e.description).toMatch(
      /^Velociraptor \[Windows\.Sysinternals\.Autoruns\]: Autorun entry \(Autoruns\): VendorUpdater/,
    );
    expect(e.description).toContain("c:\\program files\\vendor\\updater.exe");
    expect(e.description).toContain("CurrentVersion\\Run");
    expect(e.path).toBe("c:\\program files\\vendor\\updater.exe");
    expect(e.sha256).toBe(SHA);
    expect(e.timestamp).toBe("2026-01-05T10:15:00Z");
  });

  it("grades an enabled entry with a verified signer Info, an unverified or unsigned one Low (T1547)", () => {
    const grade = (signer: string, enabled = "enabled") => {
      const [e] = events([autorunsRow("WS-01", signer, { Enabled: enabled })]);
      return { severity: e.severity, mitre: e.mitreTechniques };
    };
    expect(grade("(Verified) Vendor Inc")).toEqual({ severity: "Info", mitre: [] });
    expect(grade("(Not verified) Vendor Inc")).toEqual({ severity: "Low", mitre: ["T1547"] });
    expect(grade("")).toEqual({ severity: "Low", mitre: ["T1547"] });
    expect(grade("Vendor Inc")).toEqual({ severity: "Low", mitre: ["T1547"] });
    expect(grade("(Verified) ")).toEqual({ severity: "Low", mitre: ["T1547"] });
  });

  it("grades a disabled entry Info, signed or not", () => {
    for (const signer of ["(Verified) Vendor Inc", "(Not verified) Vendor Inc", ""]) {
      const [e] = events([autorunsRow("WS-01", signer, { Enabled: "disabled" })]);
      expect(e.severity).toBe("Info");
      expect(e.mitreTechniques).toEqual([]);
    }
  });

  it("records a signer only from a '(Verified) ' Signer value", () => {
    expect(events([autorunsRow("WS-01", "(Verified) Vendor Inc")])[0].fileIdentity).toEqual({
      signer: "Vendor Inc",
    });
    expect(events([autorunsRow("WS-01", "(Not verified) Vendor Inc")])[0].fileIdentity).toEqual({
      signatureUnverified: true,
    });
    expect(events([autorunsRow("WS-01", "")])[0].fileIdentity).toBeUndefined();
    expect(autorunsSignature("Vendor Inc")).toEqual({ signatureUnverified: true });
    expect(autorunsSignature("(Verified) ")).toEqual({ signatureUnverified: true }); // no signer name: never a signer
  });

  it("never uses the Company column as a signer", () => {
    const [e] = events([autorunsRow("WS-01", "")]);
    expect(huntFieldsOf(e)?.signer).toBeUndefined();
  });

  it("forms one autorun hunt item across hosts, with the verified signer", () => {
    const ev = events([
      autorunsRow("WS-01", "(Verified) Vendor Inc"),
      autorunsRow("WS-02", "(Verified) Vendor Inc"),
    ]);
    const f = ev.map(huntFieldsOf);
    expect(f.every((x) => x?.evidence === "autorun")).toBe(true);
    expect(new Set(f.map((x) => huntItemKey(x!)))).toEqual(
      new Set(["autorun|updater.exe|\\program files\\vendor"]),
    );
    expect(f[0]).toMatchObject({ signer: "Vendor Inc", sha256: SHA });
    expect(f[0]?.sha1).toBeUndefined(); // the autorunsc SHA-1 is not an Amcache SHA1
  });

  it("two entries on one host stay two events", () => {
    const ev = events([
      autorunsRow("WS-01", ""),
      autorunsRow("WS-01", "", { Entry: "Other", "Image Path": "c:\\tools\\other.exe" }),
    ]);
    expect(ev).toHaveLength(2);
  });

  it("routes an autorunsc row without a _Source column by its columns", () => {
    const { _Source: _drop, ...bare } = autorunsRow("WS-01", "(Verified) Vendor Inc");
    expect(isAutorunsRow(bare)).toBe(true);
    const [e] = events([bare]);
    expect(e.description).toContain("Autorun entry (Autoruns): VendorUpdater");
  });

  it("leaves Windows.Sys.StartupItems rows on the StartupItems mapper", () => {
    const [e] = events([
      {
        _Source: "Windows.Sys.StartupItems",
        Fqdn: "WS-01",
        Name: "Updater",
        OSPath: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk",
        Details: "C:\\Tools\\updater.exe",
        Enabled: "enabled",
      },
    ]);
    expect(e.description).toMatch(
      /^Velociraptor \[Windows\.Sys\.StartupItems\]: Startup \[Updater\] — C:\\Tools\\updater\.exe \(enabled\)/,
    );
  });
});

// #2881: a cap applied after the host suffix cut it to a fragment ("@ WS-") in a ~6-char window.
describe("Autoruns mapper — host suffix under the cap (#2881)", () => {
  it("keeps the '@ HOST' suffix whole when a long entry name reaches the 600-char cap", () => {
    for (let n = 150; n <= 450; n++) {
      const [e] = events([autorunsRow("WS-01", "(Verified) Vendor Inc", { Entry: "e".repeat(n) })]);
      expect(e.description.length).toBeLessThanOrEqual(600);
      expect(e.description.endsWith(" @ WS-01")).toBe(true);
    }
  });
});
