// Regression tests for the precision/recall fixes from the Velociraptor artifact eval:
// routing (HijackLibsMFT rescue, native Hayabusa), and IOC hygiene (version strings, code tokens).
import { describe, it, expect } from "vitest";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { extractDomains } from "../../src/analysis/textDomains.js";
import { scrapeText } from "../../src/analysis/veloTextIocs.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { mapHijackLib } from "../../src/analysis/hijackLibImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

describe("import routing — eval fixes", () => {
  it("rescues a DetectRaptor pack whose row shape does not sample (HijackLibsMFT) to velociraptor, not unknown", () => {
    // NDJSON of the HijackLibs shape — no _Source, no Detection, no siem markers.
    const body = [
      JSON.stringify({
        HijackLibInfo: { DllName: "log4net.dll", Vendor: "Apache", Type: "Sideloading" },
        OSPath: "C:\\Users\\v\\AppData\\Local\\app\\log4net.dll",
        FileName: "log4net.dll",
      }),
      JSON.stringify({
        HijackLibInfo: { DllName: "msimg32.dll", Vendor: "Microsoft", Type: "Sideloading" },
        OSPath: "C:\\Users\\v\\Downloads\\consent\\msimg32.dll",
        FileName: "msimg32.dll",
      }),
    ].join("\n");
    expect(detectImportKind("DetectRaptor.Windows.Detection.HijackLibsMFT.json", body)).toBe("velociraptor");
    // …and the importer actually keeps them (not rejected, not dropped to nothing).
    const r = parseVelociraptorJson(body, { artifact: "DetectRaptor.Windows.Detection.HijackLibsMFT" });
    expect(r.kept).toBeGreaterThan(0);
  });

  it("routes a Velociraptor-hosted Hayabusa result file to the native Hayabusa importer", () => {
    const body = [
      JSON.stringify({
        Timestamp: "2026-08-26T03:00:00Z",
        Computer: "DESKTOP-1",
        Channel: "Security",
        EID: 4104,
        Level: "high",
        Title: "Suspicious PowerShell",
        Details: "x",
        _Source: "Windows.Hayabusa.Rules",
      }),
    ].join("\n");
    expect(detectImportKind("Windows.Hayabusa.Rules.json", body)).toBe("hayabusa");
  });

  it("does not misroute a non-Hayabusa velo file that merely mentions the word in a value", () => {
    const body = JSON.stringify([
      { _Source: "Windows.Detection.Sigma", Rule: { Title: "hayabusa mention", Level: "high" } },
    ]);
    expect(detectImportKind("Windows.Detection.Sigma.json", body)).not.toBe("hayabusa");
  });
});

describe("HijackLibsMFT — DLL side-load (T1574) mapping", () => {
  const hijackRow = (osPath: string, expected: string) => ({
    _Source: "DetectRaptor.Windows.Detection.HijackLibsMFT",
    HijackLibInfo: {
      DllName: "log4net.dll",
      Vendor: "Apache",
      Type: "Sideloading",
      ExpectedLocation: expected,
      ExecutableSHA256: "a".repeat(64),
      Url: "https://hijacklibs.net/entries/x.html",
    },
    OSPath: osPath,
    FileName: "log4net.dll",
  });

  it("grades a DLL outside its vendor location as a side-load candidate (Medium + T1574.002)", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        hijackRow("C:\\Users\\v\\AppData\\Local\\app\\log4net.dll", "\\\\Program Files\\\\Vendor"),
      ]),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1574.002");
  });

  it("grades a DLL sitting in its expected vendor location as Low (likely legitimate)", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([hijackRow("C:\\Program Files\\Vendor\\log4net.dll", "\\\\Program Files\\\\Vendor")]),
    );
    expect(r.events[0].severity).toBe("Low");
  });

  // A hijackable-DLL scan walks the whole disk, so a deep path is its NORMAL input. The key used to
  // be truncated with a plain .slice(0, 400): two DLLs under one deep directory collapsed to one
  // key, and applyEventIdentity then overwrote the survivor's path and hash — deleting a row's
  // evidence rather than miscounting it (#722). boundedAggKey digests the full key instead.
  it("keeps the same DLL at two deep paths as two aggregation keys", () => {
    const deepDir = `C:\\${"nested\\".repeat(70)}`;
    const key = (leaf: string) =>
      mapHijackLib(
        { HijackLibInfo: { DllName: "log4net.dll" }, OSPath: `${deepDir}${leaf}\\log4net.dll` },
        "DetectRaptor.Windows.Detection.HijackLibsMFT",
        "HOST01",
        new Map<string, SiemIoc>(),
      ).aggKey;
    const a = key("appOne");
    const b = key("appTwo");
    expect(a).not.toBe(b);
    expect(a.length).toBeLessThanOrEqual(400);
  });
});

describe("IOC hygiene — version strings are not IPs", () => {
  it("does not extract a FileVersion/ProductVersion field as an IP IOC", () => {
    const row = {
      _Source: "DetectRaptor.Windows.Registry.NetworkProvider",
      Name: "provider",
      FileVersion: "11.0.49.0",
      ProductVersion: "8.0.0.1",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.iocs.some((i) => i.type === "ip")).toBe(false);
  });

  it("rejects an invalid-octet dotted quad (a version like 1.457.375.0) as an IP", () => {
    const sink = new Map<string, SiemIoc>();
    scrapeText("assembly 1.457.375.0 loaded", sink);
    expect([...sink.values()].some((i) => i.type === "ip")).toBe(false);
  });

  it("does not read a version-argument dotted quad as an IP", () => {
    const sink = new Map<string, SiemIoc>();
    scrapeText("choco install openssh --version 8.0.0.1 ; $ModuleVersion = '1.0.0.0'", sink);
    expect([...sink.values()].some((i) => i.type === "ip")).toBe(false);
  });

  it("still extracts a real IP from free text", () => {
    const sink = new Map<string, SiemIoc>();
    scrapeText("beacon to 45.135.232.3 over 443", sink);
    expect([...sink.values()].some((i) => i.type === "ip" && i.value === "45.135.232.3")).toBe(true);
  });
});

describe("IOC hygiene — code tokens are not domains", () => {
  it("drops property-access / non-ccTLD code tokens", () => {
    const got = extractDomains("$proc.Id $decoy.Id aes.iv Microsoft.Po [System.Management.Automation.Id]");
    for (const junk of ["proc.id", "decoy.id", "aes.iv", "microsoft.po", "system.management.automation.id"]) {
      expect(got).not.toContain(junk);
    }
  });

  it("keeps real domains, including multi-label Indonesian ones", () => {
    const got = extractDomains("c2 at borjumaniya.store and news at tempo.co.id and evil.com");
    expect(got).toContain("borjumaniya.store");
    expect(got).toContain("tempo.co.id");
    expect(got).toContain("evil.com");
  });
});

// Identifiers a script block names in plain text and no scraper reads.
//
// From the Bissa-scanner eval: the whole campaign — both target CVEs, both Telegram bot handles,
// the exfil bucket, the acquirer domains — arrived in ONE 4104 script block. The domain pass (#648)
// caught the domains. The CVEs and the bot handles were read by the importer and dropped on the
// floor, so no finding, no IOC, and no report ever named the vulnerability being exploited or the
// channel the operator was alerted on.
describe("IOC hygiene — identifiers named inside a script block", () => {
  const values = (text: string) => {
    const sink = new Map<string, SiemIoc>();
    scrapeText(text, sink);
    return [...sink.values()].map((i) => i.value);
  };

  it("extracts a CVE id the script names as its exploitation target", () => {
    expect(values("react2shell module targeting CVE-2025-55182")).toContain("CVE-2025-55182");
  });

  it("extracts every CVE in a block that names more than one", () => {
    const v = values("modules: CVE-2025-55182 (RCE) and CVE-2025-9501 (version-check only)");
    expect(v).toContain("CVE-2025-55182");
    expect(v).toContain("CVE-2025-9501");
  });

  it("normalizes a lowercase cve id to the canonical form", () => {
    expect(values("cve-2025-55182")).toContain("CVE-2025-55182");
  });

  it("does not read a bare year-number pair as a CVE", () => {
    expect(values("build 2025-55182 shipped")).not.toContain("CVE-2025-55182");
  });

  // Telegram requires a bot username to end in "bot", so the suffix is the platform's own rule and
  // not a guess — an @mention that is not a bot never matches.
  it("extracts a Telegram bot handle used for operator alerting", () => {
    expect(values("AlertBotUsername = 'bissapwned_bot' -> @bissapwned_bot")).toContain("@bissapwned_bot");
  });

  it("extracts a second bot handle named in the same block", () => {
    expect(values("alert bot @bissapwned_bot, ai-control bot @bissa_scan_bot")).toContain("@bissa_scan_bot");
  });

  // How the eval's script block actually wrote it: assigned to a key, no `@` anywhere in the file.
  it("extracts a bot handle a script assigned to a bot-named key with no @", () => {
    const v = values('    AlertBotUsername  = "bissapwned_bot"\n    AiControlBot      = "bissa_scan_bot"');
    expect(v).toContain("@bissapwned_bot");
    expect(v).toContain("@bissa_scan_bot");
  });

  it("counts the assigned and written-out spellings of one bot as a single indicator", () => {
    expect(values('AlertBotUsername = "bissapwned_bot" alerts @bissapwned_bot')).toEqual(["@bissapwned_bot"]);
  });

  it("does not read a short word ending in bot as an assigned handle", () => {
    expect(values('robot: "mybot"')).toEqual([]);
  });

  it("does not read an ordinary @mention as a bot handle", () => {
    expect(values("operator handle @BonJoviGoesHard")).not.toContain("@BonJoviGoesHard");
  });

  it("does not read an email address as a bot handle", () => {
    expect(values("contact abuse@robot.example.com")).not.toContain("@robot");
  });

  it("extracts an s3:// destination the script uploads to", () => {
    expect(values("aws s3 cp results/*.zip s3://bissapromax/archives/")).toContain(
      "s3://bissapromax/archives/",
    );
  });
});
