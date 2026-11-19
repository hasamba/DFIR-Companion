// DetectRaptor.Windows.Detection.Webhistory — a browser visit/download whose domain matched one of the
// pack's domain lists ("Phishing Hosting", "File Sharing", …). The verdict is `Detection.Category`
// (no rule Name) and the visit sits nested in `ArtifactData`, so before this mapper the row reached
// the generic dump as "Phishing Hosting - " with no domain, no URL and empty details — and every
// domain on a host folded into one event.
import { describe, expect, it } from "vitest";
import { isWebhistoryRow, mapWebhistory } from "../../src/analysis/webhistoryDetection.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

const ARTIFACT = "DetectRaptor.Windows.Detection.Webhistory";
const HISTORY = "C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History";

const visit = (domain = "login-portal.example.net", over: Record<string, unknown> = {}) => ({
  BrowserArtifact: "Chromium History",
  Category: "Phishing Hosting",
  Domain: domain,
  ArtifactData: {
    User: "bob",
    ID: 5,
    Visit_Date: "2026-11-01T10:00:00Z",
    Title: "Sign in to your account",
    URL: `https://${domain}/auth/login`,
    Last_Visit_Date: "2026-11-01T10:05:00Z",
    OSPath: HISTORY,
  },
  Detection: {
    Category: "Phishing Hosting",
    DomainRegex: "example\\.net$",
    AllowRegex: "",
    Comment: "phishing host list",
  },
  ...over,
});

const download = () => ({
  BrowserArtifact: "Chromium Download",
  Category: "File Sharing",
  Domain: "files.example.org",
  ArtifactData: {
    User: "bob",
    ID: 9,
    Download_Date: "2026-11-02T08:00:00Z",
    Current_Path: "C:\\Users\\bob\\Downloads\\invoice.zip",
    Target_Path: "C:\\Users\\bob\\Downloads\\invoice.zip",
    Tab_URL: "https://files.example.org/d/abc",
    Tab_Referrer_URL: "",
    Mime_Type: "application/zip",
    OSPath: HISTORY,
  },
  Detection: { Category: "File Sharing", DomainRegex: "example\\.org$", AllowRegex: "", Comment: "" },
});

describe("isWebhistoryRow", () => {
  it("claims the DetectRaptor Webhistory shape", () => {
    expect(isWebhistoryRow(visit())).toBe(true);
  });
  it("ignores a Detection verdict without a DomainRegex", () => {
    expect(isWebhistoryRow({ Domain: "x.example", Detection: { Name: "rule" } })).toBe(false);
    expect(isWebhistoryRow({ Detection: { Category: "c", DomainRegex: "x" } })).toBe(false);
  });
});

describe("mapWebhistory", () => {
  it("puts the category and domain in the title and the visit in the details", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapWebhistory(visit(), ARTIFACT, "WS01", sink);
    expect(e.description).toContain(
      `Velociraptor [${ARTIFACT}]: Phishing Hosting — login-portal.example.net`,
    );
    expect(e.description).toContain("URL: https://login-portal.example.net/auth/login");
    expect(e.description).toContain("User: bob");
    expect(e.timestamp).toBe("2026-11-01T10:00:00Z");
    expect(e.severity).toBe("Medium");
    expect(e.asset).toBe("WS01");
    expect(e.message).toContain("Domain: login-portal.example.net");
    expect(e.message).toContain("Title: Sign in to your account");
    expect(e.message).toContain(`OSPath: ${HISTORY}`);
    expect(e.message).toContain("DomainRegex: example\\.net$");
    expect(e.message).toContain("Comment: phishing host list");
    const iocs = [...sink.values()];
    expect(iocs.some((i) => i.type === "domain" && i.value === "login-portal.example.net")).toBe(true);
    expect(iocs.some((i) => i.type === "url")).toBe(true);
  });

  it("reads a download row's own fields and date", () => {
    const e = mapWebhistory(download(), ARTIFACT, "WS01", new Map());
    expect(e.description).toContain("File Sharing — files.example.org");
    expect(e.description).toContain("URL: https://files.example.org/d/abc");
    expect(e.description).toContain("File: invoice.zip");
    expect(e.timestamp).toBe("2026-11-02T08:00:00Z");
    expect(e.message).toContain("Mime_Type: application/zip");
  });

  it("keeps two domains apart and the same domain together", () => {
    const a = mapWebhistory(visit("a.example.net"), ARTIFACT, "WS01", new Map());
    const b = mapWebhistory(visit("b.example.net"), ARTIFACT, "WS01", new Map());
    const a2 = mapWebhistory(visit("a.example.net"), ARTIFACT, "WS01", new Map());
    expect(a.aggKey).not.toBe(b.aggKey);
    expect(a.aggKey).toBe(a2.aggKey);
  });

  it("survives a row with no ArtifactData", () => {
    const e = mapWebhistory({ ...visit(), ArtifactData: undefined }, ARTIFACT, "", new Map());
    expect(e.description).toContain("Phishing Hosting — login-portal.example.net");
  });
});

describe("Velociraptor import of a Webhistory file", () => {
  it("emits one titled event per domain with details", () => {
    const rows = [visit("a.example.net"), visit("b.example.net")].map((r) => ({
      ...r,
      Fqdn: "WS01",
      _Source: ARTIFACT,
    }));
    const { events } = parseVelociraptorJson(JSON.stringify(rows));
    expect(events).toHaveLength(2);
    const titles = events.map((e) => e.description).sort();
    expect(titles[0]).toContain("Phishing Hosting — a.example.net");
    expect(titles[1]).toContain("Phishing Hosting — b.example.net");
    for (const e of events) {
      expect(e.message ?? "").toContain("URL: https://");
      expect(e.description.match(/\[DetectRaptor\.Windows\.Detection\.Webhistory\]/g)).toHaveLength(1);
    }
  });
});
