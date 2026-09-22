// #1530 — a first-party updater's connection to its own vendor is Info, and every clause that
// keeps the rule's grade is a clause an intruder would want to get past. The real rows are the
// seven Sysmon EID 3 records from INC-2026-001 that were fused into a C2 finding.
import { describe, it, expect } from "vitest";
import {
  downgradeFirstPartyEgress,
  firstPartyClientProduct,
  firstPartyEgressNote,
} from "../../src/analysis/firstPartyEgress.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

const ONEDRIVE_SETUP =
  "C:\\Users\\vagrant\\AppData\\Local\\Microsoft\\OneDrive\\StandaloneUpdater\\OneDriveSetup.exe";

function netRow(p: {
  image?: string;
  dst?: string;
  port?: number;
  severity?: ForensicEvent["severity"];
  mitre?: string[];
  promotedAt?: string;
  origin?: ForensicEvent["origin"];
}): ForensicEvent {
  const image = p.image ?? ONEDRIVE_SETUP;
  return {
    id: "1e61",
    timestamp: "2026-08-30T15:02:40.005Z",
    description:
      "Velociraptor [Windows.Sigma.Base] Sigma: Net Conn (Sysmon Alert) - Sysmon Network connection (EID 3)",
    severity: p.severity ?? "Medium",
    mitreTechniques: p.mitre ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(p.promotedAt ? { promotedAt: p.promotedAt } : {}),
    ...(p.origin ? { origin: p.origin } : {}),
    canonical: {
      schemaVersion: "1.0.0",
      event: { category: "network", type: "connection" },
      network: {
        source: { address: "192.168.195.133" },
        destination: { address: p.dst ?? "150.171.109.82", port: p.port ?? 443 },
        protocol: "tcp",
      },
      file: { path: image, name: image.slice(image.lastIndexOf("\\") + 1) },
      time: { observed: "2026-08-30 15:02:40.005", normalized: "2026-08-30T15:02:40.005Z" },
    },
  } as unknown as ForensicEvent;
}

describe("firstPartyClientProduct", () => {
  it.each([
    ["the per-user OneDrive install", ONEDRIVE_SETUP, "OneDrive"],
    [
      "the standalone updater",
      "C:\\Users\\v\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
      "OneDrive",
    ],
    [
      "the sync service",
      "C:\\Users\\v\\AppData\\Local\\Microsoft\\OneDrive\\26.163.0823.0004\\OneDrive.Sync.Service.exe",
      "OneDrive",
    ],
    ["the machine-wide install", "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "OneDrive"],
    [
      "the Edge updater",
      "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
      "Microsoft Edge Update",
    ],
    [
      "the Defender engine",
      "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\MsMpEng.exe",
      "Microsoft Defender",
    ],
  ])("recognises %s", (_label, path, product) => {
    expect(firstPartyClientProduct(path)).toBe(product);
  });

  it.each([
    ["a stranger beside a real install", "C:\\Users\\v\\AppData\\Local\\Microsoft\\OneDrive\\evil.exe"],
    ["the right name in the wrong place", "C:\\Users\\v\\Downloads\\OneDriveSetup.exe"],
    [
      "a traversal into the install shape",
      "C:\\Users\\v\\..\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
    ],
    ["a look-alike directory", "C:\\Users\\v\\AppData\\Local\\Microsoft\\OneDriveX\\OneDrive.exe"],
    // A browser connects wherever it is told to, so being Edge says nothing about the destination.
    ["the browser itself", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"],
    ["svchost, whose service name an EID 3 never records", "C:\\Windows\\System32\\svchost.exe"],
    ["nothing at all", ""],
  ])("refuses %s", (_label, path) => {
    expect(firstPartyClientProduct(path)).toBe("");
  });
});

describe("firstPartyEgressNote — the clauses that lower the grade", () => {
  it("lowers OneDriveSetup.exe to a Microsoft service address on 443", () => {
    expect(firstPartyEgressNote(netRow({}))).toBe(
      " [first-party update traffic — OneDrive to a Microsoft service address on 443]",
    );
  });

  it("lowers a Microsoft fetch on 80 as well as 443", () => {
    expect(firstPartyEgressNote(netRow({ dst: "13.107.4.50", port: 80 }))).toContain("Microsoft");
  });
});

describe("firstPartyEgressNote — the clauses that keep the rule's grade", () => {
  it.each([
    ["an unknown ISP destination", { dst: "82.102.152.51" }],
    ["an internal destination", { dst: "10.0.0.162" }],
    ["rentable Azure compute", { dst: "20.40.1.1" }],
    ["a Cloudflare edge, which anyone can front C2 behind", { dst: "104.16.1.1" }],
    ["an Akamai edge, which can front a compromised origin", { dst: "23.221.30.94" }],
    ["a port no updater fetches over", { port: 4444 }],
    ["a High verdict", { severity: "High" as const }],
    ["a Critical verdict", { severity: "Critical" as const }],
    ["a row a named rule mapped to a technique", { mitre: ["T1071.001"] }],
    ["a row the analyst promoted", { promotedAt: "2026-09-01T00:00:00Z" }],
    ["a row already carrying an origin", { origin: "collector" as const }],
    [
      "a binary an intruder dropped in the install directory",
      {
        image: "C:\\Users\\vagrant\\AppData\\Local\\Microsoft\\OneDrive\\beacon.exe",
      },
    ],
  ])("keeps %s", (_label, patch) => {
    expect(firstPartyEgressNote(netRow(patch))).toBe("");
  });

  it("keeps a row with no destination recorded", () => {
    const row = netRow({});
    delete (row.canonical as { network?: unknown }).network;
    expect(firstPartyEgressNote(row)).toBe("");
  });
});

describe("downgradeFirstPartyEgress", () => {
  it("returns new events and never mutates the input", () => {
    const rows = [netRow({}), netRow({ dst: "82.102.152.51" })];
    const before = JSON.stringify(rows);
    const { events, downgraded } = downgradeFirstPartyEgress(rows);
    expect(downgraded).toEqual(["1e61"]);
    expect(events[0].severity).toBe("Info");
    expect(events[0].description).toContain("first-party update traffic");
    expect(events[1].severity).toBe("Medium");
    expect(JSON.stringify(rows)).toBe(before);
  });

  it("is idempotent — a second pass changes nothing", () => {
    const once = downgradeFirstPartyEgress([netRow({})]);
    const twice = downgradeFirstPartyEgress(once.events);
    expect(twice.downgraded).toEqual([]);
    expect(twice.events[0].description).toBe(once.events[0].description);
  });

  it("leaves a timeline with nothing to lower untouched", () => {
    const rows = [netRow({ dst: "82.102.152.51" })];
    const { events, downgraded } = downgradeFirstPartyEgress(rows);
    expect(downgraded).toEqual([]);
    expect(events[0]).toBe(rows[0]);
  });
});

// The whole chain on the row shape the case actually holds: a Velociraptor Windows.Sigma.Base
// export of Hayabusa's "Net Conn (Sysmon Alert)" hits. The importer must still produce the row at
// the rule's grade (it grades rules, not images), the IOC sink must not call Microsoft's service
// address an `ip` indicator, and the downgrade must lower the row.

function sigmaNetConnRow(image: string, dstIp: string, port: number): Record<string, unknown> {
  return {
    Timestamp: "2026-08-30T15:02:40.005Z",
    Computer: "HOST-01",
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EID: 3,
    Level: "medium",
    Title: "Net Conn (Sysmon Alert)",
    RecordID: 1188,
    Details: `Proto: tcp ¦ TgtIP: ${dstIp} ¦ TgtPort: ${port} ¦ Proc: ${image}`,
    _Event: {
      System: {
        Provider: { Name: "Microsoft-Windows-Sysmon" },
        EventID: { Value: 3 },
        Channel: "Microsoft-Windows-Sysmon/Operational",
        Computer: "HOST-01",
        Security: { UserID: "S-1-5-18" },
      },
      EventData: {
        UtcTime: "2026-08-30 15:02:40.005",
        Image: image,
        User: "HOST-01\\analyst",
        Protocol: "tcp",
        Initiated: true,
        SourceIp: "192.0.2.10",
        SourceHostname: "host-01.example.com",
        DestinationIp: dstIp,
        DestinationPort: port,
      },
    },
    _Source: "Windows.Sigma.Base",
    Fqdn: "host-01.example.com",
  };
}

describe("the INC-2026-001 row shape, end to end", () => {
  const parsed = parseVelociraptorJson(
    JSON.stringify({
      "Windows.Hayabusa.Rules": [
        sigmaNetConnRow(ONEDRIVE_SETUP, "150.171.109.82", 443),
        sigmaNetConnRow(ONEDRIVE_SETUP, "198.51.100.7", 443),
        sigmaNetConnRow("C:\\Windows\\System32\\svchost.exe", "0:0:0:0:0:0:0:1", 5985),
      ],
    }),
    { aggregate: false },
  );

  it("imports the OneDrive rows at the rule's grade — the importer grades rules, not images", () => {
    const rows = parsed.events.filter((e) => e.description.includes("OneDriveSetup.exe"));
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.severity === "Medium")).toBe(true);
  });

  it("lowers only the row whose destination is a vendor service address", () => {
    const { events, downgraded } = downgradeFirstPartyEgress(
      parsed.events.map((e, i) => ({ ...e, id: `e${i}`, relatedFindingIds: [], sourceScreenshots: [] })),
    );
    expect(downgraded).toHaveLength(1);
    const lowered = events.find((e) => e.severity === "Info" && e.description.includes("OneDriveSetup"));
    expect(lowered?.description).toContain("first-party update traffic");
    expect(events.filter((e) => e.description.includes("198.51.100.7"))[0].severity).toBe("Medium");
  });

  it("records the Microsoft service address as context, not as an ip indicator", () => {
    const ms = parsed.iocs.find((c) => c.value === "150.171.109.82");
    expect(ms?.type).toBe("other");
    const real = parsed.iocs.find((c) => c.value === "198.51.100.7");
    expect(real?.type).toBe("ip");
  });

  it("mints no indicator for loopback written the long way", () => {
    expect(parsed.iocs.some((c) => c.value.includes("0:0:0:0:0:0:0:1"))).toBe(false);
  });
});
