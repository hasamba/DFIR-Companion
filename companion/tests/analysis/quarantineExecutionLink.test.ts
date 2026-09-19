import { describe, it, expect } from "vitest";
import { parseMacos } from "../../src/analysis/macosImport.js";
import { parseMacPersist } from "../../src/analysis/macosPersistImport.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { SPOTLIGHT_USAGE_BASIS } from "../../src/analysis/canonicalSpotlightUsage.js";
import {
  linkQuarantineExecution,
  RAN_MARKED_MARKER,
  USED_MARKED_MARKER,
  MARKED_FILE_MARKER,
} from "../../src/analysis/quarantineExecutionLink.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1037 link 2, the execution / usage path: a file that carries a quarantine mark (an attribute
// record, or a launchd job's program) against the rows that say the same path ran or was used —
// a process start, or a Spotlight last-used date — AFTER the mark. Byte-exact path (APFS may be
// case-sensitive), same host, never a basename, never "malicious".

const UUID = "8f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";
const UNIX_HEX = "5f3a1b2c"; // 2020-08-17T05:52:44Z
const PATH = "/Users/x/Downloads/installer";

type Ev = ForensicEvent;
const asForensic = (
  e: Partial<Ev> & { description: string; timestamp: string; severity: string },
  id: string,
): Ev => ({ mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...e, id });

const attrRow = (host?: string, path = PATH, sha?: string): Ev => {
  const rec = {
    path,
    "com.apple.quarantine": `0083;${UNIX_HEX};Safari;${UUID}`,
    ...(host ? { hostname: host } : {}),
    ...(sha ? { sha256: sha } : {}),
  };
  const e = parseMacos(JSON.stringify([rec]), { aggregate: false }).events.find((x) =>
    x.description.startsWith("macOS quarantine attribute"),
  )!;
  return asForensic(e, "attr1");
};

const processStart = (executable: string, iso: string, id: string, asset?: string, sha?: string): Ev =>
  asForensic(
    {
      description: `Process start: ${executable}`,
      timestamp: iso,
      severity: "Low",
      sources: ["EDR"],
      ...(asset ? { asset } : {}),
      ...(sha ? { sha256: sha } : {}),
      canonical: createCanonicalEvent({
        event: { category: "process", type: "start" },
        process: { executable, name: executable.split("/").pop()! },
        time: { observed: iso, normalized: iso },
        evidence: { rawRecords: [{ source: "edr", locator: id }] },
        producer: { importer: "siem", parserVersion: "1", mappingVersion: "1" },
      }),
    },
    id,
  );

const spotlightUsed = (path: string, lastUsed: string, id: string): Ev =>
  asForensic(
    {
      description: `Spotlight store item ${path}`,
      timestamp: lastUsed,
      severity: "Info",
      sources: ["mac_apt"],
      canonical: createCanonicalEvent({
        event: { category: "file", type: "spotlight-usage" },
        spotlightUsage: {
          tool: "mac_apt-spotlight",
          itemId: "1",
          displayName: "installer",
          displayNameSource: "kMDItemDisplayName",
          pathStatus: "resolved",
          path,
          useCount: 2,
          lastUsedDate: lastUsed,
          storeIdentity: "store",
          storeIdentitySource: "upload-label",
          reportFingerprint: "a".repeat(64),
          mappingVersion: "mac-spotlight-usage-v1",
          basis: SPOTLIGHT_USAGE_BASIS,
        },
        time: { observed: lastUsed, normalized: lastUsed },
        evidence: { rawRecords: [{ source: "mac_apt", locator: id }] },
        producer: {
          importer: "mac-spotlight-usage",
          parserVersion: "1",
          mappingVersion: "mac-spotlight-usage-v1",
        },
      }),
    },
    id,
  );

const AFTER = "2020-08-17T06:10:00Z";
const BEFORE = "2020-08-17T05:00:00Z";

describe("quarantine-marked file ↔ the evidence it ran or was used (#1037 link 2)", () => {
  it("a process start of the exact path after the mark is noted on both rows; the attribute row is raised to Medium", () => {
    const out = linkQuarantineExecution([attrRow(), processStart(PATH, AFTER, "p1")]);
    const a = out.find((e) => e.id === "attr1")!;
    const p = out.find((e) => e.id === "p1")!;
    expect(a.description).toContain(`${RAN_MARKED_MARKER} Process start: ${PATH}`);
    expect(a.description).toMatch(/after the mark/);
    expect(a.severity).toBe("Medium");
    expect(p.description).toContain(`${MARKED_FILE_MARKER} ${PATH}`);
    expect(p.severity).toBe("Medium");
    expect(a.description).not.toMatch(/malicious/);
  });

  it("a Spotlight last-used date after the mark is 'used', not 'ran'", () => {
    const out = linkQuarantineExecution([attrRow(), spotlightUsed(PATH, AFTER, "s1")]);
    const a = out.find((e) => e.id === "attr1")!;
    expect(a.description).toContain(`${USED_MARKED_MARKER} Spotlight last-used`);
    expect(a.description).toContain("opened or used, not necessarily executed");
    expect(a.description).not.toContain(RAN_MARKED_MARKER);
    expect(a.severity).toBe("Medium");
  });

  it("a run before the mark, a case-different path, another path, or a hash that differs joins nothing", () => {
    const rows = [
      attrRow(undefined, PATH, "a".repeat(64)),
      processStart(PATH, BEFORE, "before"),
      processStart(PATH.toUpperCase(), AFTER, "case"),
      processStart("/Users/x/Downloads/installer2", AFTER, "other"),
      processStart(PATH, AFTER, "hash", undefined, "b".repeat(64)),
    ];
    const out = linkQuarantineExecution(rows);
    const a = out.find((e) => e.id === "attr1")!;
    expect(a.description).not.toContain(RAN_MARKED_MARKER);
    expect(a.severity).toBe("Info");
    for (const id of ["before", "case", "other", "hash"])
      expect(out.find((e) => e.id === id)!.description).not.toContain(MARKED_FILE_MARKER);
  });

  it("two named hosts must agree; an unnamed side attaches only when one host is named", () => {
    expect(
      linkQuarantineExecution([attrRow("mac-01"), processStart(PATH, AFTER, "p1", "mac-01")]).find(
        (e) => e.id === "attr1",
      )!.description,
    ).toContain(RAN_MARKED_MARKER);
    expect(
      linkQuarantineExecution([attrRow("mac-01"), processStart(PATH, AFTER, "p1", "mac-02")]).find(
        (e) => e.id === "attr1",
      )!.description,
    ).not.toContain(RAN_MARKED_MARKER);
    expect(
      linkQuarantineExecution([attrRow("mac-01"), processStart(PATH, AFTER, "p1")]).find(
        (e) => e.id === "attr1",
      )!.description,
    ).toContain("host not named on one record");
  });

  it("a launchd job's quarantine-marked program joins the same way", () => {
    const plist = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.vendor.helper</string><key>ProgramArguments</key><array><string>/Users/Shared/.a/agent</string></array><key>RunAtLoad</key><true/></dict></plist>`;
    const text = `==> /Library/LaunchAgents/com.vendor.helper.plist <==\n# mtime: 2020-08-17T05:53:00Z\n# quarantine: 0083;${UNIX_HEX};Safari;${UUID}\n${plist}\n`;
    const persist = parseMacPersist("mac.txt", text).events.map((e) => asForensic(e as never, e.id));
    const out = linkQuarantineExecution([...persist, processStart("/Users/Shared/.a/agent", AFTER, "p1")]);
    const p = out.find((e) => e.description.startsWith("macOS persistence"))!;
    expect(p.description).toContain(`${RAN_MARKED_MARKER} Process start: /Users/Shared/.a/agent`);
    expect(out.find((e) => e.id === "p1")!.description).toContain(MARKED_FILE_MARKER);
  });

  it("is recomputed on every pass and bounded", () => {
    const many = Array.from({ length: 12 }, (_, i) => processStart(PATH, AFTER, `p${i}`));
    const once = linkQuarantineExecution([attrRow(), ...many]);
    const a = once.find((e) => e.id === "attr1")!;
    expect(a.description).toContain("+4 more");
    const twice = linkQuarantineExecution(once);
    expect(twice.map((e) => e.description)).toEqual(once.map((e) => e.description));
  });
});
