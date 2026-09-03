import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { compileSigmaText } from "../../src/analysis/sigmaToVql.js";

// Rows a real Velociraptor returned for every compiled template (#802 item 1): server 0.77.2, one
// Windows 11 client, each rule launched through VelociraptorClient.launchHunt() — the path the
// dashboard's Sigma card uses — and read back per source with hunt_results(). The fixture holds the
// exact VQL that ran. A template change that alters that text fails the first test on purpose:
// sigmaVqlTemplates.ts admits a template only with a fixture proven against a live server, so
// re-prove the new text there and refresh the fixture rather than editing the string here.

type Row = Record<string, unknown>;
interface LiveHunt {
  huntId: string;
  rule: string;
  vql: string;
  snapshot: boolean;
  sources: Record<string, Row[]>;
}
interface LiveFixture {
  capturedAt: string;
  client: { os: string; agent: string };
  hunts: Record<string, LiveHunt>;
}

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/sigma-velociraptor-live.json", import.meta.url), "utf8"),
) as LiveFixture;
const HEX = /^[0-9a-f]+$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const hunt = (key: string): LiveHunt => {
  const h = fixture.hunts[key];
  if (!h) throw new Error(`fixture has no hunt ${key}`);
  return h;
};
const rows = (key: string, source = "Pivot0"): Row[] => {
  const r = hunt(key).sources[source];
  if (!r?.length) throw new Error(`fixture hunt ${key}/${source} has no rows`);
  return r;
};

describe("Sigma → VQL templates against rows from a live Velociraptor (#802)", () => {
  it("was captured from a Windows client on the agent version the templates target", () => {
    // Pinned on purpose: a re-proof on another version is a visible change here, not a silent one.
    expect(fixture.client.os).toBe("windows");
    expect(fixture.client.agent).toBe("0.77.2");
  });

  it("holds, for every hunt, exactly the VQL the current compiler emits for its rule", () => {
    for (const [key, h] of Object.entries(fixture.hunts)) {
      const r = compileSigmaText(h.rule);
      if (!r.ok) throw new Error(`${key}: ` + r.refusals.map((x) => `${x.path}: ${x.message}`).join("\n"));
      expect(r.vql, key).toBe(h.vql);
      expect(r.snapshot, key).toBe(h.snapshot);
    }
  });

  it("every row carries the hunt bookkeeping columns the importer keys on", () => {
    for (const h of Object.values(fixture.hunts))
      for (const source of Object.values(h.sources))
        for (const row of source) {
          expect(row.ClientId).toMatch(/^C\.[0-9a-f]+$/);
          expect(row.FlowId).toMatch(/^F\./);
          expect(typeof row.Fqdn).toBe("string");
        }
  });

  it("process: the ByPid lookup fills ParentImage/ParentCommandLine and hash() is an object with MD5, SHA1 and SHA256", () => {
    for (const row of rows("process")) {
      expect(row.Image).toMatch(/\\svchost\.exe$/i);
      expect(row.ParentImage).toMatch(/\\services\.exe$/i);
      expect(row.ParentCommandLine).toMatch(/services\.exe/i);
      expect(typeof row.Pid).toBe("number");
      expect(typeof row.Ppid).toBe("number");
      expect(typeof row.CommandLine).toBe("string");
      expect(typeof row.User).toBe("string");
      const hashes = row.Hashes as Record<string, string>;
      expect(hashes.MD5).toMatch(HEX);
      expect(hashes.MD5).toHaveLength(32);
      expect(hashes.SHA1).toMatch(HEX);
      expect(hashes.SHA1).toHaveLength(40);
      expect(hashes.SHA256).toMatch(HEX);
      expect(hashes.SHA256).toHaveLength(64);
    }
  });

  it("network: Raddr.IP/Raddr.Port land in DestinationIp/DestinationPort and the Pid lookup names the Image", () => {
    for (const row of rows("netPort")) {
      expect(row.DestinationIp).toMatch(IPV4);
      expect(row.SourceIp).toMatch(IPV4);
      expect(typeof row.DestinationPort).toBe("number");
      expect(row.DestinationPort as number).toBeGreaterThanOrEqual(1);
      expect(typeof row.SourcePort).toBe("number");
      expect(row.Image).toMatch(/\.exe$/i);
      expect(typeof row.Status).toBe("string");
    }
  });

  it("network: cidr_contains matched only a destination inside the given private ranges", () => {
    const matched = rows("netCidr");
    for (const row of matched)
      expect(row.DestinationIp).toMatch(/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/);
    // The port hunt on the same client saw a public destination too; cidr_contains left it out.
    const all = rows("netPort").map((r) => r.DestinationIp as string);
    expect(all.some((ip) => !/^(10\.|192\.168\.|172\.)/.test(ip))).toBe(true);
  });

  it("file: glob() returns the file under TargetFilename with Size and Mtime", () => {
    for (const row of rows("file")) {
      expect(row.TargetFilename).toMatch(/^C:\\Windows\\System32\\cmd\.exe$/i);
      expect(typeof row.Size).toBe("number");
      expect(row.Mtime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it("registry: TargetObject carries the full hive name and Details is the value's data", () => {
    for (const row of rows("registry")) {
      expect(row.TargetObject).toMatch(
        /^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion/i,
      );
      expect(row.Details).toMatch(/windows/i);
      expect(row.Mtime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it("mixed: one hunt carried a source per category, each read back by its own name with its own columns", () => {
    const h = hunt("mixed");
    expect(Object.keys(h.sources)).toEqual(["Pivot0", "Pivot1", "Pivot2"]);
    expect(h.vql.split(/\n\s*\n/)).toHaveLength(3);
    for (const row of rows("mixed", "Pivot0")) expect(row.Hashes).toBeTypeOf("object");
    // Pivot1 is the netstat source over 10.0.0.0/8; the client had no such connection, so it is
    // empty — the launcher still read it by name instead of reporting the whole artifact empty.
    expect(h.sources.Pivot1).toEqual([]);
    for (const row of rows("mixed", "Pivot2")) expect(row.TargetFilename).toMatch(/cmd\.exe$/i);
  });
});
