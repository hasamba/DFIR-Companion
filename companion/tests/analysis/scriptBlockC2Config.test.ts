import { describe, it, expect } from "vitest";
import {
  scriptC2Config,
  renderScriptC2Tag,
  SCRIPT_C2_TAG_MAX,
} from "../../src/analysis/scriptBlockC2Config.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Hostnames are example.com-shaped; addresses are RFC 5737 documentation ranges.
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: p.timestamp ?? "2026-09-22T08:33:05Z",
    description: p.description ?? "Script block logged (EID 4104)",
    severity: p.severity ?? "High",
    asset: p.asset ?? "ws01.example.com",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const ISSUE_BLOCK = "$server='x.example.com'; $port=443; $uri='/submit.php'; $watermark=123456";

describe("scriptC2Config", () => {
  it("reads the issue's example: server, port, uri and watermark", () => {
    const c = scriptC2Config(ev({ message: ISSUE_BLOCK }));
    expect(c).not.toBeNull();
    expect(c!.entries.map((x) => `${x.key}=${x.value}`)).toEqual([
      "server=x.example.com",
      "port=443",
      "uri=/submit.php",
      "watermark=123456",
    ]);
    expect(c!.infrastructure).toEqual(["x.example.com"]);
  });

  it("reads the hashtable form", () => {
    const c = scriptC2Config(
      ev({ message: "$cfg = @{c2='203.0.113.9';port=8443;urls=@('/a','/b');sleep=60;jitter=20}" }),
    );
    expect(c).not.toBeNull();
    expect(c!.infrastructure).toEqual(["203.0.113.9"]);
    expect(c!.entries.map((x) => x.key)).toEqual(["c2", "port", "urls", "sleep", "jitter"]);
    expect(c!.entries.find((x) => x.key === "urls")!.value).toBe("/a, /b");
  });

  it("reads the real config shapes: domains/IPs arrays and the x86Get/post/spawnto keys", () => {
    const a = scriptC2Config(
      ev({
        message:
          "@{domains=@('cdn.example.com','img.example.net');IPs=@('198.51.100.7','127.0.0.1');port=443;sleep=62760;jitter=37;get='/_next.css';post='/boards';watermark=1357776117;actualConnections='127.0.0.1 only';beaconIncluded=$false}",
      }),
    );
    expect(a!.infrastructure).toEqual(["cdn.example.com", "img.example.net", "198.51.100.7"]);
    expect(a!.entries.map((x) => x.key)).toContain("watermark");
    const b = scriptC2Config(
      ev({
        message:
          "@{server='198.51.100.32';port=80;x86Get='/IE9CompatViewList.xml';x64Get='/visit.js';post='/submit.php';watermark=987654321;sleep=60000;spawnto='rundll32.exe'}",
      }),
    );
    expect(b!.infrastructure).toEqual(["198.51.100.32"]);
    expect(b!.entries.map((x) => x.key)).toEqual(
      expect.arrayContaining(["x86Get", "x64Get", "post", "spawnto"]),
    );
  });

  it("returns nothing for a port alone", () => {
    expect(scriptC2Config(ev({ message: "$port=443" }))).toBeNull();
  });

  it("returns nothing for Chocolatey's install script (url/uri/useragent never satisfy the beacon key)", () => {
    const choco = [
      "$url = ''",
      "$uri = [System.Uri]$url",
      "[string] $userAgent = 'chocolatey command line'",
      "$url = 'https://community.chocolatey.org/api/v2/package/chocolatey'",
      "$port = 443",
    ].join("\n");
    expect(scriptC2Config(ev({ message: choco }))).toBeNull();
  });

  it("returns nothing for an admin server + port with no beacon key", () => {
    expect(scriptC2Config(ev({ message: "$server='sql01.example.com'; $port=1433" }))).toBeNull();
  });

  it("returns nothing when the only infrastructure is loopback", () => {
    expect(scriptC2Config(ev({ message: "$server='127.0.0.1'; $port=443; $watermark=1" }))).toBeNull();
    expect(scriptC2Config(ev({ message: "$server='localhost'; $sleep=60" }))).toBeNull();
  });

  it("needs two config keys, not just one beacon key with infrastructure", () => {
    expect(scriptC2Config(ev({ message: "$c2='x.example.com'" }))).toBeNull();
  });

  it("returns nothing for the collector's own script blocks", () => {
    expect(scriptC2Config(ev({ message: ISSUE_BLOCK, origin: "collector" }))).toBeNull();
    expect(
      scriptC2Config(
        ev({
          message: ISSUE_BLOCK,
          description: "Script block logged (EID 4104) [DFIR collector footprint]",
        }),
      ),
    ).toBeNull();
  });

  it("returns nothing for a row that is not a script record", () => {
    expect(scriptC2Config(ev({ description: "Process created", message: ISSUE_BLOCK }))).toBeNull();
  });

  it("ignores variable references and property assignments", () => {
    expect(scriptC2Config(ev({ message: "$server=$args[0]; $obj.sleep=60; $port=443" }))).toBeNull();
  });

  it("cleans attacker values: no angle brackets, control chars or leading formula chars; capped; URL secrets redacted", () => {
    const c = scriptC2Config(
      ev({
        message: [
          "$server='x.example.com><script>alert(1)</script>'",
          "$uri='=cmd|calc'",
          // Assembled at runtime so no literal user:password URL sits in the source.
          `$urls=@("https://user:${"hunter2"}@cdn.example.com/a?sig=abc123&x=1")`,
          `$watermark='${"9".repeat(200)}'`,
          '$sleep="60\u0007\u0001"',
        ].join("\n"),
      }),
    )!;
    expect(c).not.toBeNull();
    for (const x of c.entries) {
      expect(x.value).not.toMatch(/[<>\u0000-\u001f]/u);
      expect(x.value.length).toBeLessThanOrEqual(61);
      expect(x.value.startsWith("=")).toBe(false);
    }
    const urls = c.entries.find((x) => x.key === "urls")!.value;
    expect(urls).not.toContain("hunter2");
    expect(urls).not.toContain("abc123");
    expect(urls).toContain("[redacted]");
  });
});

describe("renderScriptC2Tag", () => {
  it("renders one whole tag named for script content", () => {
    expect(renderScriptC2Tag(ev({ message: ISSUE_BLOCK }))).toBe(
      "<script-c2-config:server=x.example.com; port=443; uri=/submit.php; watermark=123456>",
    );
  });

  it("drops whole entries past the budget, keeping infrastructure and beacon keys", () => {
    const long = "/a/very/long/path/that/an/operator/would/never/shorten/x.css";
    const filler = ["url", "uri", "useragent", "get", "post", "x86Get", "x64Get", "maxGet"]
      .map((k) => `${k}='${long}'`)
      .join(";");
    const tag = renderScriptC2Tag(
      ev({ message: `@{${filler};server='x.example.com';watermark=42;port=443}` }),
    );
    expect(tag.length).toBeLessThanOrEqual(SCRIPT_C2_TAG_MAX);
    expect(tag).toContain("server=x.example.com");
    expect(tag).toContain("watermark=42");
    expect(tag.endsWith(">")).toBe(true);
  });

  it("is empty for a row with no config", () => {
    expect(renderScriptC2Tag(ev({ message: "$port=443" }))).toBe("");
  });
});
