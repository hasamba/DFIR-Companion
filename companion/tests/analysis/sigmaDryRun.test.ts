// Dry-run a pasted Sigma rule against the case's stored events (#2211). Pure: a fake page source
// stands in for the two timelines. The analyst must never see a silent "0 matches" for a rule the
// stored events cannot answer.
import { describe, expect, it } from "vitest";
import {
  SIGMA_DRY_RUN_SAMPLE_IDS,
  dryRunSigma,
  dryRunSigmaText,
  type SigmaDryRunDone,
} from "../../src/analysis/sigmaDryRun.js";
import type { HuntEventSource, HuntSourceRequest } from "../../src/analysis/huntQueryExecutor.js";
import type { HuntDataset } from "../../src/analysis/huntQueryTypes.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { parseSigmaRule } from "../../src/analysis/sigmaRule.js";
import { CANONICAL_EVENT_SCHEMA_VERSION, upgradeForensicEvent } from "../../src/analysis/canonicalEvent.js";

const ev = (id: string, over: Record<string, unknown> = {}): ForensicEvent =>
  ({
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description: "d",
    severity: "Info",
    sources: [],
    ...over,
  }) as unknown as ForensicEvent;

const env = (category: string, body: Record<string, unknown> = {}) => ({
  schemaVersion: CANONICAL_EVENT_SCHEMA_VERSION,
  event: { category, type: "observation" },
  ...body,
});

// Sysmon EID 1 normalizes the full image path and the parent's.
const sysmon = (id: string, image: string, cmd: string, parentExe?: string) =>
  ev(id, {
    canonical: env("process", {
      process: {
        name: image.split("\\").pop(),
        executable: image,
        commandLine: cmd,
        ...(parentExe ? { parent: { executable: parentExe, name: parentExe.split("\\").pop() } } : {}),
      },
    }),
  });

// The real stores upgrade every row they hand out (stateStore / superTimelineStore), so the fake does.
// A 4688-shaped legacy row: only the flat fields, and a bare parent NAME.
const legacy4688 = (id: string, image: string, cmd: string) =>
  ev(id, { path: image, commandLine: cmd, processName: image.split("\\").pop(), parentName: "cmd.exe" });

class FakeSource implements HuntEventSource {
  reads: HuntSourceRequest[] = [];
  constructor(private readonly data: Partial<Record<HuntDataset, ForensicEvent[]>>) {}
  async readPage(r: HuntSourceRequest) {
    this.reads.push(r);
    const all = this.data[r.dataset] ?? [];
    const start = r.cursor ?? 0;
    const events = all.slice(start, start + r.limit).map(upgradeForensicEvent);
    const next = start + r.limit < all.length ? start + r.limit : null;
    return { events, nextCursor: next };
  }
}

const RULE = `
title: Certutil download
logsource: { category: process_creation, product: windows }
detection:
  sel:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: sel
`;

async function run(text: string, data: Partial<Record<HuntDataset, ForensicEvent[]>>, extra = {}) {
  const source = new FakeSource(data);
  const out = await dryRunSigmaText(text, source, {
    caseId: "c1",
    datasets: Object.keys(data) as HuntDataset[],
    ...extra,
  });
  return { out, source };
}

function done(out: Awaited<ReturnType<typeof dryRunSigmaText>>): SigmaDryRunDone {
  if (!out.ok) throw new Error(JSON.stringify(out.refusals));
  return out;
}

describe("dryRunSigma — what the rule would match in this case", () => {
  it("matches a Sysmon-shaped and a 4688-shaped event alike, and counts only the rule's category", async () => {
    const { out } = await run(RULE, {
      forensic: [
        sysmon("s1", "C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -f http://x.example.com/a"),
        legacy4688("l1", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split"),
        sysmon("s2", "C:\\Windows\\System32\\notepad.exe", "notepad"),
        ev("n1", { canonical: env("network", { network: { destination: { address: "198.51.100.1" } } }) }),
      ],
    });
    const r = done(out);
    expect(r.scanned).toBe(4);
    expect(r.eligible).toBe(3);
    expect(r.matched).toBe(2);
    expect(r.sampleIds.sort()).toEqual(["l1", "s1"]);
    expect(r.eventCategory).toBe("process");
    expect(r.truncated).toBe(false);
  });

  it("reports how many eligible events carry EVERY field the rule reads", async () => {
    const { out } = await run(RULE, {
      forensic: [
        sysmon("s1", "C:\\x\\certutil.exe", "certutil -urlcache"),
        ev("p1", { canonical: env("process", { process: { name: "a.exe", executable: "C:\\a.exe" } }) }),
      ],
    });
    const r = done(out);
    expect(r.fields).toEqual([
      { field: "Image", storedAs: "process.executable", checkable: true, carried: 2 },
      { field: "CommandLine", storedAs: "process.command_line", checkable: true, carried: 1 },
    ]);
  });

  it("reports ParentImage as carried by no event when the rows keep only a bare parent name", async () => {
    const rule = RULE.replace("CommandLine|contains: 'urlcache'", "ParentImage|endswith: '\\cmd.exe'");
    const { out } = await run(rule, {
      forensic: [legacy4688("l1", "C:\\Windows\\System32\\certutil.exe", "certutil")],
    });
    const r = done(out);
    expect(r.matched).toBe(0);
    expect(r.fields.find((f) => f.field === "ParentImage")).toEqual({
      field: "ParentImage",
      storedAs: "process.parent.executable",
      checkable: true,
      carried: 0,
    });
  });

  it("names a field the stored events do not keep as not checkable, and never counts an undecided row", async () => {
    const rule = `
title: t
logsource: { category: process_creation }
detection:
  sel:
    Image|endswith: '\\certutil.exe'
  filter:
    OriginalFileName: 'CertUtil.exe'
  condition: sel and not filter
`;
    const { out } = await run(rule, {
      forensic: [sysmon("s1", "C:\\x\\certutil.exe", "certutil"), sysmon("s2", "C:\\x\\a.exe", "a")],
    });
    const r = done(out);
    expect(r.matched).toBe(0);
    expect(r.undecided).toBe(1);
    expect(r.fields).toContainEqual({ field: "OriginalFileName", checkable: false, carried: 0 });
  });

  it("still counts a definite match through an OR whose other branch is not checkable", async () => {
    const rule = `
title: t
logsource: { category: process_creation }
detection:
  a:
    Image|endswith: '\\certutil.exe'
  b:
    OriginalFileName: 'CertUtil.exe'
  condition: a or b
`;
    const { out } = await run(rule, { forensic: [sysmon("s1", "C:\\x\\certutil.exe", "c")] });
    const r = done(out);
    expect(r.matched).toBe(1);
    expect(r.undecided).toBe(0);
  });

  it("does not read a file event's path as the Image of a file_event rule", async () => {
    const rule = `
title: t
logsource: { category: file_event }
detection:
  sel:
    Image|contains: 'temp'
  condition: sel
`;
    const { out } = await run(rule, {
      forensic: [ev("f1", { path: "C:\\temp\\x.txt", sha256: "a".repeat(64) })],
    });
    const r = done(out);
    expect(r.eligible).toBe(1);
    expect(r.matched).toBe(0);
    expect(r.fields).toEqual([
      { field: "Image", storedAs: "process.executable", checkable: true, carried: 0 },
    ]);
  });

  it("maps the network, file and registry fields", async () => {
    const net = `
title: n
logsource: { category: network_connection }
detection:
  sel:
    DestinationIp|cidr: '198.51.100.0/24'
    DestinationPort: 443
  condition: sel
`;
    const netR = done(
      (
        await run(net, {
          forensic: [
            ev("n1", {
              canonical: env("network", { network: { destination: { address: "198.51.100.9", port: 443 } } }),
            }),
            ev("n2", {
              canonical: env("network", { network: { destination: { address: "203.0.113.9", port: 443 } } }),
            }),
          ],
        })
      ).out,
    );
    expect(netR.matched).toBe(1);
    expect(netR.sampleIds).toEqual(["n1"]);

    const file = `
title: f
logsource: { category: file_event }
detection:
  sel:
    TargetFilename|endswith: '.ps1'
  condition: sel
`;
    const fileR = done((await run(file, { forensic: [ev("f1", { path: "C:\\Windows\\Temp\\a.ps1" })] })).out);
    expect(fileR.matched).toBe(1);

    const reg = `
title: r
logsource: { category: registry_set }
detection:
  sel:
    TargetObject|contains: '\\CurrentVersion\\Run'
    Details|contains: 'evil'
  condition: sel
`;
    const regR = done(
      (
        await run(reg, {
          forensic: [
            ev("r1", {
              canonical: env("registry", {
                registry: {
                  key: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                  valueData: "C:\\evil.exe",
                },
              }),
            }),
          ],
        })
      ).out,
    );
    expect(regR.matched).toBe(1);
  });

  it("dedupes an event held in both timelines, and scans the super-timeline too", async () => {
    const hit = sysmon("s1", "C:\\x\\certutil.exe", "certutil -urlcache");
    const { out } = await run(RULE, {
      forensic: [hit],
      super: [hit, sysmon("raw", "C:\\x\\certutil.exe", "certutil -urlcache -f")],
    });
    const r = done(out);
    expect(r.scanned).toBe(2);
    expect(r.matched).toBe(2);
    expect(r.datasets).toEqual(["forensic", "super"]);
  });

  it("stops at the row cap and says so", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => sysmon(`s${i}`, "C:\\x\\certutil.exe", "urlcache"));
    const { out, source } = await run(RULE, { forensic: rows }, { maxRows: 10, pageSize: 4 });
    const r = done(out);
    expect(r.truncated).toBe(true);
    expect(r.scanned).toBe(10);
    expect(r.matched).toBe(10);
    expect(r.maxRows).toBe(10);
    expect(source.reads.every((q) => q.limit <= 4)).toBe(true);
  });

  it("keeps at most the sample cap of matched ids", async () => {
    const rows = Array.from({ length: 50 }, (_, i) => sysmon(`s${i}`, "C:\\x\\certutil.exe", "urlcache"));
    const r = done((await run(RULE, { forensic: rows })).out);
    expect(r.matched).toBe(50);
    expect(r.sampleIds).toHaveLength(SIGMA_DRY_RUN_SAMPLE_IDS);
  });

  it("refuses a category it cannot map, and a keyword list, by name, without scanning", async () => {
    const img = await run(RULE.replace("process_creation", "image_load"), { forensic: [] });
    expect(img.out.ok).toBe(false);
    if (!img.out.ok) expect(img.out.refusals[0]).toMatchObject({ path: "logsource.category" });
    expect(img.source.reads).toHaveLength(0);

    const kw = `
title: k
logsource: { category: process_creation }
detection:
  keywords:
    - 'mimikatz'
  condition: keywords
`;
    const k = await run(kw, { forensic: [sysmon("s1", "C:\\mimikatz.exe", "mimikatz")] });
    expect(k.out.ok).toBe(false);
    if (!k.out.ok) expect(k.out.refusals[0]).toMatchObject({ path: "detection.keywords" });
    expect(k.source.reads).toHaveLength(0);
  });

  it("passes parse refusals through", async () => {
    const { out } = await run("title: [unclosed\n", { forensic: [] });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.refusals[0].path).toBe("yaml");
  });

  it("stops when the caller aborts", async () => {
    const parsed = parseSigmaRule(RULE);
    if (!parsed.ok) throw new Error("parse");
    const controller = new AbortController();
    controller.abort();
    await expect(
      dryRunSigma(parsed.rule, new FakeSource({ forensic: [sysmon("s1", "C:\\certutil.exe", "x")] }), {
        caseId: "c1",
        datasets: ["forensic"],
        signal: controller.signal,
      }),
    ).rejects.toThrow(/abort/i);
  });
});
