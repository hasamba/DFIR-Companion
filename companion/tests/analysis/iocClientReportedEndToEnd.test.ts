// #1266, end to end: an .eml's X-Originating-IP is the ONE client-reported IOC extraction site.
// Its marker must survive the real import seam (platformImports.ts's own field-whitelisting delta
// builder — which used to drop it silently while every unit test still passed), mergeDelta, and
// a save/load round-trip, and it must then be honoured by the acting block-list. A later
// deterministic, event-linked sighting of the same value clears it through the same real path.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { buildIocBlocklistStix, buildIocBlocklistTxt } from "../../src/reports/iocBlocklist.js";

const ORIGIN = "198.51.100.23";

const eml = [
  "Return-Path: <bounce@evil.example>",
  `Received: from mx.evil.example (mx.evil.example [203.0.113.7]) by mail.victim.com with ESMTP; Tue, 01 Dec 2017 08:00:00 +0000`,
  "From: PayPal Support <service@evil.example>",
  "To: victim@victim.com",
  "Subject: Urgent: Account Locked",
  "Date: Tue, 01 Dec 2017 08:00:00 +0000",
  "Message-ID: <deadbeef@evil.example>",
  `X-Originating-IP: [${ORIGIN}]`,
  "MIME-Version: 1.0",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Please log in at http://phish.evil.example/login to unlock your account.",
  "",
].join("\r\n");

// A Zeek conn row whose own observed peer is the same address: an event-linked ordinary sighting.
const zeekConn = JSON.stringify({
  _path: "conn",
  ts: 1512115200.0,
  uid: "CjVwXY1",
  "id.orig_h": ORIGIN,
  "id.orig_p": 51234,
  "id.resp_h": "10.0.0.5",
  "id.resp_p": 443,
  proto: "tcp",
  conn_state: "SF",
  orig_bytes: 1200,
  resp_bytes: 3400,
});

let stateStore: StateStore;
let pipeline: AnalysisPipeline;

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-1266-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore: new SuperTimelineStore(cases),
    stateLock: new StateLock(),
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
});

describe("client-reported IOC provenance, end to end (#1266)", () => {
  it("the marker survives import, merge and a save/load round-trip, and the block-list honours it", async () => {
    await pipeline.importEmail("c1", eml, {
      label: "lure.eml",
      idPrefix: "em1",
      importedAt: "2026-09-10T11:00:00Z",
    });
    const state = await stateStore.load("c1");
    const origin = state.iocs.find((i) => i.type === "ip" && i.value === ORIGIN);
    expect(origin?.provenance).toBe("client-reported");
    // Lure content from the same message stays unmarked.
    expect(state.iocs.find((i) => i.value === "phish.evil.example")?.provenance).toBeUndefined();

    const opts = { minSeverity: "Info" as const };
    expect(buildIocBlocklistTxt(state, opts)).not.toContain(ORIGIN);
    expect(JSON.stringify(buildIocBlocklistStix(state, opts))).not.toContain(ORIGIN);
    // and the unmarked lure domain IS on both, so the exclusion is specific, not a broken build
    expect(buildIocBlocklistTxt(state, opts)).toContain("phish.evil.example");
    expect(JSON.stringify(buildIocBlocklistStix(state, opts))).toContain("phish.evil.example");
  });

  it("a later event-linked ordinary sighting of the same address clears the marker through the real path", async () => {
    await pipeline.importEmail("c1", eml, {
      label: "lure.eml",
      idPrefix: "em1",
      importedAt: "2026-09-10T11:00:00Z",
    });
    expect((await stateStore.load("c1")).iocs.find((i) => i.value === ORIGIN)?.provenance).toBe(
      "client-reported",
    );
    await pipeline.importSiem("c1", zeekConn, {
      label: "conn.log",
      idPrefix: "z1",
      importedAt: "2026-09-10T11:01:00Z",
    });
    const after = await stateStore.load("c1");
    const hits = after.iocs.filter((i) => i.type === "ip" && i.value === ORIGIN);
    expect(hits).toHaveLength(1);
    expect(hits[0].provenance).toBeUndefined();
    expect(hits[0].extractedFrom?.length ?? 0).toBeGreaterThan(0);
  });
});
