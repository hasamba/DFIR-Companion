import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { loadFilteredState } from "../../src/reports/filteredState.js";
import { normalizeReportTemplate, REPORT_SECTION_DEFS } from "../../src/reports/reportTemplate.js";

// #930 item 6: real Windows records through the importer → the chain over the route → the
// report section, off unless opted in.

const elastic = (...sources: object[]) =>
  JSON.stringify({ data: sources.map((s) => ({ _index: "win", _type: "winevtx", _source: s })) });

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-kerb-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const state = emptyState("c1");
  const parsed = parseSiemExport(
    elastic(
      {
        "@timestamp": "2026-06-01T00:00:00Z",
        log_name: "Security",
        computer_name: "FS01.corp.local",
        event_id: 4624,
        event_data: {
          TargetDomainName: "CORP",
          TargetUserName: "backupop",
          LogonType: "3",
          IpAddress: "10.0.0.5",
        },
      },
      {
        "@timestamp": "2026-06-01T10:00:00Z",
        log_name: "Security",
        computer_name: "DC01.corp.local",
        event_id: 4769,
        event_data: {
          TargetUserName: "attacker@CORP.LOCAL",
          TargetDomainName: "CORP.LOCAL",
          ServiceName: "svc_sql",
          TicketEncryptionType: "0x17",
          Status: "0x0",
          IpAddress: "::ffff:10.0.0.66",
        },
      },
      {
        "@timestamp": "2026-06-01T12:00:00Z",
        log_name: "Security",
        computer_name: "FS01.corp.local",
        event_id: 4624,
        event_data: {
          TargetDomainName: "CORP",
          TargetUserName: "svc_sql",
          TargetUserSid: "S-1-5-21-1-2-3-1105",
          LogonType: "3",
          IpAddress: "10.0.0.66",
        },
      },
    ),
  );
  state.forensicTimeline = parsed.events.map((e, i) => ({
    ...e,
    id: `e${i}`,
    mitreTechniques: e.mitre ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
  await stateStore.save(state);
  const app = createApp(store, { stateStore });
  return { app, store, stateStore };
}

describe("kerberoast chain route + report", () => {
  it("serves the chain from the importer's own envelope; the report section is off unless opted in", async () => {
    const { app, store, stateStore } = await harness();
    const res = await request(app).get("/cases/c1/kerberoast-chain");
    expect(res.status).toBe(200);
    expect(res.body.accounts).toHaveLength(1);
    const a = res.body.accounts[0];
    expect(a).toMatchObject({ service: "svc_sql", realm: "corp.local", stage: "first-seen-host-use" });
    expect(a.uses[0]).toMatchObject({
      eventId: "e2",
      kind: "logon",
      account: "CORP\\svc_sql",
      sid: "S-1-5-21-1-2-3-1105",
      placement: "after",
      firstSeenHost: true,
      sameObservedAddress: { requestAddress: "10.0.0.66", useAddress: "10.0.0.66" },
    });
    const filtered = await loadFilteredState({ state: stateStore, cases: store }, "c1");
    const only = normalizeReportTemplate({
      sections: REPORT_SECTION_DEFS.map((d) => ({ key: d.key, enabled: d.key === "kerberoastChain" })),
    });
    const md = renderMarkdownReport(filtered, undefined, undefined, undefined, undefined, undefined, only);
    expect(md).toContain("## Kerberoast chain");
    expect(md).toContain("first-seen-host-use");
    expect(md).toContain("whether it was cracked is not observable");
    const saved = normalizeReportTemplate({
      sections: REPORT_SECTION_DEFS.filter((d) => d.key !== "kerberoastChain").map((d) => ({
        key: d.key,
        enabled: true,
      })),
    });
    expect(
      renderMarkdownReport(filtered, undefined, undefined, undefined, undefined, undefined, saved),
    ).not.toContain("## Kerberoast chain");
  });
});
