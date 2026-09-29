import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

// #1779: the version diff names a report-text / Case Details change instead of "no differences".
// #1807: the block-list dialog shows how many IOCs match and why the rest are left out.
const read = (f: string) => readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
const VERSIONS = read("dashboard-report-versions.js");
const BLOCKLIST = read("dashboard-ioc-blocklist.js");

type Deferred = { url: string; resolve: (body: unknown, ok?: boolean) => void; reject: (e: Error) => void };

function harness(src: string, els: Record<string, Record<string, unknown>>) {
  const fetches: Deferred[] = [];
  const win: Record<string, unknown> = { addEventListener: () => {}, location: { href: "" } };
  const sandbox = {
    window: win,
    document: { getElementById: (id: string) => els[id] ?? null },
    fetch: (url: string) =>
      new Promise((res, rej) =>
        fetches.push({
          url,
          resolve: (body, ok = true) => res({ ok, status: ok ? 200 : 500, json: async () => body }),
          reject: rej,
        }),
      ),
    esc: (s: unknown) =>
      String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!),
    URLSearchParams,
    encodeURIComponent,
  };
  runInNewContext(src, sandbox);
  const fn = (name: string) => win[name] as (...a: unknown[]) => unknown;
  return { fetches, fn, els };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const noEvidence = {
  findings: { added: [], removed: [], severityChanged: [] },
  iocs: { added: [], removed: [] },
  timeline: { added: [], removed: [] },
};

function versionEls() {
  return {
    caseId: { value: "INC-1" },
    rvFrom: { value: "a" },
    rvTo: { value: "b" },
    rvDiffResult: { textContent: "", innerHTML: "" },
  } as Record<string, Record<string, unknown>>;
}

describe("report version diff (#1779)", () => {
  it("names the changed Case Details fields with labels", async () => {
    const h = harness(VERSIONS, versionEls());
    const done = h.fn("doReportVersionsDiff")();
    h.fetches[0].resolve({
      ...noEvidence,
      report: { textChanged: true, caseDetailsChanged: ["incidentId", "executiveSummary", "customKey<x>"] },
    });
    await done;
    const html = String(h.els.rvDiffResult.innerHTML);
    expect(html).toContain("Report text / Case Details changed:");
    expect(html).toContain("Incident ID, Executive summary, customKey&lt;x&gt;");
    expect(html).not.toContain("no finding");
  });

  it("says the report text changed when no Case Details field did", async () => {
    const h = harness(VERSIONS, versionEls());
    const done = h.fn("doReportVersionsDiff")();
    h.fetches[0].resolve({ ...noEvidence, report: { textChanged: true, caseDetailsChanged: [] } });
    await done;
    expect(String(h.els.rvDiffResult.innerHTML)).toContain("report text changed");
  });

  it("reworded empty state, and tolerates an older server without `report`", async () => {
    for (const body of [
      noEvidence,
      { ...noEvidence, report: { textChanged: false, caseDetailsChanged: [] } },
    ]) {
      const h = harness(VERSIONS, versionEls());
      const done = h.fn("doReportVersionsDiff")();
      h.fetches[0].resolve(body);
      await done;
      expect(String(h.els.rvDiffResult.innerHTML)).toBe(
        "no finding, IOC or timeline differences, and the report text is unchanged",
      );
    }
  });
});

function blocklistEls() {
  const listeners: Record<string, Array<() => void>> = {};
  const control = (id: string, extra: Record<string, unknown>) => ({
    ...extra,
    addEventListener: (type: string, cb: () => void) => {
      (listeners[`${id}:${type}`] ??= []).push(cb);
    },
  });
  const els: Record<string, Record<string, unknown>> = {
    caseId: { value: "INC-1" },
    iocBlocklistOverlay: { classList: { add: () => {}, remove: () => {} }, addEventListener: () => {} },
    blMinSev: control("blMinSev", { value: "Medium" }),
    blTypeIp: control("blTypeIp", { checked: true }),
    blTypeDomain: control("blTypeDomain", { checked: true }),
    blTypeUrl: control("blTypeUrl", { checked: false }),
    blTypeHash: control("blTypeHash", { checked: true }),
    blTypeEmail: control("blTypeEmail", { checked: false }),
    blVerdictOnly: control("blVerdictOnly", { checked: false }),
    blMatchCount: { textContent: "" },
    blDlTxt: {},
    blDlCsv: {},
    blDlStix: {},
    blCancel: {},
  };
  return {
    els,
    fire: (id: string, type = "change") => (listeners[`${id}:${type}`] ?? []).forEach((cb) => cb()),
  };
}

const summary = (matched: number, total: number, excluded: Record<string, number> = {}) => ({
  total,
  matched,
  excluded: {
    retired: 0,
    "client-reported": 0,
    "ineligible-type": 0,
    "no-actionable-intel": 0,
    "below-min-severity": 0,
    "not-verdict-confirmed": 0,
    ...excluded,
  },
});

describe("block-list dialog match count (#1807)", () => {
  it("fetches the summary with the download's filters when the dialog opens", async () => {
    const b = blocklistEls();
    const h = harness(BLOCKLIST, b.els);
    h.fn("initIocBlocklist")();
    h.fn("openIocBlocklist")();
    expect(h.fetches).toHaveLength(1);
    expect(h.fetches[0].url).toBe(
      "/cases/INC-1/export/ioc-blocklist?format=summary&minSeverity=Medium&types=ip%2Cdomain%2Chash",
    );
    h.fetches[0].resolve(
      summary(0, 5, { "no-actionable-intel": 3, "below-min-severity": 1, "ineligible-type": 1 }),
    );
    await settle();
    expect(b.els.blMatchCount.textContent).toBe(
      "Matches 0 of 5 IOCs — 1 below minimum severity, 3 with no usable threat-intel verdict, 1 ineligible or unselected type",
    );
  });

  it("refetches when a filter changes, and says only the count when nothing is excluded", async () => {
    const b = blocklistEls();
    const h = harness(BLOCKLIST, b.els);
    h.fn("initIocBlocklist")();
    b.els.blVerdictOnly.checked = true;
    b.fire("blVerdictOnly");
    expect(h.fetches[0].url).toContain("verdictOnly=true");
    h.fetches[0].resolve(summary(2, 2));
    await settle();
    expect(b.els.blMatchCount.textContent).toBe("Matches 2 of 2 IOCs");
    for (const id of ["blMinSev", "blTypeIp", "blTypeDomain", "blTypeUrl", "blTypeHash", "blTypeEmail"]) {
      b.fire(id);
    }
    expect(h.fetches).toHaveLength(7);
  });

  it("never lets a stale response overwrite a newer one", async () => {
    const b = blocklistEls();
    const h = harness(BLOCKLIST, b.els);
    h.fn("initIocBlocklist")();
    b.fire("blMinSev");
    b.fire("blMinSev");
    h.fetches[1].resolve(summary(4, 4));
    await settle();
    h.fetches[0].resolve(summary(1, 4, { "below-min-severity": 3 }));
    await settle();
    expect(b.els.blMatchCount.textContent).toBe("Matches 4 of 4 IOCs");
  });

  it("writes nothing misleading when the summary request fails", async () => {
    const b = blocklistEls();
    const h = harness(BLOCKLIST, b.els);
    h.fn("initIocBlocklist")();
    b.els.blMatchCount.textContent = "Matches 9 of 9 IOCs";
    b.fire("blMinSev");
    h.fetches[0].resolve({ error: "boom" }, false);
    await settle();
    expect(b.els.blMatchCount.textContent).toBe("");
  });
});
