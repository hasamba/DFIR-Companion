import { describe, it, expect } from "vitest";
import { adapterForUrl, adapterById, ADAPTERS } from "../src/adapters/registry.js";
import { splunkAdapter } from "../src/adapters/splunk.js";
import { velociraptorAdapter, velociraptorSourceLabel } from "../src/adapters/velociraptor.js";
import { elasticAdapter } from "../src/adapters/elastic.js";
import { crowdstrikeAdapter } from "../src/adapters/crowdstrike.js";
import { parseResponseBodies } from "../src/adapters/extractUtils.js";

describe("adapterForUrl", () => {
  it("matches Splunk by host, app path, and :8000", () => {
    expect(adapterForUrl("https://splunk.corp.local/en-US/app/search/search")?.id).toBe("splunk");
    expect(adapterForUrl("https://siem.example.com/en-US/app/search/search")?.id).toBe("splunk");
    expect(adapterForUrl("http://10.0.0.5:8000/en-US/app/search/search")?.id).toBe("splunk");
  });

  it("matches Velociraptor by host, /app/index.html, and :8889", () => {
    expect(adapterForUrl("https://velociraptor.corp:8889/app/index.html")?.id).toBe("velociraptor");
    expect(adapterForUrl("https://ir.example.com/app/index.html#/host")?.id).toBe("velociraptor");
    expect(adapterForUrl("https://10.0.0.9:8889/api/v1/GetTable")?.id).toBe("velociraptor");
  });

  it("matches Elastic/Kibana by host, app path, and :5601/:9200", () => {
    expect(adapterForUrl("https://kibana.corp/app/discover")?.id).toBe("elastic");
    expect(adapterForUrl("https://logs.example.com/app/security/alerts")?.id).toBe("elastic");
    expect(adapterForUrl("http://10.0.0.3:5601/app/discover")?.id).toBe("elastic");
    expect(adapterForUrl("http://10.0.0.3:9200/myindex/_search")?.id).toBe("elastic");
  });

  it("matches CrowdStrike Falcon by host", () => {
    expect(adapterForUrl("https://falcon.crowdstrike.com/activity/detections")?.id).toBe("crowdstrike");
    expect(adapterForUrl("https://falcon.us-2.crowdstrike.com/investigate")?.id).toBe("crowdstrike");
  });

  it("returns null for unrecognized sites and non-http schemes", () => {
    expect(adapterForUrl("https://example.com/foo")).toBeNull();
    expect(adapterForUrl("https://news.ycombinator.com/")).toBeNull();
    expect(adapterForUrl("chrome://extensions")).toBeNull();
    expect(adapterForUrl("not a url")).toBeNull();
  });

  it("adapterById resolves and the registry holds the four tools", () => {
    expect(ADAPTERS.map((a) => a.id).sort()).toEqual(["crowdstrike", "elastic", "splunk", "velociraptor"]);
    expect(adapterById("splunk")?.label).toBe("Splunk");
    expect(adapterById("nope")).toBeNull();
  });
});

describe("splunk.extractRows", () => {
  it("returns the results array from the json envelope", () => {
    const body = { preview: false, init_offset: 0, results: [{ _time: "t1", host: "h1" }, { _time: "t2", host: "h2" }], fields: [] };
    expect(splunkAdapter.extractRows("/services/search/v2/jobs/x/results", body)).toEqual(body.results);
  });

  it("zips the json_rows variant (fields + rows)", () => {
    const body = { fields: [{ name: "host" }, { name: "count" }], rows: [["h1", "3"], ["h2", "5"]] };
    expect(splunkAdapter.extractRows("u", body)).toEqual([{ host: "h1", count: "3" }, { host: "h2", count: "5" }]);
  });

  it("returns null when there are no results", () => {
    expect(splunkAdapter.extractRows("u", { preview: true, results: [] })).toBeNull();
    expect(splunkAdapter.extractRows("u", "nope")).toBeNull();
  });
});

describe("velociraptor.extractRows", () => {
  it("zips columns onto { cell: [...] } rows (GetTable shape)", () => {
    const body = { columns: ["Name", "Pid"], rows: [{ cell: ["svchost.exe", "1234"] }, { cell: ["cmd.exe", "5678"] }] };
    expect(velociraptorAdapter.extractRows("/api/v1/GetTable", body)).toEqual([
      { Name: "svchost.exe", Pid: "1234" },
      { Name: "cmd.exe", Pid: "5678" },
    ]);
  });

  it("zips columns onto raw-array rows", () => {
    const body = { columns: ["A", "B"], rows: [["1", "2"]] };
    expect(velociraptorAdapter.extractRows("u", body)).toEqual([{ A: "1", B: "2" }]);
  });

  it("parses the GUI GetTable { json: '[...]' } cell format and zips it", () => {
    const body = {
      columns: ["EventTime", "Computer", "EventID", "Message"],
      rows: [{ json: '["2026-06-03T07:56:13Z","WIN11.windomain.local",4103,"CommandInvocation(Out-Default)"]' }],
    };
    expect(velociraptorAdapter.extractRows("/api/v1/GetTable", body)).toEqual([
      { EventTime: "2026-06-03T07:56:13Z", Computer: "WIN11.windomain.local", EventID: 4103, Message: "CommandInvocation(Out-Default)" },
    ]);
  });

  it("un-flattens dotted GUI column names into nested objects (Detection.Name)", () => {
    const body = {
      columns: ["EventTime", "Detection.Name", "EventID"],
      rows: [{ json: '["2026-06-03T08:28:58Z","T1567.002-Execution of Exfiltration Programs",4688]' }],
    };
    expect(velociraptorAdapter.extractRows("/api/v1/GetTable", body)).toEqual([
      { EventTime: "2026-06-03T08:28:58Z", Detection: { Name: "T1567.002-Execution of Exfiltration Programs" }, EventID: 4688 },
    ]);
  });

  it("passes a bare array through", () => {
    expect(velociraptorAdapter.extractRows("u", [{ x: 1 }])).toEqual([{ x: 1 }]);
  });

  it("skips GUI-internal tables (notebook selector + column value-count facet)", () => {
    // Velociraptor renders these through GetTable too — they must not shadow the results grid.
    const notebookList = {
      columns: ["NotebookId", "Name", "Collaborators"],
      rows: [{ json: '["N.ABC","hayabusa",null]' }, { json: '["N.DEF","Notebook",null]' }],
    };
    expect(velociraptorAdapter.extractRows("/api/v1/GetTable", notebookList)).toBeNull();
    expect(velociraptorAdapter.extractRows("u", [{ NotebookId: "N.ABC", Name: "x" }])).toBeNull();
    // Column value-count facet: { value, idx, c }.
    expect(velociraptorAdapter.extractRows("u", [
      { value: "Windows Defender Threat Detected", idx: 0, c: 4 },
      { value: "Proc Access (Sysmon Alert)", idx: 78, c: 1775 },
    ])).toBeNull();
    // A real artifact row that merely has a "value" column among many others is NOT skipped.
    expect(velociraptorAdapter.extractRows("u", [
      { EventTime: "2026-06-03T08:06:56Z", Computer: "WIN11", value: "x", Message: "m" },
    ])).toEqual([{ EventTime: "2026-06-03T08:06:56Z", Computer: "WIN11", value: "x", Message: "m" }]);
    // Flow / collection list (the "collected artifacts" table always shown above a flow's results).
    expect(velociraptorAdapter.extractRows("/api/v1/GetTable", {
      columns: ["State", "FlowId", "Artifacts", "Rows"],
      rows: [{ json: '["ERROR","F.D8M0V5UIO64QE.H",["Windows.Detection.Malfind"],17345]' }],
    })).toBeNull();
    expect(velociraptorAdapter.extractRows("u", [{ HuntId: "H.123", artifacts: ["X"] }])).toBeNull();
  });

  it("returns null on an unrecognized shape", () => {
    expect(velociraptorAdapter.extractRows("u", { foo: "bar" })).toBeNull();
  });
});

describe("velociraptorSourceLabel", () => {
  it("prefers the GetTable artifact= param (results tab)", () => {
    expect(velociraptorSourceLabel({ apiUrl: "/api/v1/GetTable?flow_id=F.1&artifact=Windows.Hayabusa.Rules&rows=10" }))
      .toBe("Windows.Hayabusa.Rules");
  });
  it("falls back to a row's _Source (notebook VQL)", () => {
    expect(velociraptorSourceLabel({ rows: [{ _Source: "Custom.MyHunt", x: 1 }] })).toBe("Custom.MyHunt");
  });
  it("reads the combo-box artifact from the page's <select>/<input> values (results tab, no param)", () => {
    expect(velociraptorSourceLabel({ domInputs: ["Search clients", "10", "DetectRaptor.Windows.Detection.Applications"] }))
      .toBe("DetectRaptor.Windows.Detection.Applications");
  });
  it("accepts artifact names containing a / source separator", () => {
    expect(velociraptorSourceLabel({ domInputs: ["Windows.Network.NetstatEnriched/Netstat"] }))
      .toBe("Windows.Network.NetstatEnriched/Netstat");
    expect(velociraptorSourceLabel({ domInputs: ["Custom.DFIR.RDPLateralMovementDetection/ExplicitCredentialLogons"] }))
      .toBe("Custom.DFIR.RDPLateralMovementDetection/ExplicitCredentialLogons");
  });
  it("reads the artifact from a unique notebook-cell heading (notebook tab)", () => {
    expect(velociraptorSourceLabel({
      pageUrl: "https://h:5888/app/index.html?org_id=root#/notebooks/N.ABC",
      domHeadings: ["DetectRaptor.Windows.Detection.Evtx"],
    })).toBe("DetectRaptor.Windows.Detection.Evtx");
  });
  it("falls back to the notebook id when no heading, or headings are ambiguous", () => {
    expect(velociraptorSourceLabel({ pageUrl: "https://h:5888/app/index.html?org_id=root#/fullscreen/notebooks/N.D8G0LA8MEASII" }))
      .toBe("notebook N.D8G0LA8MEASII");
    // Two different artifact headings → ambiguous → notebook id, not a guess.
    expect(velociraptorSourceLabel({
      pageUrl: "https://h/#/notebooks/N.XYZ",
      domHeadings: ["DetectRaptor.Windows.Detection.Evtx", "Windows.Hayabusa.Rules"],
    })).toBe("notebook N.XYZ");
  });
  it("returns empty when nothing identifies the source", () => {
    expect(velociraptorSourceLabel({ domInputs: ["Search clients", "10"], pageUrl: "https://h/#/collected/C.x/F.y/results" })).toBe("");
  });

  it("is wired onto the adapter (adapter.sourceLabel is used by the content script)", () => {
    expect(typeof velociraptorAdapter.sourceLabel).toBe("function");
    expect(velociraptorAdapter.sourceLabel!({
      apiUrl: "", pageUrl: "https://h/app/index.html?org_id=root#/notebooks/N.ABC", domInputs: [], domHeadings: [], rows: [],
    })).toBe("notebook N.ABC");
  });
});

describe("elastic.extractRows", () => {
  it("flattens hits.hits to _source with id/index metadata", () => {
    const body = { hits: { hits: [{ _id: "1", _index: "logs", _source: { msg: "a" } }] } };
    expect(elasticAdapter.extractRows("/logs/_search", body)).toEqual([{ _id: "1", _index: "logs", msg: "a" }]);
  });

  it("unwraps the Kibana bsearch rawResponse wrapper", () => {
    const body = { result: { rawResponse: { hits: { hits: [{ _id: "9", _source: { a: 1 } }] } } } };
    expect(elasticAdapter.extractRows("/internal/bsearch", body)).toEqual([{ _id: "9", _index: undefined, a: 1 }]);
  });

  it("returns null when there are no hits", () => {
    expect(elasticAdapter.extractRows("u", { hits: { hits: [] } })).toBeNull();
    expect(elasticAdapter.extractRows("u", { took: 5 })).toBeNull();
  });
});

describe("parseResponseBodies", () => {
  it("parses a single JSON document", () => {
    expect(parseResponseBodies('{"a":1}')).toEqual([{ a: 1 }]);
    expect(parseResponseBodies('[1,2,3]')).toEqual([[1, 2, 3]]);
  });

  it("parses streamed NDJSON (one object per line — Kibana bsearch)", () => {
    const ndjson = '{"id":0,"result":{"rawResponse":{"hits":{"hits":[{"_id":"1","_source":{"a":1}}]}}}}\n'
      + '{"id":1,"result":{"rawResponse":{"hits":{"hits":[{"_id":"2","_source":{"a":2}}]}}}}';
    const bodies = parseResponseBodies(ndjson);
    expect(bodies).toHaveLength(2);
    expect((bodies[0] as { id: number }).id).toBe(0);
    expect((bodies[1] as { id: number }).id).toBe(1);
  });

  it("skips blank and non-JSON lines, returns [] for empty input", () => {
    expect(parseResponseBodies("")).toEqual([]);
    expect(parseResponseBodies("   \n  ")).toEqual([]);
    expect(parseResponseBodies('not json\n{"a":1}\n\nalso not json')).toEqual([{ a: 1 }]);
  });

  it("end-to-end: NDJSON bsearch bodies accumulate rows through elastic.extractRows", () => {
    // Mirrors what the content script does: parse the captured body, then run extractRows per object.
    const ndjson = '{"id":0,"result":{"rawResponse":{"hits":{"hits":[{"_id":"1","_index":"logs","_source":{"msg":"a"}}]}}}}\n'
      + '{"id":1,"result":{"rawResponse":{"hits":{"hits":[{"_id":"2","_index":"logs","_source":{"msg":"b"}}]}}}}';
    const rows = parseResponseBodies(ndjson).flatMap((b) => elasticAdapter.extractRows("/internal/bsearch", b) ?? []);
    expect(rows).toEqual([
      { _id: "1", _index: "logs", msg: "a" },
      { _id: "2", _index: "logs", msg: "b" },
    ]);
  });
});

describe("crowdstrike.extractRows", () => {
  it("returns the events array", () => {
    const body = { events: [{ id: "e1" }, { id: "e2" }] };
    expect(crowdstrikeAdapter.extractRows("/loggingapi/x", body)).toEqual(body.events);
  });

  it("returns resources when they are objects, not an id-list", () => {
    expect(crowdstrikeAdapter.extractRows("/detects/v2", { resources: [{ detection_id: "d1" }] })).toEqual([{ detection_id: "d1" }]);
    expect(crowdstrikeAdapter.extractRows("/detects/v1/queries", { resources: ["id1", "id2"] })).toBeNull();
  });

  it("returns null with no rows", () => {
    expect(crowdstrikeAdapter.extractRows("u", { meta: {}, errors: [] })).toBeNull();
  });
});
