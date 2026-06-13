import { describe, it, expect } from "vitest";
import { parseTheHive } from "../../src/analysis/theHiveImport.js";

const j = (o: unknown): string => JSON.stringify(o);

// ── fixtures ──

function caseRecord(overrides: Record<string, unknown> = {}): object {
  return {
    _type: "case",
    _createdAt: 1706400000000,
    startDate: 1706403600000,
    title: "Ransomware on FS01",
    description: "File server encrypted; ransom note dropped",
    severity: 3,
    tlp: 2,
    pap: 1,
    tags: ["T1486", "attack.T1059.001", "ransomware"],
    assignee: "analyst1",
    ...overrides,
  };
}

function alertRecord(overrides: Record<string, unknown> = {}): object {
  return {
    _type: "alert",
    _createdAt: 1706400000000,
    title: "Suspicious login from TOR exit node",
    severity: 2,
    tlp: 1,
    tags: ["T1078"],
    ...overrides,
  };
}

function observableIp(overrides: Record<string, unknown> = {}): object {
  return { dataType: "ip", data: "185.220.101.5", ioc: true, ...overrides };
}
function observableDomain(overrides: Record<string, unknown> = {}): object {
  return { dataType: "domain", data: "evil.example.com", ioc: true, ...overrides };
}
function observableHash(overrides: Record<string, unknown> = {}): object {
  return { dataType: "hash", data: "d41d8cd98f00b204e9800998ecf8427e", ioc: true, ...overrides };
}
function observableUrl(overrides: Record<string, unknown> = {}): object {
  return { dataType: "url", data: "http://evil.example.com/payload.exe", ioc: true, ...overrides };
}
function observableFilename(overrides: Record<string, unknown> = {}): object {
  return { dataType: "filename", data: "ransom_note.txt", ioc: true, ...overrides };
}
function observableMail(overrides: Record<string, unknown> = {}): object {
  return { dataType: "mail", data: "phish@evil.example.com", ioc: true, ...overrides };
}

// ── case / alert mapping ──

describe("parseTheHive — case mapping", () => {
  it("maps severity 3 case as High", () => {
    const r = parseTheHive(j(caseRecord()));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
  });

  it("uses startDate (incident time) over _createdAt", () => {
    const r = parseTheHive(j(caseRecord()));
    const ts = r.events[0].timestamp;
    // startDate = 1706403600000 → 2024-01-28T01:00:00.000Z
    expect(ts).toContain("2024-01-28");
  });

  it("includes title in description", () => {
    const r = parseTheHive(j(caseRecord()));
    expect(r.events[0].description).toContain("Ransomware on FS01");
  });

  it("prepends TLP and PAP labels", () => {
    const r = parseTheHive(j(caseRecord()));
    expect(r.events[0].description).toContain("TLP:AMBER");
    expect(r.events[0].description).toContain("PAP:GREEN");
  });

  it("extracts MITRE technique IDs from tags", () => {
    const r = parseTheHive(j(caseRecord()));
    expect(r.events[0].mitreTechniques).toContain("T1486");
    expect(r.events[0].mitreTechniques).toContain("T1059.001");
    // non-technique tag is ignored
    expect(r.events[0].mitreTechniques).not.toContain("ransomware");
  });

  it("sets asset from assignee", () => {
    const r = parseTheHive(j(caseRecord()));
    expect(r.events[0].asset).toBe("analyst1");
  });

  it("tags source as TheHive", () => {
    const r = parseTheHive(j(caseRecord()));
    expect(r.events[0].sources).toContain("TheHive");
  });
});

describe("parseTheHive — severity mapping", () => {
  it("severity 1 → Info", () => {
    const r = parseTheHive(j(caseRecord({ severity: 1 })));
    expect(r.events[0].severity).toBe("Info");
  });
  it("severity 2 → Medium", () => {
    const r = parseTheHive(j(alertRecord({ severity: 2 })));
    expect(r.events[0].severity).toBe("Medium");
  });
  it("severity 3 → High", () => {
    const r = parseTheHive(j(caseRecord({ severity: 3 })));
    expect(r.events[0].severity).toBe("High");
  });
  it("severity 4 → Critical", () => {
    const r = parseTheHive(j(caseRecord({ severity: 4 })));
    expect(r.events[0].severity).toBe("Critical");
  });
});

describe("parseTheHive — alert mapping", () => {
  it("maps an alert record", () => {
    const r = parseTheHive(j(alertRecord()));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("TheHive Alert");
    expect(r.events[0].description).toContain("Suspicious login");
    expect(r.events[0].mitreTechniques).toContain("T1078");
  });
});

describe("parseTheHive — customFields appended", () => {
  it("appends custom field values to description", () => {
    const rec = caseRecord({
      customFields: {
        customer: { type: "string", value: "ACME Corp", order: 1 },
        impactScore: { type: "number", value: 9, order: 2 },
      },
    });
    const r = parseTheHive(j(rec));
    expect(r.events[0].description).toContain("ACME Corp");
    expect(r.events[0].description).toContain("9");
  });
});

// ── observable → IOC mapping ──

describe("parseTheHive — observables as IOCs", () => {
  it("maps ip observable to ip IOC", () => {
    const r = parseTheHive(j([observableIp()]));
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "185.220.101.5")).toBe(true);
  });
  it("maps domain observable to domain IOC", () => {
    const r = parseTheHive(j([observableDomain()]));
    expect(r.iocs.some((i) => i.type === "domain")).toBe(true);
  });
  it("maps fqdn to domain IOC", () => {
    const r = parseTheHive(j([{ dataType: "fqdn", data: "host.evil.com", ioc: true }]));
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "host.evil.com")).toBe(true);
  });
  it("maps hash observable to hash IOC", () => {
    const r = parseTheHive(j([observableHash()]));
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
  });
  it("maps url observable to url IOC", () => {
    const r = parseTheHive(j([observableUrl()]));
    expect(r.iocs.some((i) => i.type === "url")).toBe(true);
  });
  it("maps filename to file IOC", () => {
    const r = parseTheHive(j([observableFilename()]));
    expect(r.iocs.some((i) => i.type === "file" && i.value === "ransom_note.txt")).toBe(true);
  });
  it("maps mail to other IOC (no email type in SiemIoc)", () => {
    const r = parseTheHive(j([observableMail()]));
    expect(r.iocs.some((i) => i.type === "other" && i.value === "phish@evil.example.com")).toBe(true);
  });
  it("skips observables without ioc:true by default", () => {
    const r = parseTheHive(j([{ dataType: "ip", data: "10.0.0.1", ioc: false }]));
    expect(r.iocs).toHaveLength(0);
  });
  it("includes non-ioc observables when allObservables:true", () => {
    const r = parseTheHive(j([{ dataType: "ip", data: "10.0.0.1", ioc: false }]), { allObservables: true });
    expect(r.iocs.some((i) => i.type === "ip")).toBe(true);
  });
});

// ── container shapes ──

describe("parseTheHive — container shapes", () => {
  it("single object", () => {
    const r = parseTheHive(j(caseRecord()));
    expect(r.format).toBe("single");
    expect(r.total).toBe(1);
  });
  it("array of records", () => {
    const r = parseTheHive(j([caseRecord(), alertRecord()]));
    expect(r.format).toBe("array");
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(2);
  });
  it("search result container { data: [...] }", () => {
    const r = parseTheHive(j({ data: [caseRecord(), alertRecord()] }));
    expect(r.format).toBe("container");
    expect(r.total).toBe(2);
  });
  it("pure observables array → format=observables, no events", () => {
    const r = parseTheHive(j([observableIp(), observableDomain()]));
    expect(r.format).toBe("observables");
    expect(r.events).toHaveLength(0);
    expect(r.observables).toBe(2);
    expect(r.iocs.length).toBeGreaterThan(0);
  });
  it("empty input returns empty result", () => {
    const r = parseTheHive("");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
  it("invalid JSON returns empty result", () => {
    const r = parseTheHive("not json");
    expect(r.events).toHaveLength(0);
  });
});

// ── Elasticsearch false-positive guard ──

describe("parseTheHive — Elasticsearch guard", () => {
  it("skips records with _source (ES hit wrappers)", () => {
    const esHit = { _type: "case", _source: { title: "x" }, _index: "thehive", _id: "1" };
    const r = parseTheHive(j([esHit]));
    expect(r.events).toHaveLength(0);
    expect(r.total).toBe(0);
  });
  it("processes real TheHive records without _source", () => {
    const r = parseTheHive(j([caseRecord()]));
    expect(r.total).toBe(1);
  });
});

// ── counts ──

describe("parseTheHive — counts", () => {
  it("reports correct total, kept, dropped, observables, iocCount", () => {
    const input = j([caseRecord(), alertRecord(), observableIp()]);
    const r = parseTheHive(input);
    expect(r.total).toBe(2);      // 2 cases/alerts
    expect(r.kept).toBe(2);
    expect(r.dropped).toBe(0);
    expect(r.observables).toBe(1);
    expect(r.iocCount).toBe(1);
  });
});
