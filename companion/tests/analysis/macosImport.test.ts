import { describe, it, expect } from "vitest";
import { parseMacos } from "../../src/analysis/macosImport.js";

function ulog(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    timestamp: "2026-05-02 10:00:00.123456+0000",
    eventMessage: "Session opened for user jdoe",
    eventType: "logEvent",
    processImagePath: "/usr/sbin/sshd",
    senderImagePath: "/usr/lib/libsystem.dylib",
    subsystem: "com.apple.securityd",
    category: "auth",
    processID: 501,
    ...over,
  };
}

describe("parseMacos — unified log", () => {
  it("reports an empty result for empty input", () => {
    const r = parseMacos("");
    expect(r.total).toBe(0);
    expect(r.format).toBe("empty");
  });

  it("maps a unified-log record to an Info evidence row naming the process", () => {
    const r = parseMacos(JSON.stringify([ulog()]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("sshd");
    expect(r.events[0].description).toContain("Session opened for user jdoe");
    expect(r.events[0].sources).toContain("macOS Unified Log");
  });

  it("normalizes the unified-log timestamp format", () => {
    const r = parseMacos(JSON.stringify([ulog()]));
    expect(r.events[0].timestamp).toMatch(/^2026-05-02T10:00:00/);
  });

  it("carries the subsystem so the log source stays visible", () => {
    const r = parseMacos(JSON.stringify([ulog()]));
    expect(r.events[0].description).toContain("com.apple.securityd");
  });

  it("stamps the host as the asset when the record names one", () => {
    const r = parseMacos(JSON.stringify([ulog({ machineName: "mbp-jdoe" })]));
    expect(r.events[0].asset).toBe("mbp-jdoe");
  });

  it("skips a record with no timestamp", () => {
    const r = parseMacos(JSON.stringify([{ eventMessage: "orphan" }]));
    expect(r.events).toHaveLength(0);
  });

  it("honours the event cap without dropping the count", () => {
    const many = Array.from({ length: 12 }, (_, i) => ulog({ eventMessage: `msg ${i}` }));
    const r = parseMacos(JSON.stringify(many), { maxEvents: 5 });
    expect(r.total).toBe(12);
    expect(r.events.length).toBeLessThanOrEqual(5);
  });
});

describe("parseMacos — LSQuarantine", () => {
  const csv = [
    "LSQuarantineTimeStamp,LSQuarantineAgentName,LSQuarantineDataURLString,LSQuarantineOriginURLString,LSQuarantineSenderName",
    "2026-05-02T09:30:00Z,Safari,https://cdn.example.invalid/installer.dmg,https://lure.example.invalid/promo,",
  ].join("\n");

  it("maps a quarantine row and records the download URL and host as IOCs", () => {
    const r = parseMacos(csv);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description.toLowerCase()).toContain("quarantine");
    expect(r.events[0].description).toContain("installer.dmg");
    expect(r.iocs.map((i) => i.value)).toContain("cdn.example.invalid");
    expect(r.events[0].sources).toContain("macOS Quarantine");
  });

  it("names the downloading agent, which is the provenance an analyst needs", () => {
    const r = parseMacos(csv);
    expect(r.events[0].description).toContain("Safari");
  });

  it("keeps the referring origin URL, not just the file URL", () => {
    const r = parseMacos(csv);
    expect(r.iocs.map((i) => i.value)).toContain("lure.example.invalid");
  });

  it("stays Info — a quarantine record is provenance, not a verdict", () => {
    const r = parseMacos(csv);
    expect(r.events[0].severity).toBe("Info");
  });
});
