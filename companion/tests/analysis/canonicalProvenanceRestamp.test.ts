// #1352: #1342 made hostBinding.ts's IP index fail-closed on `network.source.provenance`, and
// siemImport.ts only began stamping it at d0b613fa (#1310). A canonical 4624 persisted before that
// carried the address with no stamp, and `upgradeForensicEvent` returned a current-version envelope
// as written — so every IP -> host binding for such a case vanished at once, with nothing but the
// #1345 counter to say so. The pass here re-stamps on read, ONLY for an envelope whose
// `producer.importer` is one of the audited edge-observed writers, because for those the envelope
// itself says which importer wrote the address and that importer's recorder edge observed it.
import { describe, it, expect } from "vitest";
import {
  EDGE_OBSERVED_IMPORTERS,
  restampEdgeObserved,
} from "../../src/analysis/canonicalProvenanceRestamp.js";
import {
  CANONICAL_EVENT_SCHEMA_VERSION,
  LEGACY_UPGRADE_IMPORTER,
  createCanonicalEvent,
  upgradeForensicEvent,
} from "../../src/analysis/canonicalEvent.js";
import { mapWindows, type SiemIoc } from "../../src/analysis/siemImport.js";
import {
  buildHostBindingIndex,
  resolveIpAtTime,
  type IpExclusionReason,
} from "../../src/analysis/hostBinding.js";
import { resolveProxyHostIdentity } from "../../src/analysis/proxyWorkstationChain.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const EMPTY_ALIAS = buildHostAliasIndex([], {});
const TS = "2026-07-30T10:00:00.000Z";

let seq = 0;
function event(o: {
  importer: string;
  ip?: string;
  stamped?: boolean;
  schemaVersion?: string;
}): ForensicEvent {
  seq += 1;
  const canonical = createCanonicalEvent({
    event: { category: "authentication", type: "logon", outcome: "success" },
    target: { kind: "host", name: "SRV-01" },
    session: { terminal: "WS-042" },
    authentication: { logonType: 3 },
    ...(o.ip
      ? {
          network: {
            source: { address: o.ip, ...(o.stamped ? { provenance: "edge-observed" as const } : {}) },
          },
        }
      : {}),
    time: { observed: TS, normalized: TS },
    evidence: { rawRecords: [{ source: "test", locator: `row:${seq}` }] },
    producer: { importer: o.importer, parserVersion: "1", mappingVersion: "1" },
  });
  return {
    id: `id-${seq}`,
    timestamp: TS,
    description: "logon",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "SRV-01",
    canonical: o.schemaVersion
      ? ({ ...canonical, schemaVersion: o.schemaVersion } as unknown as typeof canonical)
      : canonical,
  };
}

/** A real Security 4624 through siemImport.ts's own mapper — the writer whose historical rows #1352 is about. */
function real4624(): ForensicEvent {
  const mapped = mapWindows(
    {
      "@timestamp": TS,
      log_name: "Security",
      computer_name: "SRV-01",
      event_id: 4624,
      event_data: {
        TargetUserName: "jdoe",
        TargetDomainName: "CORP",
        LogonType: "3",
        IpAddress: "10.0.0.5",
        WorkstationName: "WS-042",
      },
    },
    "SRV-01",
    new Map<string, SiemIoc>(),
  );
  if (!mapped?.canonical) throw new Error("fixture: mapWindows produced no canonical envelope");
  return {
    id: "real-4624",
    timestamp: mapped.timestamp,
    description: mapped.description,
    severity: mapped.severity,
    mitreTechniques: mapped.mitre,
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: mapped.asset,
    canonical: mapped.canonical,
  };
}

/** The same envelope as siemImport.ts wrote it before d0b613fa: address present, no stamp. */
function persistedBeforeStamp(e: ForensicEvent): ForensicEvent {
  const source = e.canonical?.network?.source;
  if (!e.canonical || !source) throw new Error("fixture: no network.source to strip");
  const { provenance: _provenance, ...bare } = source;
  return { ...e, canonical: { ...e.canonical, network: { ...e.canonical.network, source: bare } } };
}

function proxyRow(ip: string): ForensicEvent {
  seq += 1;
  return {
    id: `proxy-${seq}`,
    timestamp: TS,
    description: `${ip} - - [request]`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      network: { source: { address: ip, provenance: "edge-observed" } },
      time: { observed: TS, normalized: TS },
      evidence: { rawRecords: [{ source: "combined-access-log", locator: `row:${seq}` }] },
      producer: { importer: "combined-log", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("restampEdgeObserved (#1352)", () => {
  it("stamps an unstamped address written by an audited edge-observed importer", () => {
    const e = event({ importer: "windows-event", ip: "10.0.0.5" });
    const out = restampEdgeObserved(e);
    expect(out.canonical?.network?.source).toEqual({ address: "10.0.0.5", provenance: "edge-observed" });
  });

  it("does not mutate its input", () => {
    const e = event({ importer: "windows-event", ip: "10.0.0.5" });
    const before = JSON.stringify(e);
    restampEdgeObserved(e);
    expect(JSON.stringify(e)).toBe(before);
  });

  it("returns the same object when there is nothing to do", () => {
    const stamped = event({ importer: "windows-event", ip: "10.0.0.5", stamped: true });
    expect(restampEdgeObserved(stamped)).toBe(stamped);
    const noAddress = event({ importer: "windows-event" });
    expect(restampEdgeObserved(noAddress)).toBe(noAddress);
    const noEnvelope: ForensicEvent = { ...event({ importer: "windows-event" }), canonical: undefined };
    expect(restampEdgeObserved(noEnvelope)).toBe(noEnvelope);
  });

  it("leaves an importer outside the audited allowlist unstamped — the legacy upgrader and the header-sourced email writer included", () => {
    for (const importer of [LEGACY_UPGRADE_IMPORTER, "email", "test"]) {
      const e = event({ importer, ip: "10.0.0.5" });
      expect(restampEdgeObserved(e)).toBe(e);
      expect(e.canonical?.network?.source?.provenance).toBeUndefined();
    }
  });

  it("never stamps a source with no address", () => {
    const e = event({ importer: "windows-event" });
    const withPortOnly: ForensicEvent = {
      ...e,
      canonical: { ...e.canonical!, network: { source: { port: 4444 } } },
    };
    expect(restampEdgeObserved(withPortOnly)).toBe(withPortOnly);
  });

  it("keeps every other field of the envelope and the event", () => {
    const e = event({ importer: "windows-event", ip: "10.0.0.5" });
    const out = restampEdgeObserved(e);
    expect({ ...out, canonical: undefined }).toEqual({ ...e, canonical: undefined });
    expect({ ...out.canonical, network: undefined }).toEqual({ ...e.canonical, network: undefined });
  });

  it("the allowlist is the audited writers' importer ids, and nothing that is not one", () => {
    expect(EDGE_OBSERVED_IMPORTERS.has("windows-event")).toBe(true);
    expect(EDGE_OBSERVED_IMPORTERS.has("combined-log")).toBe(true);
    expect(EDGE_OBSERVED_IMPORTERS.has("network")).toBe(true);
    expect(EDGE_OBSERVED_IMPORTERS.has("email")).toBe(false);
    expect(EDGE_OBSERVED_IMPORTERS.has(LEGACY_UPGRADE_IMPORTER)).toBe(false);
  });
});

describe("upgradeForensicEvent applies the re-stamp on read (#1352)", () => {
  it("re-stamps a current-version envelope from an audited importer", () => {
    const e = event({ importer: "windows-event", ip: "10.0.0.5" });
    expect(e.canonical?.schemaVersion).toBe(CANONICAL_EVENT_SCHEMA_VERSION);
    expect(upgradeForensicEvent(e).canonical?.network?.source?.provenance).toBe("edge-observed");
  });

  it("is idempotent: a second read returns the first read's object", () => {
    const once = upgradeForensicEvent(event({ importer: "windows-event", ip: "10.0.0.5" }));
    expect(upgradeForensicEvent(once)).toBe(once);
  });

  it("still preserves an unknown schema version verbatim — no migration, no re-stamp", () => {
    const e = event({ importer: "windows-event", ip: "10.0.0.5", schemaVersion: "9.9.9" });
    expect(upgradeForensicEvent(e)).toBe(e);
  });
});

// The issue's own test: the same 4624 evidence resolves to `matched` through the real join whether
// it was imported today (stamped by siemImport.ts) or yesterday (persisted before d0b613fa, no stamp).
describe("the same 4624 evidence binds IP -> host whether imported before or after the stamp existed (#1352)", () => {
  const today = real4624();
  const yesterday = persistedBeforeStamp(today);

  it("fixture: siemImport.ts stamps today's row and the persisted copy differs only by the stamp", () => {
    expect(today.canonical?.producer.importer).toBe("windows-event");
    expect(today.canonical?.network?.source).toEqual({ address: "10.0.0.5", provenance: "edge-observed" });
    expect(yesterday.canonical?.network?.source).toEqual({ address: "10.0.0.5" });
  });

  it("control: read without the re-stamp, yesterday's row contributes no IP binding (the #1342 gate)", () => {
    const excluded = new Map<IpExclusionReason, number>();
    const index = buildHostBindingIndex([yesterday], undefined, excluded);
    expect(index.byIp.size).toBe(0);
    expect(excluded.get("not-edge-observed")).toBe(1);
  });

  it("through the load path, both rows bind 10.0.0.5 -> WS-042 and nothing is excluded", () => {
    for (const row of [today, yesterday]) {
      const excluded = new Map<IpExclusionReason, number>();
      const index = buildHostBindingIndex([upgradeForensicEvent(row)], undefined, excluded);
      expect(resolveIpAtTime(index, "10.0.0.5", TS, 1_000).map((h) => h.host)).toEqual(["WS-042"]);
      expect(excluded.size).toBe(0);
    }
  });

  it("through the real proxy join, both rows resolve the proxy client to `matched`", () => {
    for (const row of [today, yesterday]) {
      const events = [row, proxyRow("10.0.0.5")].map(upgradeForensicEvent);
      const results = resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000);
      expect(results).toHaveLength(1);
      expect(results[0].outcome).toBe("matched");
      expect(results[0].hosts.map((h) => h.host)).toEqual(["ws-042"]); // the join lowercases host names
      expect(results[0].hosts[0].via).toEqual(["address"]);
    }
  });
});
