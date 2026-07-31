import { describe, expect, it, vi } from "vitest";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  HuntQueryCancelledError,
  HuntQueryLimitError,
  executeHuntQuery,
  type HuntEventPage,
  type HuntEventSource,
  type HuntSourceRequest,
} from "../../src/analysis/huntQueryExecutor.js";
import { parseHuntQuery } from "../../src/analysis/huntQueryParser.js";

function event(id: string, overrides: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-07-31T10:00:00.000Z",
    description: `event ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...overrides,
  };
}

function sourceFor(events: readonly ForensicEvent[]): {
  source: HuntEventSource;
  calls: HuntSourceRequest[];
} {
  const calls: HuntSourceRequest[] = [];
  return {
    calls,
    source: {
      readPage: vi.fn(async (request): Promise<HuntEventPage> => {
        calls.push(request);
        const start = request.cursor ?? 0;
        const selected = events.filter((item) => {
          if (request.plan.host && item.asset !== request.plan.host) return false;
          if (request.plan.source) {
            const source = item.artifactName ?? item.sources?.[0];
            if (source !== request.plan.source) return false;
          }
          if (request.plan.severity && item.severity !== request.plan.severity) return false;
          if (request.plan.entityId && item.id !== request.plan.entityId) return false;
          if (request.plan.from && Date.parse(item.timestamp) < Date.parse(request.plan.from)) return false;
          if (request.plan.to && Date.parse(item.timestamp) > Date.parse(request.plan.to)) return false;
          return true;
        });
        const page = selected.slice(start, start + request.limit);
        return {
          events: page,
          nextCursor: start + page.length < selected.length ? start + page.length : null,
        };
      }),
    },
  };
}

describe("hunt query executor", () => {
  it("pushes eligible predicates into the indexed plan and cursor-pages matches", async () => {
    const { source, calls } = sourceFor([
      event("e1", { asset: "DC01", severity: "High" }),
      event("e2", { asset: "DC01", severity: "Low" }),
      event("e3", { asset: "WEB01", severity: "High" }),
    ]);
    const parsed = parseHuntQuery("host.name=DC01 AND severity=High AND description contains event");
    const first = await executeHuntQuery({
      caseId: "c1",
      dataset: "forensic",
      parsed,
      source,
      limit: 1,
    });

    expect(first.events.map((item) => item.id)).toEqual(["e1"]);
    expect(calls[0].plan).toMatchObject({ host: "DC01", severity: "High" });
    expect(calls[0].limit).toBeLessThanOrEqual(500);
    expect(first.explanation).toContain("host index");
  });

  it("does not skip matches when a filtered page ends part-way through a source page", async () => {
    const rows = Array.from({ length: 40 }, (_, index) =>
      event(`e${index}`, {
        description: index % 2 === 0 ? "match" : "miss",
      }),
    );
    const { source } = sourceFor(rows);
    const parsed = parseHuntQuery("description=match");
    const ids: string[] = [];
    let cursor: string | undefined;

    do {
      const page = await executeHuntQuery({
        caseId: "c1",
        dataset: "forensic",
        parsed,
        source,
        cursor,
        limit: 3,
      });
      ids.push(...page.events.map((item) => item.id));
      cursor = page.nextCursor ?? undefined;
    } while (cursor);

    expect(ids).toEqual(rows.filter((_, index) => index % 2 === 0).map((item) => item.id));
  });

  it("evaluates severity ordering and relative time windows deterministically", async () => {
    const { source } = sourceFor([
      event("old", { timestamp: "2026-07-31T07:59:59.000Z", severity: "Critical" }),
      event("low", { timestamp: "2026-07-31T09:00:00.000Z", severity: "Low" }),
      event("high", { timestamp: "2026-07-31T09:30:00.000Z", severity: "High" }),
    ]);
    const result = await executeHuntQuery({
      caseId: "c1",
      dataset: "forensic",
      parsed: parseHuntQuery('severity>=High AND timestamp during "last 2h"'),
      source,
      now: new Date("2026-07-31T10:00:00.000Z"),
    });
    expect(result.events.map((item) => item.id)).toEqual(["high"]);
  });

  it("groups, counts and sorts without retaining an unbounded event array", async () => {
    const { source } = sourceFor([
      event("e1", { srcIp: "192.0.2.1" }),
      event("e2", { srcIp: "192.0.2.1" }),
      event("e3", { srcIp: "192.0.2.2" }),
    ]);
    const result = await executeHuntQuery({
      caseId: "c1",
      dataset: "forensic",
      parsed: parseHuntQuery("source.ip exists | group by source.ip | count | sort count desc"),
      source,
    });
    expect(result.columns).toEqual(["source.ip", "count"]);
    expect(result.rows).toEqual([
      { "source.ip": "192.0.2.1", count: 2 },
      { "source.ip": "192.0.2.2", count: 1 },
    ]);
    expect(result.events).toEqual([]);
  });

  it("returns least-common values for a rare stage", async () => {
    const { source } = sourceFor([
      event("e1", { dstIp: "198.51.100.1" }),
      event("e2", { dstIp: "198.51.100.1" }),
      event("e3", { dstIp: "203.0.113.9" }),
    ]);
    const result = await executeHuntQuery({
      caseId: "c1",
      dataset: "super",
      parsed: parseHuntQuery("destination.ip exists | rare destination.ip limit 1"),
      source,
    });
    expect(result.rows).toEqual([{ "destination.ip": "203.0.113.9", count: 1 }]);
  });

  it("requires all parameters before execution", async () => {
    const { source } = sourceFor([]);
    await expect(
      executeHuntQuery({
        caseId: "c1",
        dataset: "forensic",
        parsed: parseHuntQuery("host.name=$host"),
        source,
      }),
    ).rejects.toMatchObject({
      code: "missing_parameter",
    });
  });

  it("enforces scanned-row and group limits", async () => {
    const { source } = sourceFor(
      Array.from({ length: 20 }, (_, index) => event(`e${index}`, { asset: `HOST-${index}` })),
    );
    await expect(
      executeHuntQuery({
        caseId: "c1",
        dataset: "forensic",
        parsed: parseHuntQuery("description exists"),
        source,
        limits: { maxScannedRows: 5 },
      }),
    ).rejects.toBeInstanceOf(HuntQueryLimitError);

    await expect(
      executeHuntQuery({
        caseId: "c1",
        dataset: "forensic",
        parsed: parseHuntQuery("host.name exists | group by host.name | count"),
        source,
        limits: { maxGroups: 5 },
      }),
    ).rejects.toMatchObject({ resource: "groups" });
  });

  it("performance: scans 20,000 events in bounded pages within five seconds", async () => {
    const { source, calls } = sourceFor(Array.from({ length: 20_000 }, (_, index) => event(`e${index}`)));
    const started = performance.now();
    const result = await executeHuntQuery({
      caseId: "c1",
      dataset: "forensic",
      parsed: parseHuntQuery("description exists | count"),
      source,
    });

    expect(result.rows).toEqual([{ count: 20_000 }]);
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(calls.length).toBeGreaterThan(1);
    expect(calls.every((call) => call.limit <= 500)).toBe(true);
  });

  it("cancels between bounded pages", async () => {
    const controller = new AbortController();
    const source: HuntEventSource = {
      readPage: async () => {
        controller.abort();
        return {
          events: [event("e1")],
          nextCursor: 1,
        };
      },
    };
    await expect(
      executeHuntQuery({
        caseId: "c1",
        dataset: "forensic",
        parsed: parseHuntQuery("description exists | count"),
        source,
        signal: controller.signal,
      }),
    ).rejects.toBeInstanceOf(HuntQueryCancelledError);
  });
});
