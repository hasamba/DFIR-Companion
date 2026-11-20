import { readHuntField } from "./huntQueryFields.js";
import type { HuntPipelineStage, HuntStatistic } from "./huntQueryTypes.js";
import type { ForensicEvent } from "./stateTypes.js";

type HuntRow = Record<string, string | number | boolean | null>;

interface AggregateValue {
  count: number;
  /** Distinct hosts (short name, upper-cased) — kept only for a `prevalence` stage (#2670). */
  hosts?: Set<string>;
  statistics: Map<
    string,
    {
      count: number;
      sum: number;
      min: string | number | null;
      max: string | number | null;
    }
  >;
}

export class HuntAggregationGroupLimitError extends Error {
  constructor() {
    super("hunt query group limit exceeded");
  }
}

function scalarValues(value: ReturnType<typeof readHuntField>): Array<string | number | boolean | null> {
  if (Array.isArray(value)) return value;
  return [value ?? null];
}

function groupKey(event: ForensicEvent, field: string | undefined): string {
  if (!field) return "__all__";
  const values = scalarValues(readHuntField(event, field)).filter(
    (value) => value != null && String(value).length > 0,
  );
  return values.length ? String(values[0]) : "(missing)";
}

function comparableStatValue(event: ForensicEvent, statistic: HuntStatistic): string | number | null {
  if (!statistic.field) return null;
  const value = scalarValues(readHuntField(event, statistic.field)).find((item) => item != null);
  if (value == null || typeof value === "boolean") return null;
  return value;
}

function addStatistic(aggregate: AggregateValue, statistic: HuntStatistic, event: ForensicEvent): void {
  const current = aggregate.statistics.get(statistic.alias) ?? {
    count: 0,
    sum: 0,
    min: null,
    max: null,
  };
  const raw = comparableStatValue(event, statistic);
  const numeric = Number(raw);
  if (raw != null) {
    current.count++;
    if (Number.isFinite(numeric)) current.sum += numeric;
    if (current.min == null || raw < current.min) current.min = raw;
    if (current.max == null || raw > current.max) current.max = raw;
  }
  aggregate.statistics.set(statistic.alias, current);
}

function sortRows(rows: HuntRow[], pipeline: readonly HuntPipelineStage[]): void {
  const sort = [...pipeline].reverse().find((stage) => stage.kind === "sort");
  if (sort?.kind !== "sort") return;
  const direction = sort.direction === "desc" ? -1 : 1;
  rows.sort((left, right) => {
    const a = left[sort.field];
    const b = right[sort.field];
    if (a == null && b == null) return 0;
    if (a == null) return direction;
    if (b == null) return -direction;
    return (
      direction *
      (typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b)))
    );
  });
}

/** The host a row is about, as the short upper-cased name hosts are compared on; "" when none. */
function hostOf(event: ForensicEvent): string {
  return (event.asset ?? "").trim().split(".")[0].toUpperCase();
}

export class HuntAggregation {
  private readonly groups = new Map<string, AggregateValue>();
  private readonly allHosts = new Set<string>();
  private readonly prevalence;
  private readonly rare;
  private readonly stats;
  private readonly groupField: string | undefined;

  constructor(
    private readonly pipeline: readonly HuntPipelineStage[],
    private readonly maxGroups: number,
  ) {
    this.rare = pipeline.find((stage) => stage.kind === "rare");
    this.prevalence = pipeline.find((stage) => stage.kind === "prevalence");
    const group = pipeline.find((stage) => stage.kind === "group");
    this.stats = pipeline.find((stage) => stage.kind === "stats");
    this.groupField =
      this.prevalence?.kind === "prevalence"
        ? this.prevalence.field
        : this.rare?.kind === "rare"
          ? this.rare.field
          : this.stats?.kind === "stats"
            ? this.stats.by
            : group?.kind === "group"
              ? group.field
              : undefined;
  }

  add(event: ForensicEvent): void {
    const key = groupKey(event, this.groupField);
    let aggregate = this.groups.get(key);
    if (!aggregate) {
      if (this.groups.size >= this.maxGroups) {
        throw new HuntAggregationGroupLimitError();
      }
      aggregate = { count: 0, statistics: new Map() };
      this.groups.set(key, aggregate);
    }
    aggregate.count++;
    if (this.prevalence) {
      const host = hostOf(event);
      if (host) {
        (aggregate.hosts ??= new Set()).add(host);
        this.allHosts.add(host);
      }
    }
    if (this.stats?.kind === "stats") {
      for (const statistic of this.stats.statistics) {
        addStatistic(aggregate, statistic, event);
      }
    }
  }

  /** `prevalence`: value, distinct hosts, of how many hosts in the matched rows, events. Rarest first. */
  private finishPrevalence(field: string, limit: number): { columns: string[]; rows: HuntRow[] } {
    const of = this.allHosts.size;
    const rows: HuntRow[] = [...this.groups.entries()].map(([key, a]) => ({
      [field]: key,
      hosts: a.hosts?.size ?? 0,
      of_hosts: of,
      events: a.count,
    }));
    rows.sort(
      (l, r) => Number(l.hosts) - Number(r.hosts) || String(l[field]).localeCompare(String(r[field])),
    );
    return { columns: [field, "hosts", "of_hosts", "events"], rows: rows.slice(0, limit) };
  }

  finish(): { columns: string[]; rows: HuntRow[] } {
    if (this.prevalence?.kind === "prevalence")
      return this.finishPrevalence(this.prevalence.field, this.prevalence.limit);
    const statList =
      this.stats?.kind === "stats" ? this.stats.statistics : [{ fn: "count" as const, alias: "count" }];
    const columns = [...(this.groupField ? [this.groupField] : []), ...statList.map((item) => item.alias)];
    const rows = [...this.groups.entries()].map(([key, aggregate]) => {
      const row: HuntRow = {};
      if (this.groupField) row[this.groupField] = key;
      for (const statistic of statList) {
        if (statistic.fn === "count") {
          row[statistic.alias] = aggregate.count;
          continue;
        }
        const value = aggregate.statistics.get(statistic.alias);
        row[statistic.alias] =
          statistic.fn === "sum"
            ? (value?.sum ?? 0)
            : statistic.fn === "avg"
              ? value?.count
                ? value.sum / value.count
                : null
              : statistic.fn === "min"
                ? (value?.min ?? null)
                : (value?.max ?? null);
      }
      return row;
    });
    if (this.rare?.kind === "rare") {
      const rare = this.rare;
      rows.sort(
        (left, right) =>
          Number(left.count) - Number(right.count) ||
          String(left[rare.field]).localeCompare(String(right[rare.field])),
      );
      return { columns, rows: rows.slice(0, rare.limit) };
    }
    sortRows(rows, this.pipeline);
    return { columns, rows };
  }
}
