import { randomUUID } from "node:crypto";
import { HuntAggregation, HuntAggregationGroupLimitError } from "./huntQueryAggregation.js";
import {
  decodeHuntCursor,
  encodeHuntCursor,
  HuntCursorError,
  huntCursorFingerprint,
  type HuntCursorState,
} from "./huntQueryCursor.js";
import { readHuntField, resolveHuntField } from "./huntQueryFields.js";
import type {
  HuntDataset,
  HuntExpression,
  HuntParameters,
  HuntPipelineStage,
  HuntPredicate,
  HuntValue,
  ParsedHuntQuery,
} from "./huntQueryTypes.js";
import type { ForensicEvent } from "./stateTypes.js";

export interface HuntIndexedPlan {
  host?: string;
  source?: string;
  severity?: string;
  entityId?: string;
  from?: string;
  to?: string;
  ioc?: string;
  technique?: string;
}

export interface HuntSourceRequest {
  caseId: string;
  dataset: HuntDataset;
  plan: HuntIndexedPlan;
  cursor: number | null;
  limit: number;
}

export interface HuntEventPage {
  events: ForensicEvent[];
  nextCursor: number | null;
}

export interface HuntEventSource {
  readPage(request: HuntSourceRequest): Promise<HuntEventPage>;
}

export interface HuntExecutionLimits {
  maxScannedRows: number;
  maxDurationMs: number;
  maxGroups: number;
  maxMaterializedRows: number;
  maxRegexEvaluations: number;
  scanPageSize: number;
}

export interface HuntExecutionOptions {
  caseId: string;
  dataset: HuntDataset;
  parsed: ParsedHuntQuery;
  source: HuntEventSource;
  parameters?: HuntParameters;
  cursor?: string;
  limit?: number;
  now?: Date;
  signal?: AbortSignal;
  limits?: Partial<HuntExecutionLimits>;
  executionId?: string;
}

export interface HuntExecutionResult {
  dataset: HuntDataset;
  executionId: string;
  columns: string[];
  rows: Array<Record<string, string | number | boolean | null>>;
  events: ForensicEvent[];
  nextCursor: string | null;
  matched: number;
  scanned: number;
  durationMs: number;
  explanation: string;
}

interface EvaluationContext {
  regexEvaluations: number;
  limits: HuntExecutionLimits;
  anchorTime: Date;
  // Per-execution caches: a `matches` pattern/flags pair and a `during` window string are query
  // constants, so compile/resolve them once instead of per scanned row. Hunt regex flags are
  // restricted to [imsu] (no g/y), so a cached instance carries no lastIndex state between .test()
  // calls. Both caches die with the request.
  regexCache: Map<string, RegExp>;
  duringCache: Map<string, { fromMs: number; toMs: number }>;
}

const DEFAULT_LIMITS: HuntExecutionLimits = {
  maxScannedRows: 100_000,
  maxDurationMs: 5_000,
  maxGroups: 5_000,
  maxMaterializedRows: 10_000,
  maxRegexEvaluations: 50_000,
  scanPageSize: 250,
};
const DEFAULT_RESULT_LIMIT = 100;
const MAX_RESULT_LIMIT = 1_000;
const SEVERITY_RANK = new Map([
  ["info", 0],
  ["low", 1],
  ["medium", 2],
  ["high", 3],
  ["critical", 4],
]);

export class HuntQueryExecutionError extends Error {
  readonly name: string = "HuntQueryExecutionError";

  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export class HuntQueryLimitError extends HuntQueryExecutionError {
  readonly name = "HuntQueryLimitError";

  constructor(
    readonly resource: string,
    limit: number,
  ) {
    super("resource_limit", `Query exceeded the ${resource} limit (${limit})`);
  }
}

export class HuntQueryCancelledError extends HuntQueryExecutionError {
  readonly name = "HuntQueryCancelledError";

  constructor() {
    super("cancelled", "Query execution was cancelled");
  }
}

function isParameter(value: HuntValue | undefined): value is {
  kind: "parameter";
  name: string;
} {
  return value != null && typeof value === "object" && value.kind === "parameter";
}

function resolveValue(
  value: HuntValue | undefined,
  parameters: HuntParameters,
): string | number | boolean | null | undefined {
  if (!isParameter(value)) return value;
  if (!Object.prototype.hasOwnProperty.call(parameters, value.name)) {
    throw new HuntQueryExecutionError("missing_parameter", `Missing required parameter $${value.name}`);
  }
  return parameters[value.name];
}

function durationMs(text: string): number | null {
  const match = /^(?:last|past)\s+(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)$/i.exec(text.trim());
  if (!match) return null;
  const scale: Record<string, number> = {
    ms: 1,
    s: 1_000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
    w: 604_800_000,
  };
  return Number(match[1]) * scale[match[2].toLowerCase()];
}

function duringRange(raw: string, anchorTime: Date): { from: string; to: string } | null {
  const relative = durationMs(raw);
  if (relative != null) {
    return {
      from: new Date(anchorTime.getTime() - relative).toISOString(),
      to: anchorTime.toISOString(),
    };
  }
  const absolute = raw.split(/\s+(?:to|\.\.)\s+/i);
  if (
    absolute.length === 2 &&
    Number.isFinite(Date.parse(absolute[0])) &&
    Number.isFinite(Date.parse(absolute[1]))
  ) {
    return {
      from: new Date(absolute[0]).toISOString(),
      to: new Date(absolute[1]).toISOString(),
    };
  }
  return null;
}

function comparable(
  field: string,
  value: string | number | boolean | null,
): string | number | boolean | null {
  if (value == null) return null;
  const fieldType = resolveHuntField(field)?.type;
  if (field === "severity") {
    return SEVERITY_RANK.get(String(value).toLowerCase()) ?? -1;
  }
  if (field === "event.outcome") {
    const normalized = String(value).toLowerCase();
    return normalized === "failure" ? "failed" : normalized;
  }
  if (fieldType === "timestamp") {
    const parsed = Date.parse(String(value));
    return Number.isFinite(parsed) ? parsed : Number.NaN;
  }
  if (fieldType === "number") return Number(value);
  if (fieldType === "boolean") return value === true || value === "true";
  return String(value);
}

function scalarValues(value: ReturnType<typeof readHuntField>): Array<string | number | boolean | null> {
  if (Array.isArray(value)) return value;
  return [value ?? null];
}

function compareScalar(
  field: string,
  actual: string | number | boolean | null,
  predicate: HuntPredicate,
  parameters: HuntParameters,
  context: EvaluationContext,
): boolean {
  const expected = resolveValue(predicate.value, parameters);
  if (predicate.operator === "exists") {
    return actual != null && (typeof actual !== "string" || actual.length > 0);
  }
  if (predicate.operator === "during") {
    if (actual == null || typeof expected !== "string") return false;
    let window = context.duringCache.get(expected);
    if (!window) {
      const range = duringRange(expected, context.anchorTime);
      if (!range) {
        throw new HuntQueryExecutionError(
          "invalid_time_window",
          `Invalid time window ${JSON.stringify(expected)}`,
        );
      }
      window = { fromMs: Date.parse(range.from), toMs: Date.parse(range.to) };
      context.duringCache.set(expected, window);
    }
    const time = Date.parse(String(actual));
    return Number.isFinite(time) && time >= window.fromMs && time <= window.toMs;
  }
  if (predicate.operator === "matches") {
    context.regexEvaluations++;
    if (context.regexEvaluations > context.limits.maxRegexEvaluations) {
      throw new HuntQueryLimitError("regex evaluations", context.limits.maxRegexEvaluations);
    }
    const pattern = String(expected ?? "");
    // NUL-joined so a pattern that itself ends in a flag letter can never collide with another
    // pattern+flags pair (a regex pattern cannot contain a raw NUL).
    const cacheKey = `${pattern}\u0000${predicate.regexFlags ?? ""}`;
    let regex = context.regexCache.get(cacheKey);
    if (!regex) {
      regex = new RegExp(pattern, predicate.regexFlags);
      context.regexCache.set(cacheKey, regex);
    }
    return regex.test(String(actual ?? ""));
  }
  if (predicate.operator === "contains") {
    return String(actual ?? "")
      .toLowerCase()
      .includes(String(expected ?? "").toLowerCase());
  }
  const left = comparable(field, actual);
  const right = comparable(field, expected ?? null);
  if (predicate.operator === "between") {
    const upperValue = resolveValue(predicate.upper, parameters);
    const upper = comparable(field, upperValue ?? null);
    return left != null && right != null && upper != null && left >= right && left <= upper;
  }
  switch (predicate.operator) {
    case "=":
      return left === right;
    case "!=":
      return left !== right;
    case ">":
      return left != null && right != null && left > right;
    case ">=":
      return left != null && right != null && left >= right;
    case "<":
      return left != null && right != null && left < right;
    case "<=":
      return left != null && right != null && left <= right;
    default:
      return false;
  }
}

function evaluate(
  expression: HuntExpression,
  event: ForensicEvent,
  parameters: HuntParameters,
  context: EvaluationContext,
): boolean {
  if (expression.kind === "boolean") {
    if (expression.operator === "and") {
      return (
        evaluate(expression.left, event, parameters, context) &&
        evaluate(expression.right, event, parameters, context)
      );
    }
    return (
      evaluate(expression.left, event, parameters, context) ||
      evaluate(expression.right, event, parameters, context)
    );
  }
  if (expression.kind === "not") {
    return !evaluate(expression.operand, event, parameters, context);
  }
  const value = readHuntField(event, expression.field);
  if (expression.operator === "exists") {
    return scalarValues(value).some((item) =>
      compareScalar(expression.field, item, expression, parameters, context),
    );
  }
  return scalarValues(value).some((item) =>
    compareScalar(expression.field, item, expression, parameters, context),
  );
}

function assignPlanPredicate(
  plan: HuntIndexedPlan,
  predicate: HuntPredicate,
  parameters: HuntParameters,
  anchorTime: Date,
): void {
  const value = resolveValue(predicate.value, parameters);
  if (predicate.operator === "=" && typeof value === "string") {
    if (predicate.field === "host.name") plan.host = value;
    else if (predicate.field === "event.source") plan.source = value;
    else if (predicate.field === "severity") plan.severity = value;
    else if (predicate.field === "id") plan.entityId = value;
    else if (predicate.field === "mitre.technique") plan.technique = value;
    else if (
      ["ioc", "source.ip", "destination.ip", "file.path", "file.sha256", "file.md5"].includes(predicate.field)
    ) {
      plan.ioc = value;
    }
  }
  if (predicate.field !== "timestamp") return;
  if (predicate.operator === "during" && typeof value === "string") {
    const range = duringRange(value, anchorTime);
    if (range) Object.assign(plan, range);
  } else if (
    [">", ">="].includes(predicate.operator) &&
    typeof value === "string" &&
    Number.isFinite(Date.parse(value))
  ) {
    plan.from = new Date(value).toISOString();
  } else if (
    ["<", "<="].includes(predicate.operator) &&
    typeof value === "string" &&
    Number.isFinite(Date.parse(value))
  ) {
    plan.to = new Date(value).toISOString();
  } else if (predicate.operator === "between") {
    const upper = resolveValue(predicate.upper, parameters);
    if (
      typeof value === "string" &&
      typeof upper === "string" &&
      Number.isFinite(Date.parse(value)) &&
      Number.isFinite(Date.parse(upper))
    ) {
      plan.from = new Date(value).toISOString();
      plan.to = new Date(upper).toISOString();
    }
  }
}

function collectSafeAndPredicates(expression: HuntExpression, output: HuntPredicate[]): void {
  if (expression.kind === "boolean" && expression.operator === "and") {
    collectSafeAndPredicates(expression.left, output);
    collectSafeAndPredicates(expression.right, output);
  } else if (expression.kind === "predicate") {
    output.push(expression);
  }
}

export function buildHuntIndexedPlan(
  parsed: ParsedHuntQuery,
  parameters: HuntParameters = {},
  anchorTime = new Date(),
): HuntIndexedPlan {
  const plan: HuntIndexedPlan = {};
  const predicates: HuntPredicate[] = [];
  collectSafeAndPredicates(parsed.filter, predicates);
  for (const predicate of predicates) {
    assignPlanPredicate(plan, predicate, parameters, anchorTime);
  }
  return plan;
}

export function explainHuntIndexedPlan(plan: HuntIndexedPlan): string {
  const indexes: string[] = [];
  if (plan.host) indexes.push("host index");
  if (plan.source) indexes.push("source index");
  if (plan.severity) indexes.push("severity index");
  if (plan.entityId) indexes.push("event-id index");
  if (plan.ioc) indexes.push("IOC index");
  if (plan.technique) indexes.push("MITRE technique index");
  if (plan.from || plan.to) indexes.push("time index");
  return indexes.length
    ? `SQLite cursor scan seeded by ${indexes.join(", ")}; remaining conditions are verified on each bounded page.`
    : "SQLite cursor scan over bounded pages; no complete timeline is loaded into memory.";
}

function isAnalytical(pipeline: readonly HuntPipelineStage[]): boolean {
  return pipeline.some((stage) => ["group", "count", "stats", "rare", "sort"].includes(stage.kind));
}

function stageLimit(pipeline: readonly HuntPipelineStage[], fallback: number): number {
  const limit = [...pipeline].reverse().find((stage) => stage.kind === "limit");
  return limit?.kind === "limit" ? Math.min(limit.limit, fallback) : fallback;
}

function checkRuntime(startedAt: number, limits: HuntExecutionLimits, signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new HuntQueryCancelledError();
  if (Date.now() - startedAt > limits.maxDurationMs) {
    throw new HuntQueryLimitError("execution time (ms)", limits.maxDurationMs);
  }
}

async function executeAnalytical(
  options: ExecutionState,
): Promise<Pick<HuntExecutionResult, "columns" | "rows" | "events" | "matched" | "scanned">> {
  const materialized: ForensicEvent[] = [];
  const rare = options.parsed.pipeline.find((stage) => stage.kind === "rare");
  const group = options.parsed.pipeline.find((stage) => stage.kind === "group");
  const stats = options.parsed.pipeline.find((stage) => stage.kind === "stats");
  const rawSort =
    !rare && !group && !stats && !options.parsed.pipeline.some((stage) => stage.kind === "count");
  const aggregation = new HuntAggregation(options.parsed.pipeline, options.limits.maxGroups);
  let sourceCursor: number | null = null;
  let scanned = 0;
  let matched = 0;

  do {
    checkRuntime(options.startedAt, options.limits, options.signal);
    const page = await options.source.readPage({
      caseId: options.caseId,
      dataset: options.dataset,
      plan: options.plan,
      cursor: sourceCursor,
      limit: options.limits.scanPageSize,
    });
    checkRuntime(options.startedAt, options.limits, options.signal);
    for (const event of page.events) {
      scanned++;
      if (scanned > options.limits.maxScannedRows) {
        throw new HuntQueryLimitError("scanned rows", options.limits.maxScannedRows);
      }
      if (!evaluate(options.parsed.filter, event, options.parameters, options.evaluation)) {
        continue;
      }
      matched++;
      if (rawSort) {
        if (materialized.length >= options.limits.maxMaterializedRows) {
          throw new HuntQueryLimitError("materialized rows", options.limits.maxMaterializedRows);
        }
        materialized.push(event);
        continue;
      }
      try {
        aggregation.add(event);
      } catch (error) {
        if (error instanceof HuntAggregationGroupLimitError) {
          throw new HuntQueryLimitError("groups", options.limits.maxGroups);
        }
        throw error;
      }
    }
    sourceCursor = page.nextCursor;
  } while (sourceCursor !== null);

  if (rawSort) {
    const sort = [...options.parsed.pipeline].reverse().find((stage) => stage.kind === "sort");
    if (sort?.kind === "sort") {
      materialized.sort((left, right) => {
        const a = scalarValues(readHuntField(left, sort.field))[0];
        const b = scalarValues(readHuntField(right, sort.field))[0];
        const comparison =
          typeof a === "number" && typeof b === "number"
            ? a - b
            : String(a ?? "").localeCompare(String(b ?? ""));
        return sort.direction === "desc" ? -comparison : comparison;
      });
    }
    return {
      columns: [],
      rows: [],
      events: materialized.slice(0, options.outputLimit),
      matched,
      scanned,
    };
  }
  const aggregate = aggregation.finish();
  return {
    ...aggregate,
    rows: aggregate.rows.slice(0, options.outputLimit),
    events: [],
    matched,
    scanned,
  };
}

interface ExecutionState {
  caseId: string;
  dataset: HuntDataset;
  parsed: ParsedHuntQuery;
  source: HuntEventSource;
  parameters: HuntParameters;
  plan: HuntIndexedPlan;
  limits: HuntExecutionLimits;
  outputLimit: number;
  startedAt: number;
  signal?: AbortSignal;
  evaluation: EvaluationContext;
}

async function executeRaw(
  options: ExecutionState,
  cursorState: HuntCursorState,
): Promise<Pick<HuntExecutionResult, "columns" | "rows" | "events" | "matched" | "scanned" | "nextCursor">> {
  const events: ForensicEvent[] = [];
  let scanned = 0;
  let sourceCursor = cursorState.sourceCursor;
  let skip = cursorState.skip;

  while (events.length < options.outputLimit) {
    checkRuntime(options.startedAt, options.limits, options.signal);
    const pageCursor = sourceCursor;
    const page = await options.source.readPage({
      caseId: options.caseId,
      dataset: options.dataset,
      plan: options.plan,
      cursor: pageCursor,
      limit: options.limits.scanPageSize,
    });
    checkRuntime(options.startedAt, options.limits, options.signal);
    for (let index = skip; index < page.events.length; index++) {
      scanned++;
      if (scanned > options.limits.maxScannedRows) {
        throw new HuntQueryLimitError("scanned rows", options.limits.maxScannedRows);
      }
      const event = page.events[index];
      if (evaluate(options.parsed.filter, event, options.parameters, options.evaluation)) {
        events.push(event);
      }
      if (events.length >= options.outputLimit) {
        const moreInPage = index + 1 < page.events.length;
        const hasMore = moreInPage || page.nextCursor !== null;
        return {
          columns: [],
          rows: [],
          events,
          matched: events.length,
          scanned,
          nextCursor: hasMore
            ? encodeHuntCursor({
                version: 1,
                fingerprint: cursorState.fingerprint,
                sourceCursor: moreInPage ? pageCursor : page.nextCursor,
                skip: moreInPage ? index + 1 : 0,
                anchorTime: cursorState.anchorTime,
              })
            : null,
        };
      }
    }
    if (page.nextCursor === null) break;
    sourceCursor = page.nextCursor;
    skip = 0;
  }
  return {
    columns: [],
    rows: [],
    events,
    matched: events.length,
    scanned,
    nextCursor: null,
  };
}

export async function executeHuntQuery(input: HuntExecutionOptions): Promise<HuntExecutionResult> {
  const startedAt = Date.now();
  const parameters = input.parameters ?? {};
  for (const name of input.parsed.parameters) {
    resolveValue({ kind: "parameter", name }, parameters);
  }
  const queryFingerprint = huntCursorFingerprint(input.parsed, input.dataset, parameters);
  let decoded: HuntCursorState | null = null;
  try {
    decoded = input.cursor ? decodeHuntCursor(input.cursor, queryFingerprint) : null;
  } catch (error) {
    if (error instanceof HuntCursorError) {
      throw new HuntQueryExecutionError(
        "invalid_cursor",
        "Cursor is invalid or belongs to a different query",
      );
    }
    throw error;
  }
  const anchorTime = decoded ? new Date(decoded.anchorTime) : (input.now ?? new Date());
  const cursorState: HuntCursorState = decoded ?? {
    version: 1,
    fingerprint: queryFingerprint,
    sourceCursor: null,
    skip: 0,
    anchorTime: anchorTime.toISOString(),
  };
  const limits: HuntExecutionLimits = {
    ...DEFAULT_LIMITS,
    ...input.limits,
    scanPageSize: Math.max(
      1,
      Math.min(500, Math.floor(input.limits?.scanPageSize ?? DEFAULT_LIMITS.scanPageSize)),
    ),
  };
  const requestedLimit = Math.floor(input.limit ?? DEFAULT_RESULT_LIMIT);
  const outputLimit = stageLimit(
    input.parsed.pipeline,
    Math.max(1, Math.min(MAX_RESULT_LIMIT, requestedLimit)),
  );
  const plan = buildHuntIndexedPlan(input.parsed, parameters, anchorTime);
  const state: ExecutionState = {
    caseId: input.caseId,
    dataset: input.dataset,
    parsed: input.parsed,
    source: input.source,
    parameters,
    plan,
    limits,
    outputLimit,
    startedAt,
    signal: input.signal,
    evaluation: {
      regexEvaluations: 0,
      limits,
      anchorTime,
      regexCache: new Map(),
      duringCache: new Map(),
    },
  };
  const result = isAnalytical(input.parsed.pipeline)
    ? {
        ...(await executeAnalytical(state)),
        nextCursor: null,
      }
    : await executeRaw(state, cursorState);
  return {
    dataset: input.dataset,
    executionId: input.executionId ?? randomUUID(),
    ...result,
    durationMs: Date.now() - startedAt,
    explanation: explainHuntIndexedPlan(plan),
  };
}
