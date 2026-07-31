import { randomUUID } from "node:crypto";
import type { Express, Request, Response } from "express";
import { z } from "zod";
import { logActivity } from "../analysis/activityLog.js";
import { HUNT_FIELD_CATALOGUE } from "../analysis/huntQueryFields.js";
import {
  buildHuntIndexedPlan,
  executeHuntQuery,
  explainHuntIndexedPlan,
  HuntQueryCancelledError,
  HuntQueryExecutionError,
  HuntQueryLimitError,
} from "../analysis/huntQueryExecutor.js";
import { explainHuntQuery, HuntQuerySyntaxError, parseHuntQuery } from "../analysis/huntQueryParser.js";
import { SqliteHuntEventSource } from "../analysis/huntQuerySource.js";
import { SavedHuntStore, type SavedHuntExecutionStatus } from "../analysis/savedHuntStore.js";
import type { RouteContext } from "./context.js";

const parameterValueSchema = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
const parametersSchema = z.record(parameterValueSchema).default({});
const datasetSchema = z.enum(["forensic", "super"]);
const querySchema = z.string().min(1).max(20_000);
const authorSchema = z.string().max(200).default("anonymous");

const validateBodySchema = z.object({ query: querySchema });
const executeBodySchema = z.object({
  query: querySchema,
  dataset: datasetSchema,
  parameters: parametersSchema,
  cursor: z.string().max(2_000).optional(),
  limit: z.number().int().min(1).max(1_000).optional(),
  author: authorSchema,
  savedHuntId: z.string().uuid().optional(),
  executionId: z.string().uuid().optional(),
});
const savedHuntBodySchema = z.object({
  name: z.string().min(1).max(200),
  query: querySchema,
  dataset: datasetSchema,
  author: authorSchema,
  parameters: parametersSchema,
});
const evidenceBodySchema = z.object({
  dataset: datasetSchema,
  findingId: z.string().min(1).max(500),
  eventIds: z.array(z.string().min(1).max(500)).min(1).max(1_000),
});

const GRAMMAR = [
  "filter := expression ( '|' stage )*",
  "expression := NOT expression | '(' expression ')' | expression AND expression | expression OR expression | predicate",
  "predicate := field (= | != | > | >= | < | <= | contains | matches | exists | between | during) value",
  "value := quoted string | number | boolean | null | $parameter | bare keyword | /safe-regex/flags",
  "stage := group by field | count | stats fn(field) [by field] | rare field [limit N] | sort field [asc|desc] | limit N",
].join("\n");

const ERROR_CATALOGUE = [
  {
    code: "unknown_field",
    meaning: "The field is not in the typed catalogue.",
  },
  {
    code: "expected_token",
    meaning: "The grammar expected a different token at this location.",
  },
  {
    code: "unsafe_regex",
    meaning: "The pattern exceeds safety limits or uses risky constructs.",
  },
  {
    code: "missing_parameter",
    meaning: "A $parameter has no execution value.",
  },
  {
    code: "resource_limit",
    meaning: "The query exceeded its time, scan, regex, group or memory budget.",
  },
  { code: "cancelled", meaning: "The analyst cancelled execution." },
];

function bodyError(error: z.ZodError): {
  error: string;
  issues: z.ZodIssue[];
} {
  return {
    error: "invalid request body",
    issues: error.issues,
  };
}

function syntaxResponse(error: HuntQuerySyntaxError): {
  error: ReturnType<HuntQuerySyntaxError["toJSON"]>;
} {
  return { error: error.toJSON() };
}

function executionStatus(error: unknown): SavedHuntExecutionStatus {
  if (error instanceof HuntQueryCancelledError) return "cancelled";
  if (error instanceof HuntQueryLimitError) return "limited";
  return "failed";
}

function executionHttpStatus(error: unknown): number {
  if (error instanceof HuntQueryCancelledError) return 499;
  if (error instanceof HuntQueryLimitError) return 429;
  if (error instanceof HuntQueryExecutionError) return 400;
  return 500;
}

export function registerHuntWorkbenchRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;
  const savedHunts = new SavedHuntStore(store);
  const active = new Map<string, AbortController>();
  const activeKey = (caseId: string, executionId: string): string => `${caseId}:${executionId}`;

  app.get("/cases/:id/hunt-query/catalog", (_req: Request, res: Response) =>
    res.status(200).json({
      grammar: GRAMMAR,
      fields: HUNT_FIELD_CATALOGUE,
      errors: ERROR_CATALOGUE,
    }),
  );

  app.post("/cases/:id/hunt-query/validate", (req: Request, res: Response) => {
    const body = validateBodySchema.safeParse(req.body as unknown);
    if (!body.success) {
      return res.status(400).json(bodyError(body.error));
    }
    try {
      const parsed = parseHuntQuery(body.data.query);
      const plan = buildHuntIndexedPlan(parsed);
      return res.status(200).json({
        valid: true,
        explanation: `${explainHuntQuery(parsed)} ${explainHuntIndexedPlan(plan)}`,
        plan,
        parameters: parsed.parameters,
      });
    } catch (error) {
      if (error instanceof HuntQuerySyntaxError) {
        return res.status(400).json(syntaxResponse(error));
      }
      throw error;
    }
  });

  app.post("/cases/:id/hunt-query/execute", async (req: Request, res: Response) => {
    const body = executeBodySchema.safeParse(req.body as unknown);
    if (!body.success) {
      return res.status(400).json(bodyError(body.error));
    }
    if (!options.stateStore) {
      return res.status(501).json({ error: "indexed state store is not configured" });
    }
    const executionId = body.data.executionId ?? randomUUID();
    const controller = new AbortController();
    const key = activeKey(req.params.id, executionId);
    active.set(key, controller);
    const abortOnClose = (): void => {
      if (!res.writableEnded) controller.abort();
    };
    req.once("aborted", abortOnClose);
    res.once("close", abortOnClose);
    const startedAt = Date.now();
    try {
      const parsed = parseHuntQuery(body.data.query);
      const result = await executeHuntQuery({
        caseId: req.params.id,
        dataset: body.data.dataset,
        parsed,
        source: new SqliteHuntEventSource(options.stateStore, options.superTimelineStore),
        parameters: body.data.parameters,
        cursor: body.data.cursor,
        limit: body.data.limit,
        signal: controller.signal,
        executionId,
      });
      if (body.data.savedHuntId) {
        await savedHunts.recordExecution(req.params.id, body.data.savedHuntId, {
          executedBy: body.data.author,
          status: "completed",
          matched: result.matched,
          scanned: result.scanned,
          durationMs: result.durationMs,
          parameters: body.data.parameters,
        });
      }
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "hunt",
        action: "hunt-query",
        actor: body.data.author,
        detail: `${body.data.dataset}: ${result.matched} match(es), ${result.scanned} row(s) scanned`,
      });
      return res.status(200).json(result);
    } catch (error) {
      if (body.data.savedHuntId) {
        await savedHunts.recordExecution(req.params.id, body.data.savedHuntId, {
          executedBy: body.data.author,
          status: executionStatus(error),
          matched: 0,
          scanned: 0,
          durationMs: Date.now() - startedAt,
          parameters: body.data.parameters,
          error: (error as Error).message,
        });
      }
      if (error instanceof HuntQuerySyntaxError) {
        return res.status(400).json(syntaxResponse(error));
      }
      return res.status(executionHttpStatus(error)).json({
        error:
          error instanceof HuntQueryExecutionError
            ? { code: error.code, message: error.message }
            : { code: "execution_failed", message: (error as Error).message },
      });
    } finally {
      active.delete(key);
      req.off("aborted", abortOnClose);
      res.off("close", abortOnClose);
    }
  });

  app.post("/cases/:id/hunt-query/executions/:executionId/cancel", (req: Request, res: Response) => {
    const controller = active.get(activeKey(req.params.id, req.params.executionId));
    if (!controller) {
      return res.status(404).json({ error: "active execution not found" });
    }
    controller.abort();
    return res.status(202).json({ cancelled: true });
  });

  app.get("/cases/:id/hunt-query/saved", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await savedHunts.list(req.params.id));
    } catch (error) {
      return res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post("/cases/:id/hunt-query/saved", async (req: Request, res: Response) => {
    const body = savedHuntBodySchema.safeParse(req.body as unknown);
    if (!body.success) {
      return res.status(400).json(bodyError(body.error));
    }
    try {
      parseHuntQuery(body.data.query);
      return res.status(201).json(await savedHunts.create(req.params.id, body.data));
    } catch (error) {
      if (error instanceof HuntQuerySyntaxError) {
        return res.status(400).json(syntaxResponse(error));
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  });

  app.put("/cases/:id/hunt-query/saved/:huntId", async (req: Request, res: Response) => {
    const body = savedHuntBodySchema.safeParse(req.body as unknown);
    if (!body.success) {
      return res.status(400).json(bodyError(body.error));
    }
    try {
      parseHuntQuery(body.data.query);
      const updated = await savedHunts.update(req.params.id, req.params.huntId, body.data);
      return updated
        ? res.status(200).json(updated)
        : res.status(404).json({ error: "saved hunt not found" });
    } catch (error) {
      if (error instanceof HuntQuerySyntaxError) {
        return res.status(400).json(syntaxResponse(error));
      }
      return res.status(400).json({ error: (error as Error).message });
    }
  });

  app.delete("/cases/:id/hunt-query/saved/:huntId", async (req: Request, res: Response) => {
    try {
      return (await savedHunts.remove(req.params.id, req.params.huntId))
        ? res.status(204).end()
        : res.status(404).json({ error: "saved hunt not found" });
    } catch (error) {
      return res.status(500).json({ error: (error as Error).message });
    }
  });

  app.post("/cases/:id/hunt-query/finding-evidence", async (req: Request, res: Response) => {
    const body = evidenceBodySchema.safeParse(req.body as unknown);
    if (!body.success) {
      return res.status(400).json(bodyError(body.error));
    }
    if (body.data.dataset !== "forensic") {
      return res.status(400).json({
        error: "super-timeline rows must be individually promoted before they can support a finding",
      });
    }
    if (!options.stateStore) {
      return res.status(501).json({ error: "indexed state store is not configured" });
    }
    try {
      const requested = [...new Set(body.data.eventIds)];
      const found = await options.stateStore.hasForensicEventIds(req.params.id, requested);
      const addedEventIds = requested.filter((id) => found.has(id));
      const updated = await ctx.runStateExclusive(req.params.id, async () => {
        const state = await options.stateStore?.load(req.params.id);
        if (!state) return false;
        let changed = false;
        const findings = state.findings.map((finding) => {
          if (finding.id !== body.data.findingId) return finding;
          changed = true;
          return {
            ...finding,
            relatedEventIds: [...new Set([...(finding.relatedEventIds ?? []), ...addedEventIds])],
            lastUpdated: new Date().toISOString(),
          };
        });
        if (!changed) return false;
        await options.stateStore?.save({
          ...state,
          findings,
          updatedAt: new Date().toISOString(),
        });
        return true;
      });
      if (!updated) {
        return res.status(404).json({ error: "finding not found" });
      }
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage",
        action: "attach-hunt-evidence",
        detail: `${addedEventIds.length} event(s) attached to finding ${body.data.findingId}`,
        targetType: "finding",
        targetId: body.data.findingId,
      });
      return res.status(200).json({ addedEventIds });
    } catch (error) {
      return res.status(500).json({ error: (error as Error).message });
    }
  });
}
