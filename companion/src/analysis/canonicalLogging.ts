// The envelope block a logging-configuration row carries (#931 item 14, coverage half — record
// part): the state the request establishes after a successful call — disabled / enabled /
// deleted / created / reconfigured, or "prior state not in record" — with the request's own
// fields quoted. Never a direction from a prior value the record does not carry. Kept beside
// canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

export const loggingStates = [
  "disabled",
  "enabled",
  "deleted",
  "created",
  "reconfigured",
  "prior-state-not-in-record",
  "requested",
] as const;

/** Why a call did not establish the state it asked for (#1081): `denied` — a true authorization
 * failure; `not-found` — the target did not exist, positively identified from the error code;
 * `failed` — the call failed for a reason this evidence does not distinguish from the other two,
 * so it is asserted as neither. `denied: boolean` below is the older, narrower field — still
 * accurate, still derived from this same value — kept for callers that only read it. */
export const loggingFailureKinds = ["denied", "not-found", "failed"] as const;
export type LoggingFailureKind = (typeof loggingFailureKinds)[number];

export const loggingChangeBlockSchema = z.object({
  provider: z.enum(["aws", "gcp", "azure"]),
  /** The trail / detector / bucket / sink / exclusion / log bucket / audit config / diagnostic setting, as recorded. */
  target: z.string(),
  targetKind: z.string(),
  state: z.enum(loggingStates),
  /** The request's fields, quoted — name and value, bounded. */
  facts: z.array(z.object({ name: z.string(), value: z.string() })),
  /** Always false: no record here carries the previous configuration. */
  priorStateInRecord: z.literal(false),
  /** The state the request asked for, kept when the call was denied (`state` is then `requested`). */
  requestedState: z
    .enum(["disabled", "enabled", "deleted", "created", "reconfigured", "prior-state-not-in-record"])
    .optional(),
  /** The effective outcome depends on configurations outside this record (a GCP audit-config union). */
  effectiveNotEstablished: z.boolean(),
  /** True only when `failure === "denied"` — kept for older consumers; unchanged meaning (#1081). */
  denied: z.boolean(),
  /** Undefined when the call succeeded. Optional so an envelope from before this field existed
   * still parses (#1081, Codex design review finding #5 — a required field here would break every
   * already-persisted logging-change envelope on the same schema version). */
  failure: z.enum(loggingFailureKinds).optional(),
});

export type LoggingChangeBlock = z.infer<typeof loggingChangeBlockSchema>;
export type LoggingState = (typeof loggingStates)[number];
