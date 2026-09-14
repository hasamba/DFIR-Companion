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
] as const;

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
  /** The effective outcome depends on configurations outside this record (a GCP audit-config union). */
  effectiveNotEstablished: z.boolean(),
  denied: z.boolean(),
});

export type LoggingChangeBlock = z.infer<typeof loggingChangeBlockSchema>;
export type LoggingState = (typeof loggingStates)[number];
