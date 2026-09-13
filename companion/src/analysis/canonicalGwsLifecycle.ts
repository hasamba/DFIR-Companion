// The envelope block a Google Workspace OAuth-lifecycle summary row carries (#931 item 10, chain
// half — #983): the client the records are joined through (the client id, never the app name),
// the tenant, every user's authorizations, the activity after an authorization and before a
// revocation (totals over every record; methods bounded), the revocations, the activity after
// them, the admin app-control rows naming the client, and the export's own coverage. `basis` says
// what every reader must keep: activity is placed in time against authorizations and revocations
// for the same user; no record ties a call to a particular grant or its scopes.
// Kept beside canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

const cited = z.object({ time: z.string(), locator: z.string() });

export const gwsAuthorizationSchema = z.object({
  time: z.string(),
  locator: z.string(),
  tier: z.enum(["High", "Medium", "Low"]),
  scopes: z.array(z.string()),
  scopesBeyond: z.number().int().nonnegative(),
});

export const gwsGrantSchema = z.object({
  /** The user's profile id — the identity; the email is the label. */
  profileId: z.string(),
  email: z.string().optional(),
  authorizations: z.array(gwsAuthorizationSchema),
  authorizationsBeyond: z.number().int().nonnegative(),
  activity: z.object({
    calls: z.number().int().nonnegative(),
    /** Exact decimal digits, summed as a big integer over every activity record. */
    bytes: z.string(),
    methods: z.array(z.object({ method: z.string(), calls: z.number().int().nonnegative() })),
    callsBeyondTrackedMethods: z.number().int().nonnegative(),
    first: cited.optional(),
    last: cited.optional(),
  }),
  /** Activity before the first authorization of this user in the export. */
  beforeAuthorization: z.number().int().nonnegative(),
  revocations: z.array(cited),
  afterRevocation: z.object({
    calls: z.number().int().nonnegative(),
    /** Calls a later authorization precedes. */
    reauthorized: z.number().int().nonnegative(),
  }),
  /** Login rows of this user within ±10 minutes of an authorization — contemporaneous, never the same session. */
  contemporaneousLogins: z.number().int().nonnegative(),
  /** Drive rows of this user between an authorization and a revocation — counted, never attributed. */
  driveEventsInWindow: z.number().int().nonnegative(),
});

export const gwsLifecycleBlockSchema = z.object({
  clientId: z.string(),
  tenant: z.string(),
  /** The highest scope tier any authorization of this client carries; "unknown" when none is in the export. */
  coveredTier: z.enum(["High", "Medium", "Low", "unknown"]),
  grants: z.array(gwsGrantSchema),
  usersBeyond: z.number().int().nonnegative(),
  requests: z.number().int().nonnegative(),
  denials: z.number().int().nonnegative(),
  adminControls: z.array(z.object({ event: z.string(), time: z.string(), locator: z.string() })),
  /** Token records that carried no tenant, client id or user — not joined. */
  incomplete: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this export only; joined through the tenant, the client id and the user's profile id; activity placed in time, never tied to a grant or its scopes",
  ),
});

export type GwsLifecycleBlock = z.infer<typeof gwsLifecycleBlockSchema>;
export type GwsGrant = z.infer<typeof gwsGrantSchema>;
