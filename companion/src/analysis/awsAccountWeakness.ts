// AWS account weaknesses (#2560): what CloudTrail records PROVE about an account's hygiene, read in
// the CloudTrail importer's own parse — never a second read of the upload, never the super-timeline.
//
//   1. root signed in to the console without MFA (a successful ConsoleLogin, MFAUsed "No");
//   2. root used for routine management (root management calls, sign-in events excluded);
//   3. a bucket with no Object Lock configuration (ObjectLockConfigurationNotFoundError), and
//      versioning suspended / MFA Delete disabled ONLY when a record states it — a null response
//      proves nothing, and CloudTrail usually logs GetBucketVersioning with no response at all;
//   4. no S3 object-level records before the selector change that configured S3 object logging —
//      the same predicates as the #2542 coverage note (objectLoggingWindow.ts).
//
// One draft per upload, in the stored shape, so the case fold (awsAccountWeaknessFold.ts) is the
// only merge there is. Every count is a set of record identities (the dedup ledger's own key,
// hashed), so a record read twice — after an undo, from a re-import, without a ledger — never
// counts twice. Nothing adversary-controlled is shortened into an identity: a value over its cap
// drops the fact instead.

import { createHash } from "node:crypto";
import { z } from "zod";
import type { MappedEvent } from "./siemImport.js";
import { getCI, getPath, isObject, str } from "./siemFieldPick.js";
import { normalizeTime } from "./siemImport.js";
import { cloudRecordIdentity } from "./cloudRecordIdentity.js";
import { isObjectRecord, selectsObjects } from "./objectLoggingWindow.js";
import type { VersioningFact } from "./awsAccountWeaknessTypes.js";

type Row = Record<string, unknown>;

export const WEAKNESS_ACCOUNT_MAX = 64;
export const WEAKNESS_BUCKET_MAX = 255;
export const WEAKNESS_EVENT_ID_MAX = 128;
const TIME_MAX = 40;
const KEY_HEX = 16;
/** Record identities kept per root set; past it the count is "at least". */
export const ROOT_IDS_MAX = 500;
export const BUCKETS_PER_ACCOUNT_MAX = 50;
export const ACCOUNTS_MAX = 200;
/** Cited for a record that carries no eventID. */
export const NO_EVENT_ID = "(no eventID)";

const citeSchema = z.object({
  eventId: z.string().max(WEAKNESS_EVENT_ID_MAX),
  time: z.string().max(TIME_MAX),
});
export type WeaknessCite = z.infer<typeof citeSchema>;

const idSetSchema = z.object({
  keys: z.array(z.string().max(KEY_HEX)).max(ROOT_IDS_MAX),
  overflow: z.boolean(),
});
export type IdSet = z.infer<typeof idSetSchema>;

const rootFactSchema = z.object({ ids: idSetSchema, first: citeSchema, last: citeSchema });
export const VERSIONING_FACTS = [
  "versioning-suspended",
  "mfa-delete-disabled",
] as const satisfies readonly VersioningFact[];
export type { VersioningFact } from "./awsAccountWeaknessTypes.js";

const bucketCiteSchema = z.object({ bucket: z.string().max(WEAKNESS_BUCKET_MAX), cite: citeSchema });
const versioningCiteSchema = bucketCiteSchema.extend({ fact: z.enum(VERSIONING_FACTS) });

export const accountWeaknessSchema = z.object({
  account: z.string().max(WEAKNESS_ACCOUNT_MAX),
  /** Earliest record of this (recipient) account: the start of the item-4 window. */
  firstRecordAt: z.string().max(TIME_MAX).optional(),
  rootNoMfaLogin: rootFactSchema.optional(),
  rootUse: rootFactSchema.extend({ mutating: idSetSchema }).optional(),
  objectLock: z
    .object({ buckets: z.array(bucketCiteSchema).max(BUCKETS_PER_ACCOUNT_MAX), overflow: z.boolean() })
    .optional(),
  versioning: z
    .object({ facts: z.array(versioningCiteSchema).max(BUCKETS_PER_ACCOUNT_MAX), overflow: z.boolean() })
    .optional(),
  /** The earliest successful selector change that configured S3 object logging. */
  objectSelector: citeSchema.optional(),
  /** The earliest S3 object-level record. */
  firstObjectRecord: citeSchema.optional(),
});
export type AccountWeakness = z.infer<typeof accountWeaknessSchema>;

export const weaknessFileSchema = z.object({
  accounts: z.array(accountWeaknessSchema).max(ACCOUNTS_MAX),
  accountsOverflow: z.boolean(),
});
/** One upload's draft and the case file share this shape. */
export type WeaknessFile = z.infer<typeof weaknessFileSchema>;

export const EMPTY_WEAKNESSES: WeaknessFile = { accounts: [], accountsOverflow: false };

/** A mapped CloudTrail row and the raw record it was read from (before any replica merge). */
export interface WeaknessInput {
  event: Pick<MappedEvent, "canonical">;
  record: Row;
}

const field = (rec: Row, path: string): string => str(getPath(rec, path)).trim();
const lower = (rec: Row, path: string): string => field(rec, path).toLowerCase();

function citeOf(rec: Row): WeaknessCite | null {
  const time = normalizeTime(field(rec, "eventTime"));
  if (!time || time.length > TIME_MAX || !Number.isFinite(Date.parse(time))) return null;
  const eventId = field(rec, "eventID") || NO_EVENT_ID;
  return eventId.length > WEAKNESS_EVENT_ID_MAX ? null : { eventId, time };
}

const keyOf = (rec: Row): string =>
  createHash("sha256").update(cloudRecordIdentity("cloudtrail", rec).key).digest("hex").slice(0, KEY_HEX);

const account = (value: string): string | null => (value.length > WEAKNESS_ACCOUNT_MAX ? null : value);

const failed = (rec: Row): boolean => !!field(rec, "errorCode");

/** A per-record contribution; the fold turns a list of them into one draft. */
export type WeaknessFact =
  | { kind: "root-login"; account: string; key: string; cite: WeaknessCite }
  | { kind: "root-use"; account: string; key: string; mutating: boolean; cite: WeaknessCite }
  | { kind: "object-lock"; account: string; bucket: string; cite: WeaknessCite }
  | { kind: "versioning"; account: string; bucket: string; fact: VersioningFact; cite: WeaknessCite }
  | { kind: "selector"; account: string; cite: WeaknessCite }
  | { kind: "object-record"; account: string; cite: WeaknessCite }
  | { kind: "seen"; account: string; time: string };

function rootFacts(rec: Row, cite: WeaknessCite): WeaknessFact[] {
  if (field(rec, "userIdentity.type") !== "Root") return [];
  const acct = account(field(rec, "userIdentity.accountId") || field(rec, "recipientAccountId"));
  if (acct === null) return [];
  const key = keyOf(rec);
  if (lower(rec, "eventSource") === "signin.amazonaws.com") {
    const success =
      field(rec, "eventName") === "ConsoleLogin" &&
      !failed(rec) &&
      field(rec, "responseElements.ConsoleLogin") === "Success" &&
      lower(rec, "additionalEventData.MFAUsed") === "no";
    return success ? [{ kind: "root-login", account: acct, key, cite }] : [];
  }
  const category = lower(rec, "eventCategory");
  if (category && category !== "management") return [];
  const ro = getCI(rec, "readOnly");
  return [{ kind: "root-use", account: acct, key, mutating: ro === false || ro === "false", cite }];
}

const bucketOf = (rec: Row): string | null => {
  const b = field(rec, "requestParameters.bucketName");
  return b && b.length <= WEAKNESS_BUCKET_MAX ? b : null;
};

/** The versioning configuration a record states: a GET's response or a PUT's request. */
function versioningConfig(rec: Row): Row | null {
  const name = field(rec, "eventName");
  const holder =
    name === "GetBucketVersioning"
      ? getCI(rec, "responseElements")
      : name === "PutBucketVersioning"
        ? getCI(rec, "requestParameters")
        : undefined;
  if (!isObject(holder)) return null;
  const inner = getCI(holder, "VersioningConfiguration");
  return isObject(inner) ? inner : holder;
}

function versioningFacts(rec: Row): VersioningFact[] {
  if (failed(rec)) return [];
  const cfg = versioningConfig(rec);
  if (!cfg) return [];
  const status = str(getCI(cfg, "Status")).trim().toLowerCase();
  const mfa = str(getCI(cfg, "MFADelete")).trim().toLowerCase(); // getCI: MfaDelete and MFADelete alike
  return [
    ...(status === "suspended" ? (["versioning-suspended"] as const) : []),
    ...(mfa === "disabled" ? (["mfa-delete-disabled"] as const) : []),
  ];
}

function bucketFacts(rec: Row, acct: string, cite: WeaknessCite): WeaknessFact[] {
  const name = field(rec, "eventName");
  const bucket = bucketOf(rec);
  if (!bucket) return [];
  if (name === "GetBucketObjectLockConfiguration")
    return field(rec, "errorCode") === "ObjectLockConfigurationNotFoundError"
      ? [{ kind: "object-lock", account: acct, bucket, cite }]
      : [];
  return versioningFacts(rec).map((fact) => ({ kind: "versioning", account: acct, bucket, fact, cite }));
}

/** Every weakness fact one mapped CloudTrail row contributes. Pure. */
export function weaknessFacts(input: WeaknessInput): WeaknessFact[] {
  const rec = input.record;
  if (!isObject(rec)) return [];
  const cite = citeOf(rec);
  if (!cite) return [];
  const recipient = account(field(rec, "recipientAccountId"));
  const out: WeaknessFact[] = [...rootFacts(rec, cite)];
  if (recipient === null) return out;
  out.push(...bucketFacts(rec, recipient, cite));
  if (!recipient) return out; // an unknown account is never a shared one for the logging window
  out.push({ kind: "seen", account: recipient, time: cite.time });
  if (selectsObjects(input.event)) out.push({ kind: "selector", account: recipient, cite });
  if (isObjectRecord(input.event)) out.push({ kind: "object-record", account: recipient, cite });
  return out;
}
