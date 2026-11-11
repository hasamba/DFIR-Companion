// The read-time list of AWS account weaknesses (#2560), from the case file. Pure. The same items
// feed the Cloud Coverage panel, the report section and the CSV, so the three never disagree.
//
// Evidence values (account, bucket, eventID, time) stay in their own fields and are escaped by each
// surface: a bucket name is chosen by whoever created the bucket, possibly the adversary. `title`
// and `detail` are this module's own words and carry counts and parsed times only.

import { BUCKETS_PER_ACCOUNT_MAX, type AccountWeakness, type WeaknessFile } from "./awsAccountWeakness.js";
import type { VersioningFact, WeaknessItem, WeaknessSummary } from "./awsAccountWeaknessTypes.js";

export type { WeaknessItem, WeaknessKind, WeaknessSummary } from "./awsAccountWeaknessTypes.js";

export const WEAKNESS_LIMITS: readonly string[] = [
  "Read from the CloudTrail records each import parsed since this list was added. Records already in the case are not read again, and undoing an import does not remove what it added.",
  "Case-wide: not filtered by the investigation scope or clock alignment. Each item states what the cited record showed at its time; a later fix is not tracked.",
  "Versioning and MFA Delete are listed only when a record states them. CloudTrail usually logs GetBucketVersioning with no response, and an empty response proves nothing.",
];

const plural = (n: number, word: string): string =>
  `${n.toLocaleString("en-US")} ${word}${n === 1 ? "" : "s"}`;
const atLeast = (n: number, overflow: boolean): string =>
  overflow ? `at least ${n.toLocaleString("en-US")}` : n.toLocaleString("en-US");
const second = (iso: string): string => `${new Date(Date.parse(iso)).toISOString().slice(0, 19)}Z`;

function rootItems(a: AccountWeakness): WeaknessItem[] {
  const out: WeaknessItem[] = [];
  const login = a.rootNoMfaLogin;
  if (login)
    out.push({
      kind: "root-no-mfa-login",
      account: a.account,
      title: "Root signed in to the console without MFA",
      detail: `${atLeast(login.ids.keys.length, login.ids.overflow)} successful root console sign-in(s) with MFAUsed "No".`,
      cites: [
        { ...login.first, role: "first" },
        ...(login.last.eventId !== login.first.eventId ? [{ ...login.last, role: "last" }] : []),
      ],
    });
  const use = a.rootUse;
  if (use)
    out.push({
      kind: "root-routine-use",
      account: a.account,
      title: "Root used for routine management",
      detail: `${atLeast(use.ids.keys.length, use.ids.overflow)} root management call(s), ${atLeast(use.mutating.keys.length, use.mutating.overflow)} of them changing something. AWS advises against using root for everyday tasks.`,
      cites: [
        { ...use.first, role: "first" },
        ...(use.last.eventId !== use.first.eventId ? [{ ...use.last, role: "last" }] : []),
      ],
    });
  return out;
}

const VERSIONING_WORDS: Record<VersioningFact, { title: string; detail: string }> = {
  "versioning-suspended": {
    title: "Bucket versioning suspended",
    detail:
      "The cited record states versioning Status Suspended: overwritten or deleted objects keep no earlier version.",
  },
  "mfa-delete-disabled": {
    title: "Bucket MFA Delete disabled",
    detail:
      "The cited record states MFA Delete Disabled: a version can be deleted, or versioning suspended, without MFA.",
  },
};

function bucketItems(a: AccountWeakness): WeaknessItem[] {
  const locks = (a.objectLock?.buckets ?? []).map((b): WeaknessItem => ({
    kind: "object-lock-missing",
    account: a.account,
    bucket: b.bucket,
    title: "Bucket has no Object Lock configuration",
    detail:
      "GetBucketObjectLockConfiguration answered ObjectLockConfigurationNotFoundError: no retention protects the objects from overwrite or delete.",
    cites: [{ ...b.cite, role: "check" }],
  }));
  const versions = (a.versioning?.facts ?? []).map((v): WeaknessItem => ({
    kind: v.fact,
    account: a.account,
    bucket: v.bucket,
    ...VERSIONING_WORDS[v.fact],
    cites: [{ ...v.cite, role: "record" }],
  }));
  return [...locks, ...versions];
}

/** Item 4: a selector change configured S3 object logging and no object-level record is earlier. */
function loggingItem(a: AccountWeakness): WeaknessItem[] {
  const sel = a.objectSelector;
  if (!sel) return [];
  if (a.firstObjectRecord && Date.parse(a.firstObjectRecord.time) < Date.parse(sel.time)) return [];
  const t = second(sel.time);
  const from = a.firstRecordAt ? second(a.firstRecordAt) : "";
  return [
    {
      kind: "object-logging-window",
      account: a.account,
      title: "S3 data events off before the selector change",
      detail:
        `No S3 object-level (data) records were observed before ${t} among the CloudTrail records this list has read; at ${t} this selector change configured S3 object logging. ` +
        `Object reads, overwrites and deletes${from ? ` from ${from}` : ""} to ${t} cannot be seen in these records, so no object activity in that window is not evidence that none happened. Other trails' selectors are not in this evidence.`,
      cites: [{ ...sel, role: "selector change" }],
    },
  ];
}

/** The read-time list. `file` null = nothing recorded yet. */
export function summarizeWeaknesses(file: WeaknessFile | null): WeaknessSummary {
  if (!file) return { read: false, items: [], limits: [...WEAKNESS_LIMITS] };
  const items = file.accounts.flatMap((a) => [...rootItems(a), ...bucketItems(a), ...loggingItem(a)]);
  const limits = [
    ...WEAKNESS_LIMITS,
    ...(file.accountsOverflow
      ? ["More accounts than the list keeps: the accounts past the limit are not shown."]
      : []),
    ...(file.accounts.some((a) => a.objectLock?.overflow || a.versioning?.overflow)
      ? [
          `More buckets than the list keeps for one account (${plural(BUCKETS_PER_ACCOUNT_MAX, "bucket")}): the rest are not shown.`,
        ]
      : []),
  ];
  return { read: true, items, limits };
}
