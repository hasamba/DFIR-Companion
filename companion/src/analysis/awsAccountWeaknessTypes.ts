// The shapes of the AWS account-weakness list (#2560) that the report state carries. Types only, in
// the shared layer, so stateTypes.ts can name the read-time projection without reaching up into the
// importer that builds it (awsAccountWeakness*.ts).

export type VersioningFact = "versioning-suspended" | "mfa-delete-disabled";

export type WeaknessKind =
  "root-no-mfa-login" | "root-routine-use" | "object-lock-missing" | VersioningFact | "object-logging-window";

/** The record an item rests on: its eventID and its time (ISO). */
export interface WeaknessCite {
  eventId: string;
  time: string;
}

export interface WeaknessCiteLabelled extends WeaknessCite {
  /** What this record is to the item, e.g. "first", "last", "selector change". */
  role: string;
}

export interface WeaknessItem {
  kind: WeaknessKind;
  /** The AWS account the item is about; "" when the records do not name one. */
  account: string;
  bucket?: string;
  title: string;
  detail: string;
  cites: WeaknessCiteLabelled[];
}

export interface WeaknessSummary {
  /** False when no CloudTrail import has recorded weaknesses for this case yet. */
  read: boolean;
  items: WeaknessItem[];
  /** What the list is and is not, stated beside it on every surface. */
  limits: string[];
}
