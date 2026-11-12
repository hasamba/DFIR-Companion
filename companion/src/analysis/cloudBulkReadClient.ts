// The client side of a cloud bulk-read group (#908 item 8, #2607): which client made the reads, and
// whether its user agent claimed Terraform.
//
// The Terraform claim travels BESIDE the client, never inside the grouping key: the key keeps the
// displayed user agent it always used, so no existing group splits or merges because of the note.
// The claim is read from the importer's fixed note (awsClientHint.ts), which caller text cannot
// produce, never from the clipped `[ua: …]` echo — Terraform's token is often past the displayed
// prefix. It never raises or lowers the summary's grade: it is context the analyst and the model
// read, worded as a claim, because the user agent is caller-chosen.

import { TERRAFORM_CLAIM_HINT, carriesTerraformClaim } from "./awsClientHint.js";

/** Clients a person drives, as opposed to the services that normally move data on a schedule. */
export const INTERACTIVE_CLIENT_RE =
  /\b(?:rclone|cyberduck|s3browser|winscp|filezilla|transmit|mountainduck|s5cmd|aws-cli|boto3|botocore|s3cmd|curl|wget|python-requests|megasync|megacmd|rsync)\b/i;

/** The client that made the call. NO IMPORTER RETAINS CloudTrail's `userAgent` FIELD TODAY, so this reads what IS there (an explicit `[ua: …]` annotation, or a client name the description happens to carry) and returns "" otherwise — gradeGroup then SAYS the client was not recorded rather than grouping every caller together and implying they were one client. The Terraform note is removed first, so a clipped `[ua: …` never runs into it. */
export function clientFromDescription(d: string): string {
  const text = (d ?? "").replace(TERRAFORM_CLAIM_HINT, "");
  const tagged = /\[ua:\s*([^\]]{1,120})\]/i.exec(text)?.[1];
  if (tagged) return tagged.trim();
  const known = INTERACTIVE_CLIENT_RE.exec(text);
  return known ? known[0] : "";
}

/** How much of a group's window carries the claim: every call, some of them, or none (undefined). */
export type TerraformClaim = "all" | "some" | undefined;

/** Whether one read row's description carries the importer's Terraform note. */
export function claimsTerraform(description: string | undefined): boolean {
  return carriesTerraformClaim(description ?? "");
}

/** The claim over a window of reads. */
export function terraformClaimOf(window: ReadonlyArray<{ claimsTerraform?: boolean }>): TerraformClaim {
  const n = window.filter((r) => r.claimsTerraform).length;
  return n === 0 ? undefined : n === window.length ? "all" : "some";
}

/** The summary sentence for a claim — "" when there is none. Never a grading input. */
export function terraformClaimSentence(claim: TerraformClaim): string {
  if (!claim) return "";
  const which = claim === "all" ? "every call in this window" : "some of the calls in this window";
  return ` The user agent on ${which} claims Terraform: infrastructure-as-code set-up and state refresh read buckets like this, but the field is set by the caller, so confirm the run against the expected deployment pipeline.`;
}
