import type { HostScopeLedger } from "../analysis/hostScope.js";

// The report's scoping statement. Wording is load-bearing: the evidence supports "nothing was found,
// given what was collected" — it does NOT support "these machines are clean". The two coverage
// figures are reported separately and the fleet figure is omitted entirely when no snapshot exists,
// because a percentage against an unknown denominator is worse than no percentage at all.

function n(value: number): string {
  return value.toLocaleString("en-US");
}

export function renderScopeSection(ledger: HostScopeLedger): string {
  const { counts, fleet, referencedNeverCollected } = ledger;
  const stale = ledger.hosts.filter((h) => h.stale).length;

  const lines = [
    "## Scope and clearance",
    "",
    `**Evidence scope.** ${n(counts.confirmed)} host(s) confirmed compromised, ` +
      `${n(counts.suspected)} suspected, ${n(counts.unknown)} not yet assessed, ` +
      `${n(counts["out-of-scope"])} out of scope.`,
    "",
    `**Clearance.** On the basis of the evidence collected, no evidence of compromise was found on ` +
      `${n(counts.cleared)} host(s). This statement is bounded by the sources collected from those ` +
      `hosts and the period those sources cover; it is not an assertion that those hosts are free ` +
      `of compromise.`,
  ];

  if (fleet) {
    lines.push(
      "",
      `**Fleet coverage.** Evidence was collected from ${n(fleet.collected)} of ${n(fleet.enrolled)} ` +
        `enrolled endpoints, against a fleet inventory dated ${fleet.snapshotAt.slice(0, 10)}. ` +
        `Enrolled endpoints may not represent the whole estate.`,
    );
  }

  if (referencedNeverCollected > 0) {
    lines.push(
      "",
      `**Collection gaps.** ${n(referencedNeverCollected)} host(s) appear in the evidence — named by ` +
        `hosts that were collected — but were never collected themselves. Their state is unknown.`,
    );
  }

  if (stale > 0) {
    lines.push(
      "",
      `**${n(stale)} clearance needs review** — evidence relevant to those hosts changed after the ` +
        `clearance was recorded.`,
    );
  }

  return lines.join("\n");
}
