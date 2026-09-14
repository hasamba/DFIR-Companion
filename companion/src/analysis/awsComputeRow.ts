// The words and the envelope block of one AWS compute-lifecycle row (#931 item 8): every part is
// the record's own — a transition, a recorded rule, a returned association state — the sequence
// and the facts the grade rests on are packed with the tail and never clipped, an ARN in a
// change line is cut to its resource part, and a secret never reaches the row. The pass that
// fills the state lives in awsCompute.ts.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type {
  AwsComputeBlock,
  AwsComputeFact,
  AwsComputeLaunch,
  AwsComputeLifecycle,
} from "./canonicalAwsCompute.js";
import { enumerationWindow, type ShapeHit } from "./awsLineage.js";
import { normalizeTime, type MappedEvent } from "./siemImport.js";
import {
  AWS_COMPUTE_MAX,
  BASIS,
  CHANGES_NAMED_MAX,
  INSTANCES_TRACKED_MAX,
  COVERAGE_NOTE,
  DESCRIPTION_MAX,
  FACT_MITRE,
  FACT_WORDS,
  LIMIT_NOTE,
  RAW_RECORDS_MAX,
  SOURCES_NAMED_MAX,
  iso,
  orderOf,
  plural,
  show,
  type Inst,
  type Lifecycle,
  type Rule,
  type Timed,
} from "./awsComputeState.js";

const orderWords = (o: AwsComputeLifecycle["order"] | undefined): string =>
  o === "after"
    ? " — after the launch"
    : o === "before"
      ? " — before the launch"
      : o === "same"
        ? " — at the same recorded time as the launch"
        : "";
/** The identity words with an ARN cut to its resource part (`IAMUser user/alice`) — the launch line keeps the full ARN. */
const shortBy = (by: string): string => show(by.replace(/arn:[^:\s]*:[^:\s]*:[^:\s]*:[^:\s]*:/, ""), 60);
const whoAt = (time: number, by: string, locator: string): string =>
  `at ${iso(time)} by ${shortBy(by)} (${locator})`;

function lifecycleWords(inst: Inst, e: Lifecycle): string {
  const tail = `${whoAt(e.time, e.by, e.locator)}${orderWords(orderOf(inst, e.time))}`;
  const call = show(e.call, 40);
  switch (e.kind) {
    case "reboot":
      return `${call} requested ${tail}`;
    case "start":
    case "stop":
    case "terminate":
      return `${call}: ${e.transition ? `${show(e.transition.from, 20) || "(not recorded)"} → ${show(e.transition.to, 20) || "(not recorded)"} ` : ""}${tail}`;
    case "startup-config-replaced":
      return `${call}: startup configuration replaced (content not shown) ${tail}`;
    case "groups-set":
      return `${call}: security groups set to ${(e.groups ?? []).map((g) => show(g, 30)).join(", ") || "(none named)"} ${tail}`;
    case "termination-protection":
      return `${call}: termination protection changed ${tail}`;
    case "type-changed":
      return `${call}: instance type changed ${tail}`;
    case "attribute-modified":
      return `${call}: attribute ${show(e.attribute ?? "other", 40)} modified ${tail}`;
    case "profile-associated":
    case "profile-replaced":
      return `${call}: instance profile ${show(e.profile ?? "(not named)")}${e.associationState ? ` — association entered ${show(e.associationState, 20)}` : ""} ${tail}`;
    case "profile-disassociated":
      return `${call}: association entered ${show(e.associationState || "(state not recorded)", 20)} ${tail}`;
  }
}

/** stop → startup configuration replaced → start, strictly ordered among the retained records. */
function correlatedSequence(entries: readonly Lifecycle[]): boolean {
  const replaced = entries.filter((e) => e.kind === "startup-config-replaced");
  return replaced.some(
    (r) =>
      entries.some((e) => e.kind === "stop" && e.time < r.time) &&
      entries.some((e) => e.kind === "start" && e.time > r.time),
  );
}

function launchWords(l: Omit<AwsComputeLaunch, "time"> & Timed): string {
  const facts = [
    l.image ? `image ${show(l.image)}` : "",
    l.type ? `type ${show(l.type, 30)}` : "",
    l.keyName ? `key pair ${show(l.keyName, 40)}` : "",
    l.profile ? `instance profile ${show(l.profile)}` : "",
    l.groups.length
      ? `groups ${l.groups.map((g) => `${show(g.id, 30)}${g.name ? ` (${show(g.name, 30)})` : ""}`).join(", ")}`
      : "",
    l.subnet
      ? `subnet ${show(l.subnet, 30)}${l.vpc ? ` in ${show(l.vpc, 30)}` : ""}`
      : l.vpc
        ? `vpc ${show(l.vpc, 30)}`
        : "",
    l.privateAddress ? `private address ${show(l.privateAddress, 45)}` : "",
    l.availabilityZone ? `availability zone ${show(l.availabilityZone, 30)}` : "",
    l.startupConfig === "supplied"
      ? "startup configuration supplied (content not shown)"
      : l.startupConfig === "removed-by-cloudtrail"
        ? "startup configuration supplied; CloudTrail removed its content"
        : "startup configuration not in this record",
  ].filter(Boolean);
  const who = l.invokedBy
    ? ` — request made by AWS service ${show(l.invokedBy, 50)}; signing principal ${show(l.by)}`
    : ` by ${show(l.by)}`;
  return `launched ${iso(l.time)}${who}${l.address ? ` from ${show(l.address, 45)}` : ""}${l.agent ? ` ${show(l.agent, 40)}` : ""}${l.requesterId ? `; requesterId ${show(l.requesterId, 30)}` : ""} (${l.locators.join(", ")}) — ${facts.join(", ")}`;
}

function ruleWords(inst: Inst, r: Rule): string {
  return `${r.action === "authorize" ? "AuthorizeSecurityGroupIngress" : "RevokeSecurityGroupIngress"} recorded on ${show(r.groupId, 30)}: ${r.protocol}${r.ports ? ` ${r.ports}` : ""} from ${show(r.source, 60)}${r.anySource ? " (any address)" : ""} ${whoAt(r.time, r.by, r.locator)}${orderWords(orderOf(inst, r.time))}`;
}

function sessionWords(inst: Inst, coverage: { records: number; first: string; last: string }): string[] {
  const sess = inst.session;
  if (!sess.first || !sess.last)
    return [
      `no call using instance-role credentials among the ${plural(coverage.records, "record")} of this upload (${coverage.first.slice(0, 19)}Z → ${coverage.last.slice(0, 19)}Z)`,
    ];
  const sources = [...sess.sources.values()].sort((a, b) => a.first.time - b.first.time);
  const beyond = sources.length - Math.min(sources.length, SOURCES_NAMED_MAX) + sess.overflowSources.size;
  const shapeLine = (label: string, h: ShapeHit) =>
    `${label} by the instance-role credentials: ${show(h.call, 120)} at ${iso(h.time)} (${h.locator})`;
  const enumeration = enumerationWindow(sess.enumeration);
  return [
    `API calls using instance-role credentials: ${plural(sess.records, "record")} ${iso(sess.first.time)} (${sess.first.locator}) → ${iso(sess.last.time)} (${sess.last.locator})`,
    `sourceIPAddress recorded on these calls: ${sources
      .slice(0, SOURCES_NAMED_MAX)
      .map(
        (s) =>
          `${show(s.address, 45) || "(no address)"}${s.agent ? ` ${show(s.agent, 40)}` : ""} first ${iso(s.first.time)} (${s.first.locator}, ${plural(s.records, "record")})`,
      )
      .join(
        "; ",
      )}${beyond ? `; +${plural(beyond, "more source")}` : ""}${sess.untrackedRecords ? `; ${plural(sess.untrackedRecords, "record")} from untracked sources` : ""}`,
    ...(sess.shapes["privileged-change"].earliest
      ? [shapeLine("privileged change", sess.shapes["privileged-change"].earliest)]
      : []),
    ...(sess.shapes["remote-execution"].earliest
      ? [shapeLine("remote execution", sess.shapes["remote-execution"].earliest)]
      : []),
    ...(enumeration ? [shapeLine("enumeration", enumeration)] : []),
    ...(sess.attempts ? [`${plural(sess.attempts, "denied call")} of these shapes — not counted`] : []),
  ];
}

export function summaryRow(
  inst: Inst,
  facts: readonly AwsComputeFact[],
  grade: Severity,
  coverage: { records: number; first: string; last: string },
  uploadId: string,
): MappedEvent {
  const lifecycle = inst.lifecycle.all();
  const rules = [...inst.rules.values()]
    .flatMap((b) => b.all())
    .sort((a, b) => a.time - b.time || a.locator.localeCompare(b.locator));
  const rulesBeyond = [...inst.rules.values()].reduce((n, b) => n + b.beyond, 0);
  const changes = [
    ...lifecycle.map((e) => ({ time: e.time, words: lifecycleWords(inst, e) })),
    ...rules.map((r) => ({ time: r.time, words: ruleWords(inst, r) })),
  ].sort((a, b) => a.time - b.time);
  const changesBeyond = Math.max(0, changes.length - CHANGES_NAMED_MAX) + inst.lifecycle.beyond + rulesBeyond;
  const parts = [
    inst.launch ? launchWords(inst.launch) : "launch not in this upload",
    ...(changes.length
      ? [
          `recorded configuration changes${changesBeyond ? ` (${Math.min(changes.length, CHANGES_NAMED_MAX)} named, ${changesBeyond} further not individually named)` : ""}: ${changes
            .slice(0, CHANGES_NAMED_MAX)
            .map((c) => c.words)
            .join("; ")}`,
        ]
      : []),
    ...inst.addresses.map((a) =>
      a.action === "associate"
        ? `AssociateAddress: ${[a.allocationId ? `allocation ${show(a.allocationId, 30)}` : "", a.address ? `address ${show(a.address, 45)}` : ""].filter(Boolean).join(", ") || "(no allocation or address named)"}${a.associationId ? ` → association ${show(a.associationId, 30)}` : ""} ${whoAt(a.time, a.by, a.locator)}`
        : `DisassociateAddress: association ${show(a.associationId ?? "", 30)} ${whoAt(a.time, a.by, a.locator)}`,
    ),
    ...(inst.addressesBeyond ? [`+${plural(inst.addressesBeyond, "further address record")}`] : []),
    ...sessionWords(inst, coverage),
    ...(inst.remote.length
      ? [
          `remote-access requests (requested; whether anything ran is not in CloudTrail): ${inst.remote
            .slice()
            .sort((a, b) => a.time - b.time)
            .map(
              (r) =>
                `${show(r.call, 50)}${r.document ? ` [${show(r.document, 40)}]` : ""} ${whoAt(r.time, r.by, r.locator)}`,
            )
            .join("; ")}${inst.remoteBeyond ? `; +${plural(inst.remoteBeyond, "more request")}` : ""}`,
        ]
      : []),
    ...(inst.attempts.denied || inst.attempts.failed
      ? [`attempts: ${inst.attempts.denied} denied, ${inst.attempts.failed} failed — not joined`]
      : []),
  ];
  const factWords = facts.length
    ? `recorded facts: ${facts.map((f) => FACT_WORDS[f]).join(", ")} (${plural(facts.length, "kind")})`
    : "recorded facts: none";
  const cited = [...new Set([...(inst.launch?.locators ?? []), ...inst.locators])].slice(0, RAW_RECORDS_MAX);
  const contributing = new Set([...(inst.launch?.locators ?? []), ...inst.locators]).size;
  const notCited = Math.max(0, contributing - cited.length);
  // The sequence and the facts the grade rests on are packed with the tail, never clipped.
  const tail = [
    ...(correlatedSequence(lifecycle)
      ? ["a correlated API sequence: stop, startup configuration replaced, start"]
      : []),
    factWords,
    ...(notCited ? [`${plural(notCited, "further record")} not individually cited`] : []),
    LIMIT_NOTE,
    COVERAGE_NOTE,
    inst.terminatedAt !== null ? `terminated ${iso(inst.terminatedAt)}` : "not terminated within this upload",
  ].join("; ");
  const head = `AWS compute lifecycle: ${show(inst.id, 30)} (account ${show(inst.account, 12)}, ${show(inst.region, 20)})`;
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(
      `${inst.account.length}:${inst.account}|${inst.region.length}:${inst.region}|${inst.id.length}:${inst.id}|${uploadId.length}:${uploadId}`,
    )
    .digest("hex")
    .slice(0, 32);
  const sess = inst.session;
  const block: AwsComputeBlock = {
    instanceId: inst.id,
    account: inst.account,
    region: inst.region,
    ...(inst.launch ? { launch: (({ time, ...rest }) => ({ ...rest, time: iso(time) }))(inst.launch) } : {}),
    lifecycle: lifecycle.map(({ time, ...e }) => {
      const order = orderOf(inst, time);
      return { ...e, time: iso(time), ...(order ? { order } : {}) };
    }),
    lifecycleBeyond: inst.lifecycle.beyond,
    rules: rules.map(({ time, ...r }) => {
      const order = orderOf(inst, time);
      return { ...r, time: iso(time), ...(order ? { order } : {}) };
    }),
    rulesBeyond,
    addresses: inst.addresses.map(({ time, ...a }) => ({ ...a, time: iso(time) })),
    ...(sess.first && sess.last
      ? {
          session: {
            records: sess.records,
            first: { time: iso(sess.first.time), locator: sess.first.locator },
            last: { time: iso(sess.last.time), locator: sess.last.locator },
            sources: [...sess.sources.values()]
              .sort((a, b) => a.first.time - b.first.time)
              .map((s) => ({
                address: s.address,
                agent: s.agent,
                firstUse: { time: iso(s.first.time), locator: s.first.locator },
                records: s.records,
              })),
            sourcesBeyond: sess.overflowSources.size,
            shapes: [
              ...(sess.shapes["privileged-change"].earliest
                ? [sess.shapes["privileged-change"].earliest]
                : []),
              ...(sess.shapes["remote-execution"].earliest ? [sess.shapes["remote-execution"].earliest] : []),
              ...(enumerationWindow(sess.enumeration) ? [enumerationWindow(sess.enumeration)!] : []),
            ].map((h) => ({ kind: h.kind, time: iso(h.time), locator: h.locator, call: h.call })),
            attempts: sess.attempts,
          },
        }
      : {}),
    remote: inst.remote.map(({ time, ...r }) => ({ ...r, time: iso(time) })),
    remoteBeyond: inst.remoteBeyond,
    attempts: { ...inst.attempts },
    facts: [...facts],
    terminated: inst.terminatedAt !== null,
    notCited,
    coverage,
    basis: BASIS,
  };
  const observedAt = inst.launch?.time ?? lifecycle[0]?.time ?? sess.first?.time ?? 0;
  const observed = iso(observedAt);
  const mitre =
    grade === "Low"
      ? []
      : [...new Set([...(inst.launch ? ["T1578.002"] : []), ...facts.map((f) => FACT_MITRE[f])])];
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre,
    aggKey: boundedAggKey(`aws-compute-lifecycle|${identity}`),
    sources: ["AWS CloudTrail"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "compute-lifecycle", action: "lifecycle", outcome: "success" },
      actor: { kind: "account", name: inst.launch?.by ?? inst.id },
      ...(inst.launch?.address ? { network: { source: { address: inst.launch.address } } } : {}),
      ...(inst.launch?.credentialId ? { authentication: { credentialId: inst.launch.credentialId } } : {}),
      cloud: { provider: "aws", accountId: inst.account, region: inst.region, resource: inst.id },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: { rawRecords: cited.map((l) => ({ source: "cloudtrail", locator: l })) },
      producer: {
        importer: "aws-cloudtrail",
        parserVersion: "1",
        mappingVersion: "aws-compute-lifecycle-v1",
        ruleVersions: ["aws-compute-v1"],
      },
      awsCompute: block,
    }),
  };
}

export function omittedRow(count: number, severity: Severity, untracked: number): MappedEvent {
  const description = `AWS compute lifecycle — ${count} further instance${count === 1 ? "" : "s"} with a lifecycle in this upload beyond the ${AWS_COMPUTE_MAX} reported — not shown${untracked ? ` (${untracked} of them past the ${INSTANCES_TRACKED_MAX} tracked, their records not read)` : ""}`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`aws-compute-lifecycle|omitted|${count}`),
    sources: ["AWS CloudTrail"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "compute-lifecycle", action: "omitted" },
      cloud: { provider: "aws" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "cloudtrail", locator: "omitted" }] },
      producer: {
        importer: "aws-cloudtrail",
        parserVersion: "1",
        mappingVersion: "aws-compute-lifecycle-v1",
      },
    }),
  };
}
