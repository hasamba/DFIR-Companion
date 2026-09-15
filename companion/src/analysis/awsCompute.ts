// AWS compute lifecycle (#931 item 8): what one CloudTrail upload records about one EC2 instance —
// the launch facts as the RunInstances response states them, every later record that names the
// instance, the ingress rules recorded on the groups it holds, the address associations its
// records name, the calls signed with its own instance-role credentials, and the remote-access
// requests to it — built over the records of ONE upload inside the importer, the shape the
// credential lineage (awsLineage.ts, #979) landed on.
//
// What one row rests on, and what it never says:
//   - identity: (owning account, region, instance id); the account is the launch response's
//     ownerId, else the record's recipient account — never the caller's; an image id, a group
//     name or a session name joins nothing;
//   - the instance's own session joins only as AssumedRole with ec2RoleDelivery set, the instance
//     id as the session suffix of BOTH principalId and the ARN, and the instance's account — a
//     human-named `i-…` session never joins;
//   - a security-group record is what it recorded, never the group's state; a state call is the
//     record's own transition; "before" / "after the launch" only on strictly ordered timestamps;
//   - a startup configuration is "supplied", "removed by CloudTrail" or "not in this record" —
//     never "none", and its content never reaches the row, the key or the envelope;
//   - the grade counts distinct recorded-fact kinds: two or more → High, one → Medium, none → Low;
//     no single CloudTrail record makes a High; a denied or failed call joins nothing;
//   - what ran on the instance and its network egress are not in CloudTrail, and the row says so.

import type { Severity } from "./stateTypes.js";
import type { AwsComputeFact, AwsComputeLaunch } from "./canonicalAwsCompute.js";
import { readAwsIdentity, type AwsIdentity } from "./awsIdentity.js";
import {
  enumerationWindow,
  serviceOf,
  shapeOf,
  trackEnumerationInto,
  SOURCES_PER_KEY_MAX,
  type ShapeHit,
} from "./awsLineage.js";
import { cleanIp, getCI, isObject, normalizeTime, str, type MappedEvent } from "./siemImport.js";
import {
  ADDRESSES_MAX,
  ANY_SOURCE,
  ATTRIBUTES,
  AWS_COMPUTE_MAX,
  EdgeBuffer,
  GROUPS_MAX,
  INSTANCE_ID,
  OVERFLOW_SOURCES_MAX,
  RANK,
  REMOTE_MAX,
  RULES_EARLY_MAX,
  RULES_LATE_MAX,
  RULE_SOURCES_PER_RECORD_MAX,
  SHAPES_NAMED_MAX,
  cite,
  field,
  firstTime,
  groupsAt,
  identityWords,
  instFor,
  items,
  keepEarliest,
  lower,
  ms,
  noteFact,
  orderOf,
  outcomeOf,
  strings,
  type Address,
  type Inst,
  type Lifecycle,
  type Outcome,
  type Row,
  type Rule,
  type Source,
  type Timed,
  type Tracked,
} from "./awsComputeState.js";
import { omittedRow, summaryRow } from "./awsComputeRow.js";

export {
  AWS_COMPUTE_MAX,
  INSTANCES_TRACKED_MAX,
  LIFECYCLE_EARLY_MAX,
  LIFECYCLE_LATE_MAX,
} from "./awsComputeState.js";

// ───────────────────────────── scanning ─────────────────────────────

/** Replica locators kept per shared event — a pathological sharedEventID never grows a list. */
const REPLICA_LOCATORS_MAX = 8;

interface Scanned {
  rec: Row;
  index: number;
  time: number;
  who: AwsIdentity;
  /** Every replica record's locator (bounded) — a cross-account action cites each. */
  locators: string[];
  locator: string;
  request: Row;
  response: Row;
  outcome: Outcome;
  name: string;
  service: string;
  account: string;
  region: string;
  by: string;
}

/**
 * One record per cross-account action (replicas grouped by sharedEventID; the informative one
 * read; every replica cited), in time order with the record position as the tie-breaker — so
 * nothing downstream depends on the file's order. Coverage counts every raw record with a time.
 */
function scan(
  records: readonly Row[],
  coverage: { records: number; first: string; last: string },
): Scanned[] {
  const chosen = new Map<string, Scanned>();
  records.forEach((rec, index) => {
    const name = str(getCI(rec, "eventName")).trim();
    const source = str(getCI(rec, "eventSource")).trim();
    if (!name || !source) return;
    const time = ms(str(getCI(rec, "eventTime")));
    if (time === null) return;
    const t = normalizeTime(str(getCI(rec, "eventTime")));
    coverage.records += 1;
    if (!coverage.first || t < coverage.first) coverage.first = t;
    if (!coverage.last || t > coverage.last) coverage.last = t;
    const who = readAwsIdentity(rec);
    const replica = str(getCI(rec, "sharedEventID")).trim();
    const own = str(getCI(rec, "eventID")).trim();
    const id = replica ? `shared:${replica}` : own ? `event:${own}` : `record:${index}`;
    const locator = `record:${index}`;
    const request = isObject(getCI(rec, "requestParameters")) ? (getCI(rec, "requestParameters") as Row) : {};
    const response = isObject(getCI(rec, "responseElements")) ? (getCI(rec, "responseElements") as Row) : {};
    const entry: Scanned = {
      rec,
      index,
      time,
      who,
      locators: [locator],
      locator,
      request,
      response,
      outcome: outcomeOf(rec),
      name,
      service: serviceOf(source),
      account: str(getCI(rec, "recipientAccountId")).trim(),
      region: str(getCI(rec, "awsRegion")).trim(),
      by: identityWords(who),
    };
    const cur = chosen.get(id);
    const informative = !["AWSAccount", "AWSService", "Unknown"].includes(who.kind);
    if (!cur) {
      chosen.set(id, entry);
      return;
    }
    const swap = informative && ["AWSAccount", "AWSService", "Unknown"].includes(cur.who.kind);
    const kept = swap ? entry : cur;
    kept.locators = [...cur.locators, locator].slice(0, REPLICA_LOCATORS_MAX);
    // The response facts live on whichever replica carries them.
    if (Object.keys(kept.response).length === 0) kept.response = swap ? cur.response : entry.response;
    if (!kept.account) kept.account = swap ? cur.account : entry.account;
    chosen.set(id, kept);
  });
  return [...chosen.values()].sort((a, b) => a.time - b.time || a.index - b.index);
}

// ───────────────────────────── pass 1: the launches ─────────────────────────────

function launchFacts(s: Scanned, item: Row): Omit<AwsComputeLaunch, "time"> & Timed {
  const userData = getCI(s.request, "userData");
  const startupConfig: AwsComputeLaunch["startupConfig"] =
    userData === undefined || userData === null
      ? "not-in-record"
      : /sensitivedataremoved/i.test(str(userData))
        ? "removed-by-cloudtrail"
        : "supplied";
  const address = cleanIp(str(getCI(s.rec, "sourceIPAddress")));
  const agent = str(getCI(s.rec, "userAgent")).trim();
  const requesterId = field(s.response, "requesterId");
  const groups = items(getCI(item, "groupSet"))
    .map((g) => ({
      id: field(g, "groupId"),
      ...(field(g, "groupName") ? { name: field(g, "groupName") } : {}),
    }))
    .filter((g) => g.id)
    .slice(0, GROUPS_MAX);
  const opt = (k: string, v: string): Record<string, string> => (v ? { [k]: v } : {});
  return {
    time: s.time,
    locators: s.locators,
    by: s.by,
    ...opt("credentialId", s.who.credential.accessKeyId || s.who.credential.credentialId),
    ...opt("address", address),
    ...opt("agent", agent),
    ...opt("invokedBy", s.who.invokedBy),
    ...opt("requesterId", requesterId),
    ...opt("image", field(item, "imageId")),
    ...opt("type", field(item, "instanceType")),
    ...opt("keyName", field(item, "keyName")),
    ...opt("profile", field(item, "iamInstanceProfile", "arn") || field(item, "iamInstanceProfile", "name")),
    groups,
    ...opt("subnet", field(item, "subnetId")),
    ...opt("vpc", field(item, "vpcId")),
    ...opt("privateAddress", field(item, "privateIpAddress")),
    ...opt("availabilityZone", field(item, "placement", "availabilityZone")),
    startupConfig,
  };
}

/** Launches fill the tracked table first (in time order), so an instance that always emits is never displaced by a lone reference. */
function recordLaunch(t: Tracked, s: Scanned): void {
  if (lower(s.name) !== "runinstances" || s.outcome !== "success") return;
  const account = field(s.response, "ownerId") || s.account;
  if (!account || !s.region) return;
  for (const item of items(getCI(s.response, "instancesSet"))) {
    const id = field(item, "instanceId");
    if (!INSTANCE_ID.test(id)) continue;
    const inst = instFor(t, account, s.region, id);
    if (!inst) continue;
    if (!inst.launch) {
      inst.launch = launchFacts(s, item);
      inst.groupSets.push({
        time: s.time,
        locator: s.locator,
        groups: inst.launch.groups.map((g) => lower(g.id)),
      });
    }
    cite(inst, s.locators);
  }
}

// ───────────────────────────── pass 2: records that name the instance ─────────────────────────────

const noteAttempt = (inst: Inst, outcome: Outcome): void => {
  if (outcome === "denied") inst.attempts.denied += 1;
  else if (outcome === "failed") inst.attempts.failed += 1;
};

function pushLifecycle(
  inst: Inst,
  s: Scanned,
  entry: Omit<Lifecycle, "time" | "locator" | "by" | "call">,
): void {
  inst.lifecycle.push({ ...entry, call: s.name, time: s.time, locator: s.locator, by: s.by });
  cite(inst, s.locators);
  // The facts are noted on every record, not read back from the retained buffer — and only after the launch.
  if (orderOf(inst, s.time) !== "after") return;
  if (entry.kind === "startup-config-replaced") noteFact(inst, "startup-config-replaced", s.time, s.locator);
  if (entry.kind === "profile-associated" || entry.kind === "profile-replaced")
    noteFact(inst, "profile-changed", s.time, s.locator);
}

function recordState(t: Tracked, s: Scanned): void {
  const kind = (
    {
      startinstances: "start",
      stopinstances: "stop",
      rebootinstances: "reboot",
      terminateinstances: "terminate",
    } as const
  )[lower(s.name)];
  if (!kind) return;
  const transitions = new Map(
    items(getCI(s.response, "instancesSet")).map((i) => [
      lower(field(i, "instanceId")),
      { from: field(i, "previousState", "name"), to: field(i, "currentState", "name") },
    ]),
  );
  for (const item of items(getCI(s.request, "instancesSet"))) {
    const id = field(item, "instanceId");
    if (!INSTANCE_ID.test(id) || !s.account || !s.region) continue;
    const inst = instFor(t, s.account, s.region, id);
    if (!inst) continue;
    if (s.outcome !== "success") {
      noteAttempt(inst, s.outcome);
      continue;
    }
    const tr = kind === "reboot" ? undefined : transitions.get(lower(id));
    pushLifecycle(inst, s, { kind, ...(tr && (tr.from || tr.to) ? { transition: tr } : {}) });
    if (kind === "terminate" && (inst.terminatedAt === null || s.time < inst.terminatedAt))
      inst.terminatedAt = s.time;
  }
}

function recordModify(t: Tracked, s: Scanned): void {
  if (lower(s.name) !== "modifyinstanceattribute") return;
  const id = field(s.request, "instanceId");
  if (!INSTANCE_ID.test(id) || !s.account || !s.region) return;
  const inst = instFor(t, s.account, s.region, id);
  if (!inst) return;
  if (s.outcome !== "success") return noteAttempt(inst, s.outcome);
  const attribute = lower(field(s.request, "attribute"));
  const has = (k: string): boolean => getCI(s.request, k) !== undefined || attribute === lower(k);
  // The content of a startup configuration is never read — only that the call replaced one.
  if (has("userData")) return pushLifecycle(inst, s, { kind: "startup-config-replaced" });
  if (has("groupSet")) {
    // A group set REPLACES the instance's groups: a new membership statement from this time on.
    const groups = items(getCI(s.request, "groupSet"))
      .map((g) => field(g, "groupId"))
      .filter(Boolean)
      .slice(0, GROUPS_MAX);
    if (
      !keepEarliest(
        inst.groupSets,
        { time: s.time, locator: s.locator, groups: groups.map(lower) },
        GROUPS_MAX,
      )
    )
      inst.groupSetsBeyond += 1;
    return pushLifecycle(inst, s, { kind: "groups-set", groups });
  }
  if (has("disableApiTermination")) return pushLifecycle(inst, s, { kind: "termination-protection" });
  if (has("instanceType")) return pushLifecycle(inst, s, { kind: "type-changed" });
  const named = [...ATTRIBUTES].find((a) => attribute === a || getCI(s.request, a) !== undefined);
  pushLifecycle(inst, s, { kind: "attribute-modified", attribute: named ?? "other" });
}

/** All three profile operations read the instance, the profile and the state from the returned association — the authoritative one. */
function recordProfile(t: Tracked, s: Scanned): void {
  const kind = (
    {
      associateiaminstanceprofile: "profile-associated",
      replaceiaminstanceprofileassociation: "profile-replaced",
      disassociateiaminstanceprofile: "profile-disassociated",
    } as const
  )[lower(s.name)];
  if (!kind) return;
  const assoc = isObject(getCI(s.response, "iamInstanceProfileAssociation"))
    ? (getCI(s.response, "iamInstanceProfileAssociation") as Row)
    : null;
  // A failed Associate still names the instance in its request — an attempt on that instance.
  if (s.outcome !== "success") {
    const id = kind === "profile-associated" ? field(s.request, "instanceId") : "";
    if (INSTANCE_ID.test(id) && s.account && s.region) {
      const inst = instFor(t, s.account, s.region, id);
      if (inst) noteAttempt(inst, s.outcome);
    }
    return;
  }
  if (!assoc) return;
  const id = field(assoc, "instanceId");
  if (!INSTANCE_ID.test(id) || !s.account || !s.region) return;
  const inst = instFor(t, s.account, s.region, id);
  if (!inst) return;
  const profile =
    field(assoc, "iamInstanceProfile", "arn") ||
    field(s.request, "iamInstanceProfile", "arn") ||
    field(s.request, "iamInstanceProfile", "name");
  const state = field(assoc, "state");
  pushLifecycle(inst, s, {
    kind,
    ...(profile && kind !== "profile-disassociated" ? { profile } : {}),
    ...(state ? { associationState: state } : {}),
  });
}

function pushAddress(inst: Inst, s: Scanned, entry: Omit<Address, "time" | "locator" | "by">): void {
  if (!keepEarliest(inst.addresses, { ...entry, time: s.time, locator: s.locator, by: s.by }, ADDRESSES_MAX))
    inst.addressesBeyond += 1;
  cite(inst, s.locators);
}

function recordAssociate(t: Tracked, s: Scanned): void {
  if (lower(s.name) !== "associateaddress" || !s.account || !s.region) return;
  const id = field(s.request, "instanceId");
  if (!INSTANCE_ID.test(id)) return;
  const inst = instFor(t, s.account, s.region, id);
  if (!inst) return;
  if (s.outcome !== "success") return noteAttempt(inst, s.outcome);
  const associationId = field(s.response, "associationId");
  const allocationId = field(s.request, "allocationId");
  const address = field(s.request, "publicIp");
  pushAddress(inst, s, {
    action: "associate",
    ...(allocationId ? { allocationId } : {}),
    ...(address ? { address } : {}),
    ...(associationId ? { associationId } : {}),
  });
}

/** The instance ids a remote-access request names exactly — a tag selector never names one. */
function remoteTargets(s: Scanned): string[] {
  const name = lower(s.name);
  if (s.service === "ssm" && name === "sendcommand") {
    const ids = strings(getCI(s.request, "instanceIds"));
    for (const t of items(getCI(s.request, "targets")))
      if (lower(field(t, "key")) === "instanceids") ids.push(...strings(getCI(t, "values")));
    return ids;
  }
  if (s.service === "ssm" && name === "startsession") return strings(getCI(s.request, "target"));
  if (s.service === "ec2-instance-connect" && name === "sendsshpublickey")
    return strings(getCI(s.request, "instanceId"));
  return [];
}

function recordRemote(t: Tracked, s: Scanned): void {
  const ids = remoteTargets(s).filter((id) => INSTANCE_ID.test(id));
  if (ids.length === 0 || !s.account || !s.region) return;
  const document = field(s.request, "documentName");
  for (const id of new Set(ids.map(lower))) {
    const inst = instFor(t, s.account, s.region, id);
    if (!inst) continue;
    if (s.outcome !== "success") {
      noteAttempt(inst, s.outcome);
      continue;
    }
    const entry = {
      call: `${s.service} ${s.name}`,
      ...(document ? { document } : {}),
      time: s.time,
      locator: s.locator,
      by: s.by,
    };
    if (!keepEarliest(inst.remote, entry, REMOTE_MAX)) inst.remoteBeyond += 1;
    noteFact(inst, "remote-access-request", s.time, s.locator);
    cite(inst, s.locators);
  }
}

// ───────────────────────────── pass 3: rules on the groups, disassociations, the instance's own session ─────────────────────────────

interface Permission {
  protocol: string;
  ports: string;
  source: string;
  anySource: boolean;
}
/** Every (permission, source) pair of an ingress request, as recorded: the first few retained for the words, ALL read for the any-source fact. */
function permissions(request: Row): { retained: Permission[]; anySource: boolean; total: number } {
  const retained: Permission[] = [];
  let anySource = false;
  let total = 0;
  for (const p of items(getCI(request, "ipPermissions"))) {
    const proto = field(p, "ipProtocol");
    const protocol = proto === "-1" ? "all protocols" : proto || "protocol not recorded";
    const from = field(p, "fromPort");
    const to = field(p, "toPort");
    const ports = from && to && from !== to ? `${from}-${to}` : from || to;
    const push = (source: string, any: boolean): void => {
      if (!source) return;
      total += 1;
      anySource = anySource || any;
      if (retained.length < RULE_SOURCES_PER_RECORD_MAX)
        retained.push({ protocol, ports, source, anySource: any });
    };
    for (const r of items(getCI(p, "ipRanges"))) push(field(r, "cidrIp"), ANY_SOURCE.has(field(r, "cidrIp")));
    for (const r of items(getCI(p, "ipv6Ranges")))
      push(field(r, "cidrIpv6"), ANY_SOURCE.has(field(r, "cidrIpv6")));
    for (const g of items(getCI(p, "groups")))
      push(
        `group ${field(g, "groupId") || field(g, "groupName")}${field(g, "userId") ? ` (owner ${field(g, "userId")})` : ""}`,
        false,
      );
    for (const l of items(getCI(p, "prefixListIds"))) push(`prefix list ${field(l, "prefixListId")}`, false);
  }
  return { retained, anySource, total };
}

function recordRule(byGroup: Map<string, Inst[]>, s: Scanned): void {
  const action = (
    { authorizesecuritygroupingress: "authorize", revokesecuritygroupingress: "revoke" } as const
  )[lower(s.name)];
  if (!action || s.service !== "ec2" || s.outcome !== "success") return;
  // A group-name-only request is not joined: the name is a label, the id the identity.
  const groupId = field(s.request, "groupId");
  if (!groupId || !s.account || !s.region) return;
  const holders = byGroup.get(`${lower(s.account)}|${lower(s.region)}|${lower(groupId)}`) ?? [];
  const perms = permissions(s.request);
  for (const inst of holders) {
    // Joined only against the membership statement in force at the rule's time.
    if (!groupsAt(inst, s.time, s.locator)?.includes(lower(groupId))) continue;
    const buf = inst.rules.get(lower(groupId)) ?? new EdgeBuffer<Rule>(RULES_EARLY_MAX, RULES_LATE_MAX);
    inst.rules.set(lower(groupId), buf);
    for (const p of perms.retained)
      buf.push({ groupId, action, ...p, time: s.time, locator: s.locator, by: s.by });
    buf.count += perms.total - perms.retained.length;
    if (action === "authorize" && perms.anySource) noteFact(inst, "any-address-rule", s.time, s.locator);
    cite(inst, s.locators);
  }
}

/** A disassociation joins only through an association id one of this instance's retained associations returned. */
function recordDisassociate(byAssociation: Map<string, Inst[]>, s: Scanned): void {
  if (lower(s.name) !== "disassociateaddress" || s.outcome !== "success" || !s.account || !s.region) return;
  const associationId = field(s.request, "associationId");
  if (!associationId) return;
  for (const inst of byAssociation.get(`${lower(s.account)}|${lower(s.region)}|${lower(associationId)}`) ??
    [])
    pushAddress(inst, s, { action: "disassociate", associationId });
}

/** The instance's own session: AssumedRole, ec2RoleDelivery set, the id as the suffix of BOTH principalId and the ARN, the instance's account. */
function ownSessionInstance(who: AwsIdentity): string {
  if (who.kind !== "AssumedRole" || !who.session.ec2RoleDelivery) return "";
  const fromPrincipal = who.session.name;
  const fromArn = who.arn.slice(who.arn.lastIndexOf("/") + 1);
  return INSTANCE_ID.test(fromPrincipal) && lower(fromPrincipal) === lower(fromArn) ? fromPrincipal : "";
}

function trackSource(
  sess: Inst["session"],
  sk: string,
  address: string,
  agent: string,
  time: number,
  locator: string,
): void {
  const src = sess.sources.get(sk);
  if (src) {
    src.records += 1;
    if (time < src.first.time) src.first = { time, locator };
    return;
  }
  if (sess.sources.size < SOURCES_PER_KEY_MAX) {
    sess.sources.set(sk, { address, agent, first: { time, locator }, records: 1 });
    return;
  }
  let latest: [string, Source] | null = null;
  for (const e of sess.sources) if (!latest || e[1].first.time > latest[1].first.time) latest = e;
  if (latest && time < latest[1].first.time) {
    sess.sources.delete(latest[0]);
    sess.overflowSources.add(latest[0]);
    sess.sources.set(sk, { address, agent, first: { time, locator }, records: 1 });
    return;
  }
  if (sess.overflowSources.size < OVERFLOW_SOURCES_MAX) sess.overflowSources.add(sk);
  else sess.untrackedRecords += 1;
}

function recordSession(byAccountId: Map<string, Inst[]>, s: Scanned): void {
  const id = ownSessionInstance(s.who);
  const caller = s.who.accounts.caller;
  if (!id || !caller) return;
  for (const inst of byAccountId.get(`${lower(caller)}|${lower(id)}`) ?? []) {
    const sess = inst.session;
    sess.records += 1;
    if (!sess.first || s.time < sess.first.time) sess.first = { time: s.time, locator: s.locator };
    if (!sess.last || s.time > sess.last.time) sess.last = { time: s.time, locator: s.locator };
    const address =
      cleanIp(str(getCI(s.rec, "sourceIPAddress"))) || str(getCI(s.rec, "sourceIPAddress")).trim();
    const agent = str(getCI(s.rec, "userAgent")).trim();
    trackSource(sess, `${address}|${agent}`, address, agent, s.time, s.locator);
    cite(inst, s.locators);
    const kind = shapeOf(str(getCI(s.rec, "eventSource")), s.name);
    if (!kind) continue;
    if (s.outcome !== "success") {
      sess.attempts += 1;
      continue;
    }
    const hit: ShapeHit = { kind, time: s.time, locator: s.locator, call: `${s.service} ${s.name}` };
    if (kind === "enumeration") {
      trackEnumerationInto(sess.enumeration, hit);
      continue;
    }
    const slot = sess.shapes[kind];
    slot.count += 1;
    if (!slot.earliest || s.time < slot.earliest.time) slot.earliest = hit;
    if (slot.named.length < SHAPES_NAMED_MAX) slot.named.push(hit);
    noteFact(
      inst,
      kind === "privileged-change" ? "session-privileged-change" : "session-remote-execution",
      s.time,
      s.locator,
    );
  }
}

// ───────────────────────────── the pass ─────────────────────────────

const index = (map: Map<string, Inst[]>, key: string, inst: Inst): void => {
  (map.get(key) ?? map.set(key, []).get(key)!).push(inst);
};

/** One summary row per instance the upload's records form a lifecycle for; the rows say what they rest on. */
export function awsComputeLifecycles(records: readonly Row[], uploadId: string): MappedEvent[] {
  const t: Tracked = { instances: new Map(), untrackedRecords: 0 };
  const coverage = { records: 0, first: "", last: "" };
  const scanned = scan(records, coverage);
  const own = scanned.filter(
    (s) => s.service === "ec2" || s.service === "ssm" || s.service === "ec2-instance-connect",
  );
  // Pass 1: the launches, so a launched instance is always tracked and its launch time is known
  // before any later record is ordered against it.
  for (const s of own) recordLaunch(t, s);
  // Pass 2: every other record that names the instance in its own request or response.
  for (const s of own) {
    recordState(t, s);
    recordModify(t, s);
    recordProfile(t, s);
    recordAssociate(t, s);
    recordRemote(t, s);
  }
  // Pass 3: the records joined through what the instance's own records established.
  const byGroup = new Map<string, Inst[]>();
  const byAccountId = new Map<string, Inst[]>();
  const byAssociation = new Map<string, Inst[]>();
  for (const inst of t.instances.values()) {
    for (const g of new Set(inst.groupSets.flatMap((gs) => gs.groups)))
      index(byGroup, `${inst.account}|${inst.region}|${g}`, inst);
    index(byAccountId, `${inst.account}|${lower(inst.id)}`, inst);
    for (const a of inst.addresses)
      if (a.action === "associate" && a.associationId)
        index(byAssociation, `${inst.account}|${inst.region}|${lower(a.associationId)}`, inst);
  }
  for (const s of scanned) {
    recordRule(byGroup, s);
    recordDisassociate(byAssociation, s);
    recordSession(byAccountId, s);
  }
  for (const inst of t.instances.values())
    if (enumerationWindow(inst.session.enumeration)) {
      const w = enumerationWindow(inst.session.enumeration)!;
      noteFact(inst, "session-enumeration", w.time, w.locator);
    }
  const findings = [...t.instances.values()]
    .map((inst) => ({ inst, facts: [...inst.facts.keys()] as AwsComputeFact[] }))
    .filter(({ inst, facts }) => inst.launch || inst.lifecycle.count >= 2 || facts.length > 0)
    .map((f) => ({ ...f, grade: gradeOf(f.facts) }))
    .sort(
      (a, b) =>
        RANK[b.grade] - RANK[a.grade] ||
        firstTime(a.inst) - firstTime(b.inst) ||
        a.inst.id.localeCompare(b.inst.id) ||
        a.inst.account.localeCompare(b.inst.account) ||
        a.inst.region.localeCompare(b.inst.region),
    );
  const rows = findings
    .slice(0, AWS_COMPUTE_MAX)
    .map((f) => summaryRow(f.inst, f.facts, f.grade, coverage, uploadId));
  const omitted = Math.max(0, findings.length - AWS_COMPUTE_MAX);
  if (omitted > 0 || t.untrackedRecords > 0)
    rows.push(omittedRow(omitted, findings[AWS_COMPUTE_MAX]?.grade ?? "Low", t.untrackedRecords, uploadId));
  return rows;
}

/** Two or more distinct recorded-fact kinds → High; one → Medium; none → Low. */
const gradeOf = (facts: readonly AwsComputeFact[]): Severity =>
  facts.length >= 2 ? "High" : facts.length === 1 ? "Medium" : "Low";
