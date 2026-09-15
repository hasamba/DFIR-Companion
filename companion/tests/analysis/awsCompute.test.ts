// #931 item 8: the EC2 compute lifecycle built over one CloudTrail upload — the launch facts as
// the record states them, every later record that names the instance, the calls signed with its
// own instance-role credentials, the remote-access requests to it, and nothing the records do
// not say. Secrets never reach the row.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { awsComputeLifecycles, AWS_COMPUTE_MAX } from "../../src/analysis/awsCompute.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ACCT = "111122223333";
const OTHER = "444455556666";
const REGION = "us-east-1";
const INST = "i-0abc123def4567890";
const INST2 = "i-0fed987cba6543210";
const SG = "sg-0aaa111bbb222ccc3";
const SG2 = "sg-0ddd444eee555fff6";
const IP = "203.0.113.5";
const IP_INST = "198.51.100.9";
const T = "2024-05-01T09:00:00Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const USER_DATA = "IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vZXZpbC9wLnNoIHwgc2g=";
let n = 0;

const alice = {
  type: "IAMUser",
  principalId: "AIDAEXAMPLE",
  arn: `arn:aws:iam::${ACCT}:user/alice`,
  accountId: ACCT,
  accessKeyId: "AKIAEXAMPLEKEY000009",
  userName: "alice",
};
const bob = { ...alice, principalId: "AIDAEXAMPLE2", arn: `arn:aws:iam::${ACCT}:user/bob`, userName: "bob" };
/** The instance's own session: the role delivered through IMDS, the session named after the instance. */
const instanceSession = (
  id = INST,
  over: Record<string, unknown> = {},
  sc: Record<string, unknown> = {},
) => ({
  type: "AssumedRole",
  principalId: `AROAEXAMPLEROLE:${id}`,
  arn: `arn:aws:sts::${ACCT}:assumed-role/web-role/${id}`,
  accountId: ACCT,
  accessKeyId: "ASIAEXAMPLEINSTANCE1",
  sessionContext: {
    sessionIssuer: {
      type: "Role",
      principalId: "AROAEXAMPLEROLE",
      arn: `arn:aws:iam::${ACCT}:role/web-role`,
      accountId: ACCT,
      userName: "web-role",
    },
    attributes: { creationDate: T, mfaAuthenticated: "false" },
    ec2RoleDelivery: "2.0",
    ...sc,
  },
  ...over,
});
const rec = (over: Record<string, unknown>): Record<string, unknown> => ({
  eventVersion: "1.08",
  eventTime: T,
  eventSource: "ec2.amazonaws.com",
  eventName: "DescribeInstances",
  awsRegion: REGION,
  sourceIPAddress: IP,
  userAgent: "aws-cli/2.15",
  recipientAccountId: ACCT,
  eventID: `evt-${++n}`,
  userIdentity: alice,
  ...over,
});
const instanceItem = (id = INST, over: Record<string, unknown> = {}) => ({
  instanceId: id,
  imageId: "ami-0123456789abcdef0",
  instanceType: "c5.24xlarge",
  keyName: "deploy-key",
  privateIpAddress: "10.0.1.5",
  subnetId: "subnet-0aaa",
  vpcId: "vpc-0bbb",
  placement: { availabilityZone: "us-east-1a" },
  iamInstanceProfile: { arn: `arn:aws:iam::${ACCT}:instance-profile/web`, id: "AIPAEXAMPLE" },
  groupSet: { items: [{ groupId: SG, groupName: "web" }] },
  instanceState: { code: 0, name: "pending" },
  ...over,
});
const launch = (
  over: Record<string, unknown> = {},
  items = [instanceItem()],
  req: Record<string, unknown> = {},
) =>
  rec({
    eventName: "RunInstances",
    requestParameters: {
      instancesSet: { items: [{ imageId: "ami-0123456789abcdef0", minCount: 1, maxCount: 1 }] },
      instanceType: "c5.24xlarge",
      userData: USER_DATA,
      ...req,
    },
    responseElements: { requestId: "r-1", reservationId: "r-0abc", ownerId: ACCT, instancesSet: { items } },
    ...over,
  });
const state = (name: string, from: string, to: string, over: Record<string, unknown> = {}, id = INST) =>
  rec({
    eventName: name,
    requestParameters: { instancesSet: { items: [{ instanceId: id }] } },
    responseElements: {
      instancesSet: {
        items: [{ instanceId: id, currentState: { name: to }, previousState: { name: from } }],
      },
    },
    ...over,
  });
const modifyUserData = (over: Record<string, unknown> = {}, id = INST) =>
  rec({
    eventName: "ModifyInstanceAttribute",
    requestParameters: { instanceId: id, userData: { value: USER_DATA } },
    responseElements: { _return: true },
    ...over,
  });
const ingress = (groupId = SG, cidr = "0.0.0.0/0", over: Record<string, unknown> = {}) =>
  rec({
    eventName: "AuthorizeSecurityGroupIngress",
    requestParameters: {
      groupId,
      ipPermissions: {
        items: [{ ipProtocol: "tcp", fromPort: 22, toPort: 22, ipRanges: { items: [{ cidrIp: cidr }] } }],
      },
    },
    responseElements: { _return: true },
    ...over,
  });
const sessionCall = (over: Record<string, unknown> = {}, id = INST) =>
  rec({
    eventSource: "sts.amazonaws.com",
    eventName: "GetCallerIdentity",
    eventTime: at(300),
    sourceIPAddress: IP_INST,
    userAgent: "aws-sdk-go/1.44",
    userIdentity: instanceSession(id),
    ...over,
  });
const sendCommand = (targets: Record<string, unknown>, over: Record<string, unknown> = {}) =>
  rec({
    eventSource: "ssm.amazonaws.com",
    eventName: "SendCommand",
    eventTime: at(1800),
    requestParameters: { documentName: "AWS-RunShellScript", ...targets },
    responseElements: { command: { commandId: "cmd-1", status: "Pending" } },
    ...over,
  });
const rows = (records: Record<string, unknown>[], upload = "upload-a") =>
  awsComputeLifecycles(records, upload).filter((e) => e.description.startsWith("AWS compute lifecycle:"));
const imported = (records: Record<string, unknown>[], opts: Record<string, unknown> = {}) =>
  parseCloudTrail(JSON.stringify({ Records: records }), { aggregate: false, ...opts });
const envelopeOf = (row: { canonical?: unknown }) => canonicalEventEnvelopeSchema.parse(row.canonical);

describe("awsComputeLifecycles — the launch facts (#931 item 8)", () => {
  it("one row per launched instance with the facts the response states; the startup configuration is said as supplied, never shown", () => {
    const [row] = rows([launch()]);
    expect(row.description).toContain(`AWS compute lifecycle: ${INST} (account ${ACCT}, ${REGION})`);
    expect(row.description).toContain(
      `launched ${at(0)} by IAMUser arn:aws:iam::${ACCT}:user/alice from ${IP} aws-cli/2.15 (record:0)`,
    );
    expect(row.description).toContain("image ami-0123456789abcdef0");
    expect(row.description).toContain("type c5.24xlarge");
    expect(row.description).toContain("key pair deploy-key");
    expect(row.description).toContain(`instance profile arn:aws:iam::${ACCT}:instance-profile/web`);
    expect(row.description).toContain(`groups ${SG} (web)`);
    expect(row.description).toContain("subnet subnet-0aaa in vpc-0bbb");
    expect(row.description).toContain("private address 10.0.1.5");
    expect(row.description).toContain("availability zone us-east-1a");
    expect(row.description).toContain("startup configuration supplied (content not shown)");
    expect(row.description).not.toContain(USER_DATA);
    expect(row.severity).toBe("Low");
    expect(row.mitre).toEqual([]);
    const env = envelopeOf(row);
    expect(env.awsCompute?.launch?.startupConfig).toBe("supplied");
    expect(env.awsCompute?.launch?.image).toBe("ami-0123456789abcdef0");
    expect(env.awsCompute?.launch?.groups).toEqual([{ id: SG, name: "web" }]);
    expect(JSON.stringify(env)).not.toContain(USER_DATA);
    expect(row.description).toContain(
      "what ran on the instance and its network egress are not in CloudTrail",
    );
    expect(row.description).toContain("not terminated within this upload");
  });

  it("the startup configuration is three-valued: removed by CloudTrail, or not in this record — absence is never 'none'", () => {
    const [removed] = rows([launch({}, [instanceItem()], { userData: "<sensitiveDataRemoved>" })]);
    expect(removed.description).toContain("startup configuration supplied; CloudTrail removed its content");
    expect(envelopeOf(removed).awsCompute?.launch?.startupConfig).toBe("removed-by-cloudtrail");
    const r = launch();
    delete (r.requestParameters as Record<string, unknown>).userData;
    const [absent] = rows([r]);
    expect(absent.description).toContain("startup configuration not in this record");
    expect(absent.description).not.toContain("no startup configuration");
    expect(envelopeOf(absent).awsCompute?.launch?.startupConfig).toBe("not-in-record");
  });

  it("a service launch is rendered literally — the service, the signing principal, the requesterId — and raises nothing", () => {
    const [row] = rows([
      launch(
        {
          userIdentity: { ...instanceSession("autoscaling-session"), invokedBy: "autoscaling.amazonaws.com" },
          sourceIPAddress: "autoscaling.amazonaws.com",
        },
        [instanceItem()],
      ),
    ]);
    expect(row.description).toContain("request made by AWS service autoscaling.amazonaws.com");
    expect(row.description).toContain(
      "signing principal AssumedRole arn:aws:sts::111122223333:assumed-role/web-role/autoscaling-session",
    );
    expect(row.description).not.toContain("on behalf of");
    expect(row.severity).toBe("Low");
  });

  it("two instances of one RunInstances are two rows; the image is context, never a key; a re-import of the same upload folds and a different upload does not", () => {
    const records = [launch({}, [instanceItem(INST), instanceItem(INST2)])];
    const two = rows(records);
    expect(two).toHaveLength(2);
    expect(new Set(two.map((r) => r.aggKey)).size).toBe(2);
    expect(two[0].aggKey).toMatch(/^aws-compute-lifecycle\|[0-9a-f]{32}$/);
    expect(rows(records)[0].aggKey).toBe(two[0].aggKey);
    expect(rows(records, "upload-b")[0].aggKey).not.toBe(two[0].aggKey);
    const asEvents = (tag: string): ForensicEvent[] =>
      imported(records)
        .events.filter((e) => e.description.startsWith("AWS compute lifecycle:"))
        .map((e, i) => ({
          ...e,
          id: `${tag}-${i}`,
          relatedFindingIds: [],
          sourceScreenshots: [],
          sources: ["AWS CloudTrail"],
        }));
    expect(correlateEvents([...asEvents("a"), ...asEvents("b")])).toHaveLength(2);
  });

  it("the owning account is the response's ownerId, else the recipient account; a record with neither is not joined; the same id in two regions is two rows", () => {
    const owner = launch({ recipientAccountId: OTHER });
    expect(rows([owner])[0].description).toContain(`(account ${ACCT}, ${REGION})`);
    const noOwner = launch({ recipientAccountId: undefined });
    delete (noOwner.responseElements as Record<string, unknown>).ownerId;
    delete noOwner.recipientAccountId;
    expect(rows([noOwner])).toHaveLength(0);
    expect(rows([launch(), launch({ awsRegion: "eu-west-1" })])).toHaveLength(2);
  });

  it("a denied RunInstances has no instance and no row; a lone Terminate has no row; two lifecycle records without a launch do", () => {
    expect(
      rows([
        launch({
          errorCode: "Client.UnauthorizedOperation",
          errorMessage: "not authorized",
          responseElements: null,
        }),
      ]),
    ).toHaveLength(0);
    expect(rows([state("TerminateInstances", "running", "shutting-down")])).toHaveLength(0);
    const [row] = rows([
      state("StopInstances", "running", "stopping", { eventTime: at(10) }),
      state("StartInstances", "stopped", "pending", { eventTime: at(60) }),
    ]);
    expect(row.description).toContain("launch not in this upload");
    expect(row.description).toContain("StopInstances: running → stopping at 2024-05-01T09:00:10.000Z");
    expect(row.description).toContain("StartInstances: stopped → pending at 2024-05-01T09:01:00.000Z");
  });
});

describe("awsComputeLifecycles — recorded configuration changes", () => {
  it("stop → startup configuration replaced → start is a correlated API sequence, Medium, T1578.005; the content never reaches the row, the key or the envelope", () => {
    const [row] = rows([
      launch(),
      state("StopInstances", "running", "stopping", { eventTime: at(3600) }),
      modifyUserData({ eventTime: at(3660), userIdentity: bob }),
      state("StartInstances", "stopped", "pending", { eventTime: at(3720) }),
      state("TerminateInstances", "running", "shutting-down", { eventTime: at(7200) }),
    ]);
    expect(row.severity).toBe("Medium");
    expect(row.mitre).toContain("T1578.005");
    expect(row.description).toContain(
      `ModifyInstanceAttribute: startup configuration replaced (content not shown) at 2024-05-01T10:01:00.000Z by IAMUser user/bob (record:2) — after the launch`,
    );
    expect(row.description).toContain(
      "a correlated API sequence: stop, startup configuration replaced, start",
    );
    expect(row.description).not.toMatch(/\bexecuted\b|execution of|payload/);
    expect(row.description).toContain(
      "TerminateInstances: running → shutting-down at 2024-05-01T11:00:00.000Z",
    );
    expect(row.description).toContain(
      "recorded facts: startup configuration replaced after the launch (record:2) (1 kind)",
    );
    expect(row.description).not.toContain("not terminated within this upload");
    for (const s of [row.description, row.aggKey, JSON.stringify(row.canonical)])
      expect(s).not.toContain(USER_DATA);
  });

  it("a startup configuration replacement at the same recorded time as the launch claims no order; a Reboot is a request only", () => {
    const [row] = rows([launch(), modifyUserData(), state("RebootInstances", "", "", { eventTime: at(5) })]);
    expect(row.description).toContain(
      "startup configuration replaced (content not shown) at 2024-05-01T09:00:00.000Z",
    );
    expect(row.description).toContain("— at the same recorded time as the launch");
    expect(row.description).toContain("RebootInstances requested at 2024-05-01T09:00:05.000Z");
    expect(row.description).not.toContain("→  ");
  });

  it("an any-address ingress rule recorded on a group the instance holds is Medium and says 'recorded', never 'allows'; a group source or another group is not", () => {
    const [open] = rows([launch(), ingress(SG, "0.0.0.0/0", { eventTime: at(70) })]);
    expect(open.severity).toBe("Medium");
    expect(open.mitre).toContain("T1562.007");
    expect(open.description).toContain(
      `AuthorizeSecurityGroupIngress recorded on ${SG}: tcp 22 from 0.0.0.0/0 (any address) at 2024-05-01T09:01:10.000Z by IAMUser user/alice (record:1) — after the launch`,
    );
    expect(open.description).not.toContain("allows");
    const [other] = rows([launch(), ingress(SG2, "0.0.0.0/0", { eventTime: at(70) })]);
    expect(other.severity).toBe("Low");
    expect(other.description).not.toContain(SG2);
    const [groupSource] = rows([
      launch(),
      rec({
        eventName: "AuthorizeSecurityGroupIngress",
        eventTime: at(70),
        requestParameters: {
          groupId: SG,
          ipPermissions: {
            items: [
              {
                ipProtocol: "tcp",
                fromPort: 443,
                toPort: 443,
                groups: { items: [{ groupId: SG2, userId: OTHER }] },
              },
            ],
          },
        },
        responseElements: { _return: true },
      }),
    ]);
    expect(groupSource.severity).toBe("Low");
    expect(groupSource.description).toContain(`tcp 443 from group ${SG2} (owner ${OTHER})`);
    expect(groupSource.description).not.toContain("any address");
    const [v6] = rows([
      launch(),
      rec({
        eventName: "AuthorizeSecurityGroupIngress",
        eventTime: at(70),
        requestParameters: {
          groupId: SG,
          ipPermissions: { items: [{ ipProtocol: "-1", ipv6Ranges: { items: [{ cidrIpv6: "::/0" }] } }] },
        },
        responseElements: { _return: true },
      }),
    ]);
    expect(v6.severity).toBe("Medium");
    expect(v6.description).toContain("all protocols from ::/0 (any address)");
  });

  it("a rule recorded before the launch says so; a group-name-only request is not joined; a revoke is listed; a group added by ModifyInstanceAttribute is held from then on", () => {
    const [before] = rows([ingress(SG, "0.0.0.0/0", { eventTime: T }), launch({ eventTime: at(60) })]);
    expect(before.description).toContain("(record:0) — before the launch");
    const [byName] = rows([
      launch(),
      rec({
        eventName: "AuthorizeSecurityGroupIngress",
        eventTime: at(70),
        requestParameters: {
          groupName: "web",
          ipProtocol: "tcp",
          fromPort: 22,
          toPort: 22,
          cidrIp: "0.0.0.0/0",
        },
        responseElements: { _return: true },
      }),
    ]);
    expect(byName.severity).toBe("Low");
    expect(byName.description).not.toContain("AuthorizeSecurityGroupIngress");
    const [revoked] = rows([
      launch(),
      ingress(SG, "0.0.0.0/0", { eventTime: at(70) }),
      ingress(SG, "0.0.0.0/0", { eventTime: at(80), eventName: "RevokeSecurityGroupIngress" }),
    ]);
    expect(revoked.description).toContain(
      `RevokeSecurityGroupIngress recorded on ${SG}: tcp 22 from 0.0.0.0/0 (any address) at 2024-05-01T09:01:20.000Z`,
    );
    expect(revoked.severity).toBe("Medium");
    const [added] = rows([
      launch(),
      rec({
        eventName: "ModifyInstanceAttribute",
        eventTime: at(30),
        requestParameters: { instanceId: INST, groupSet: { items: [{ groupId: SG2 }] } },
        responseElements: { _return: true },
      }),
      ingress(SG2, "0.0.0.0/0", { eventTime: at(70) }),
    ]);
    expect(added.description).toContain(
      `ModifyInstanceAttribute: security groups set to ${SG2} at 2024-05-01T09:00:30.000Z`,
    );
    expect(added.description).toContain(`AuthorizeSecurityGroupIngress recorded on ${SG2}`);
    expect(added.severity).toBe("Medium");
  });

  it("#1084 regression: a same-timestamp rule is joined against the group in force at ITS OWN scan position, never the group a same-instant later replacement sets", () => {
    // record:0 launch (groups=[SG]); record:1 ingress on SG at t=70s; record:2 a same-instant
    // (t=70s) ModifyInstanceAttribute replacing groups to SG2. The ingress's own scan position
    // (record:1) precedes the replacement's (record:2), so groupsAt must still resolve to [SG]
    // for the ingress — never [SG2], which a bare `g.time <= time` (ignoring scan position)
    // would incorrectly pick since both groupSets satisfy `time <= 70s`.
    const [row] = rows([
      launch(),
      ingress(SG, "0.0.0.0/0", { eventTime: at(70) }),
      rec({
        eventName: "ModifyInstanceAttribute",
        eventTime: at(70),
        requestParameters: { instanceId: INST, groupSet: { items: [{ groupId: SG2 }] } },
        responseElements: { _return: true },
      }),
    ]);
    expect(row.description).toContain(`AuthorizeSecurityGroupIngress recorded on ${SG}`);
    expect(row.severity).toBe("Medium");
  });

  it("#1084 regression: same-timestamp lifecycle and rule changes are ordered by scan position, never by which list they came from", () => {
    const [row] = rows([
      launch(),
      ingress(SG, "0.0.0.0/0", { eventTime: at(70) }),
      state("StopInstances", "running", "stopped", { eventTime: at(70) }),
    ]);
    const ingressPos = row.description.indexOf("AuthorizeSecurityGroupIngress recorded on");
    const stopPos = row.description.indexOf("StopInstances:");
    expect(ingressPos).toBeGreaterThan(-1);
    expect(stopPos).toBeGreaterThan(-1);
    expect(ingressPos).toBeLessThan(stopPos);
  });

  it("an instance-profile association after the launch is Medium with the returned state; Replace names the instance only in a successful response; the profile is never a role", () => {
    const [assoc] = rows([
      launch(),
      rec({
        eventName: "AssociateIamInstanceProfile",
        eventTime: at(100),
        userIdentity: bob,
        requestParameters: {
          instanceId: INST,
          iamInstanceProfile: { arn: `arn:aws:iam::${ACCT}:instance-profile/admin` },
        },
        responseElements: {
          iamInstanceProfileAssociation: {
            associationId: "iip-assoc-1",
            instanceId: INST,
            state: "associating",
          },
        },
      }),
    ]);
    expect(assoc.severity).toBe("Medium");
    expect(assoc.description).toContain(
      `AssociateIamInstanceProfile: instance profile arn:aws:iam::${ACCT}:instance-profile/admin — association entered associating at 2024-05-01T09:01:40.000Z by IAMUser user/bob (record:1) — after the launch`,
    );
    expect(assoc.description).not.toMatch(/instance profile[^;]*\brole\b/);
    const replace = (over: Record<string, unknown>) =>
      rec({
        eventName: "ReplaceIamInstanceProfileAssociation",
        eventTime: at(100),
        requestParameters: { associationId: "iip-assoc-0", iamInstanceProfile: { name: "admin" } },
        responseElements: {
          iamInstanceProfileAssociation: {
            associationId: "iip-assoc-2",
            instanceId: INST,
            iamInstanceProfile: { arn: `arn:aws:iam::${ACCT}:instance-profile/admin` },
            state: "associating",
          },
        },
        ...over,
      });
    const [replaced] = rows([launch(), replace({})]);
    expect(replaced.severity).toBe("Medium");
    expect(replaced.description).toContain("ReplaceIamInstanceProfileAssociation: instance profile");
    const [failed] = rows([
      launch(),
      replace({ errorCode: "InvalidAssociationID.NotFound", responseElements: null }),
    ]);
    expect(failed.severity).toBe("Low");
    expect(failed.description).not.toContain("ReplaceIamInstanceProfileAssociation");
    const [disassoc] = rows([
      launch(),
      rec({
        eventName: "DisassociateIamInstanceProfile",
        eventTime: at(100),
        requestParameters: { associationId: "iip-assoc-0" },
        responseElements: {
          iamInstanceProfileAssociation: {
            associationId: "iip-assoc-0",
            instanceId: INST,
            state: "disassociating",
          },
        },
      }),
    ]);
    expect(disassoc.severity).toBe("Low");
    expect(disassoc.description).toContain(
      "DisassociateIamInstanceProfile: association entered disassociating",
    );
  });

  it("an address association is on the row only when its request names the instance, with the allocation id and the address as separate literals; a disassociation only through the returned association id; no 'previously on'", () => {
    const [row] = rows([
      launch(),
      rec({
        eventName: "AssociateAddress",
        eventTime: at(120),
        requestParameters: { instanceId: INST, allocationId: "eipalloc-0aaa", publicIp: "198.51.100.9" },
        responseElements: { associationId: "eipassoc-0bbb", _return: true },
      }),
      rec({
        eventName: "DisassociateAddress",
        eventTime: at(900),
        requestParameters: { associationId: "eipassoc-0bbb" },
        responseElements: { _return: true },
      }),
      rec({
        eventName: "DisassociateAddress",
        eventTime: at(901),
        requestParameters: { associationId: "eipassoc-0zzz" },
        responseElements: { _return: true },
      }),
      rec({
        eventName: "AssociateAddress",
        eventTime: at(1000),
        requestParameters: { networkInterfaceId: "eni-0ccc", allocationId: "eipalloc-0aaa" },
        responseElements: { associationId: "eipassoc-0ddd", _return: true },
      }),
    ]);
    expect(row.description).toContain(
      "AssociateAddress: allocation eipalloc-0aaa, address 198.51.100.9 → association eipassoc-0bbb at 2024-05-01T09:02:00.000Z",
    );
    expect(row.description).toContain(
      "DisassociateAddress: association eipassoc-0bbb at 2024-05-01T09:15:00.000Z",
    );
    expect(row.description).not.toContain("eipassoc-0zzz");
    expect(row.description).not.toContain("eipassoc-0ddd");
    expect(row.description).not.toContain("previously");
    expect(row.severity).toBe("Low");
    const env = envelopeOf(row);
    expect(env.awsCompute?.addresses).toEqual([
      expect.objectContaining({
        action: "associate",
        allocationId: "eipalloc-0aaa",
        address: "198.51.100.9",
        associationId: "eipassoc-0bbb",
      }),
      expect.objectContaining({ action: "disassociate", associationId: "eipassoc-0bbb" }),
    ]);
  });

  it("a denied or failed lifecycle call is counted as an attempt, named by class, and never joined", () => {
    const [row] = rows([
      launch(),
      modifyUserData({
        eventTime: at(10),
        errorCode: "Client.UnauthorizedOperation",
        responseElements: null,
      }),
      state("TerminateInstances", "", "", {
        eventTime: at(20),
        errorCode: "Client.InvalidInstanceID.NotFound",
        responseElements: null,
      }),
    ]);
    expect(row.severity).toBe("Low");
    expect(row.description).toContain("attempts: 1 denied, 1 failed — not joined");
    expect(row.description).not.toContain("startup configuration replaced");
    expect(row.description).toContain("not terminated within this upload");
  });
});

describe("awsComputeLifecycles — code round 1 (Codex findings)", () => {
  it("a group set REPLACES the launch groups: a later rule on the replaced-away group is not joined, and file order does not matter", () => {
    const records = [
      launch(),
      rec({
        eventName: "ModifyInstanceAttribute",
        eventTime: at(30),
        requestParameters: { instanceId: INST, groupSet: { items: [{ groupId: SG2 }] } },
        responseElements: { _return: true },
      }),
      ingress(SG, "0.0.0.0/0", { eventTime: at(70) }),
      ingress(SG, "0.0.0.0/0", { eventTime: at(10) }),
    ];
    const [row] = rows(records);
    expect(row.severity).toBe("Medium");
    expect(row.description).toContain(
      `AuthorizeSecurityGroupIngress recorded on ${SG}: tcp 22 from 0.0.0.0/0 (any address) at 2024-05-01T09:00:10.000Z`,
    );
    expect(row.description).not.toContain("at 2024-05-01T09:01:10.000Z");
    const shuffled = rows([records[2], records[3], records[1], records[0]]);
    const norm = (d: string) => d.replace(/record:\d+/g, "record:x");
    expect(norm(shuffled[0].description)).toBe(norm(row.description));
  });

  it("a fact is counted on the whole upload, not read back from a retained buffer: the ninth source of one rule, and a replacement evicted from the middle", () => {
    const [ninth] = rows([
      launch(),
      rec({
        eventName: "AuthorizeSecurityGroupIngress",
        eventTime: at(70),
        requestParameters: {
          groupId: SG,
          ipPermissions: {
            items: [
              {
                ipProtocol: "tcp",
                fromPort: 22,
                toPort: 22,
                ipRanges: {
                  items: [
                    ...Array.from({ length: 8 }, (_, i) => ({ cidrIp: `10.0.${i}.0/24` })),
                    { cidrIp: "0.0.0.0/0" },
                  ],
                },
              },
            ],
          },
        },
        responseElements: { _return: true },
      }),
    ]);
    expect(ninth.severity).toBe("Medium");
    expect(ninth.description).toContain(
      "any-address ingress rule recorded on a group the instance holds (record:1)",
    );
    const [evicted] = rows([
      launch(),
      ...Array.from({ length: 30 }, (_, i) =>
        state("StopInstances", "running", "stopping", { eventTime: at(60 + i) }),
      ),
      modifyUserData({ eventTime: at(95) }),
      ...Array.from({ length: 30 }, (_, i) =>
        state("StartInstances", "stopped", "pending", { eventTime: at(100 + i) }),
      ),
    ]);
    expect(evicted.severity).toBe("Medium");
    expect(evicted.description).toContain("startup configuration replaced after the launch (record:31)");
    expect(evicted.canonical?.evidence.rawRecords.map((r) => r.locator)).toContain("record:31");
  });

  it("a startup configuration replaced at the launch's own time, or with no launch in the upload, is listed but not a fact", () => {
    const [same] = rows([launch(), modifyUserData()]);
    expect(same.severity).toBe("Low");
    expect(same.mitre).toEqual([]);
    const [noLaunch] = rows([
      state("StopInstances", "running", "stopping", { eventTime: at(10) }),
      modifyUserData({ eventTime: at(20) }),
      state("StartInstances", "stopped", "pending", { eventTime: at(30) }),
    ]);
    expect(noLaunch.severity).toBe("Low");
    expect(noLaunch.description).toContain("a correlated API sequence");
    expect(noLaunch.description).toContain("recorded facts: none");
  });

  it("a profile operation without a returned association is not joined; the returned instance and profile win over the request", () => {
    const [absent] = rows([
      launch(),
      rec({
        eventName: "AssociateIamInstanceProfile",
        eventTime: at(100),
        requestParameters: {
          instanceId: INST,
          iamInstanceProfile: { arn: `arn:aws:iam::${ACCT}:instance-profile/admin` },
        },
        responseElements: { _return: true },
      }),
    ]);
    expect(absent.severity).toBe("Low");
    expect(absent.description).not.toContain("AssociateIamInstanceProfile");
    const [conflict] = rows([
      launch(),
      rec({
        eventName: "AssociateIamInstanceProfile",
        eventTime: at(100),
        requestParameters: { instanceId: INST2, iamInstanceProfile: { name: "requested" } },
        responseElements: {
          iamInstanceProfileAssociation: {
            associationId: "iip-assoc-9",
            instanceId: INST,
            iamInstanceProfile: { arn: `arn:aws:iam::${ACCT}:instance-profile/returned` },
            state: "associating",
          },
        },
      }),
    ]);
    expect(conflict.description).toContain(
      `AssociateIamInstanceProfile: instance profile arn:aws:iam::${ACCT}:instance-profile/returned`,
    );
    expect(conflict.description).not.toContain("requested");
  });

  it("a disassociation earlier in the file than its association still joins; the omitted row is keyed with the upload", () => {
    const [row] = rows([
      launch(),
      rec({
        eventName: "DisassociateAddress",
        eventTime: at(900),
        requestParameters: { associationId: "eipassoc-0bbb" },
        responseElements: { _return: true },
      }),
      rec({
        eventName: "AssociateAddress",
        eventTime: at(120),
        requestParameters: { instanceId: INST, allocationId: "eipalloc-0aaa" },
        responseElements: { associationId: "eipassoc-0bbb", _return: true },
      }),
    ]);
    expect(row.description).toContain(
      "DisassociateAddress: association eipassoc-0bbb at 2024-05-01T09:15:00.000Z",
    );
    expect(envelopeOf(row).awsCompute?.addresses.map((a) => a.action)).toEqual(["associate", "disassociate"]);
    const many = Array.from({ length: AWS_COMPUTE_MAX + 1 }, (_, i) =>
      launch({ eventTime: at(i) }, [instanceItem(`i-${String(i).padStart(17, "0")}`)]),
    );
    const omittedA = awsComputeLifecycles(many, "upload-a").find((e) =>
      e.description.includes("further instance"),
    )!;
    const omittedB = awsComputeLifecycles(many, "upload-b").find((e) =>
      e.description.includes("further instance"),
    )!;
    expect(omittedA.aggKey).not.toBe(omittedB.aggKey);
  });

  it("a remote-access-only row is timestamped at its first record, never the epoch", () => {
    const all = rows([sendCommand({ instanceIds: [INST2] })]);
    expect(all).toHaveLength(1);
    expect(all[0].timestamp).toBe("2024-05-01T09:30:00.000Z");
    expect(all[0].canonical?.time.observed).toBe("2024-05-01T09:30:00.000Z");
  });

  it("replicas of one cross-account launch: both records cited, coverage counts both, the informative identity read", () => {
    const shared = "shared-1";
    const [row] = rows([
      launch({
        sharedEventID: shared,
        userIdentity: { type: "AWSAccount", principalId: "", accountId: OTHER },
        recipientAccountId: OTHER,
      }),
      launch({ sharedEventID: shared }),
    ]);
    expect(row.description).toContain("(record:0, record:1)");
    expect(row.description).toContain("launched 2024-05-01T09:00:00.000Z by IAMUser");
    expect(row.description).toContain("among the 2 records of this upload");
    expect(row.canonical?.evidence.rawRecords.map((r) => r.locator)).toEqual(["record:0", "record:1"]);
  });
});

describe("awsComputeLifecycles — API calls using instance-role credentials", () => {
  it("calls signed with the instance's own credentials are counted with their recorded sourceIPAddress — never called the instance's address", () => {
    const [row] = rows([
      launch(),
      sessionCall(),
      sessionCall({ eventTime: at(600), sourceIPAddress: "192.0.2.44", userAgent: "curl/8" }),
      sessionCall({ eventTime: at(900) }),
    ]);
    expect(row.severity).toBe("Low");
    expect(row.description).toContain(
      "API calls using instance-role credentials: 3 records 2024-05-01T09:05:00.000Z (record:1) → 2024-05-01T09:15:00.000Z (record:3)",
    );
    expect(row.description).toContain(
      `sourceIPAddress recorded on these calls: ${IP_INST} aws-sdk-go/1.44 first 2024-05-01T09:05:00.000Z (record:1, 2 records); 192.0.2.44 curl/8 first 2024-05-01T09:10:00.000Z (record:2, 1 record)`,
    );
    expect(row.description).not.toMatch(/instance's (own )?address/);
    const env = envelopeOf(row);
    expect(env.awsCompute?.session?.records).toBe(3);
    expect(env.awsCompute?.session?.sources.map((s) => s.address)).toEqual([IP_INST, "192.0.2.44"]);
    expect(env.evidence.rawRecords.map((r) => r.locator)).toEqual(
      expect.arrayContaining(["record:0", "record:1", "record:3"]),
    );
  });

  it("the join needs AssumedRole, ec2RoleDelivery, the instance id as the session suffix of BOTH principalId and ARN, and the instance's account — a human-named session never joins", () => {
    const absent = (row: { description: string }) =>
      expect(row.description).toContain("no call using instance-role credentials among");
    absent(
      rows([
        launch(),
        sessionCall({ userIdentity: instanceSession(INST, {}, { ec2RoleDelivery: undefined }) }),
      ])[0],
    );
    absent(
      rows([
        launch(),
        sessionCall({ userIdentity: instanceSession(INST, { principalId: "AROAEXAMPLEROLE:other" }) }),
      ])[0],
    );
    absent(
      rows([
        launch(),
        sessionCall({
          userIdentity: instanceSession(INST, { arn: `arn:aws:sts::${ACCT}:assumed-role/web-role/other` }),
        }),
      ])[0],
    );
    absent(
      rows([
        launch(),
        sessionCall({
          userIdentity: instanceSession(INST, {
            accountId: OTHER,
            arn: `arn:aws:sts::${OTHER}:assumed-role/web-role/${INST}`,
          }),
          recipientAccountId: OTHER,
        }),
      ])[0],
    );
    absent(
      rows([launch(), sessionCall({ userIdentity: { ...instanceSession(INST), type: "FederatedUser" } })])[0],
    );
    const [joined] = rows([
      launch(),
      sessionCall({ userIdentity: instanceSession(INST, {}, { ec2RoleDelivery: "1.0" }) }),
    ]);
    expect(joined.description).toContain("API calls using instance-role credentials: 1 record");
    const [absence] = rows([launch(), rec({ eventTime: at(50) })]);
    expect(absence.description).toContain(
      "no call using instance-role credentials among the 2 records of this upload (2024-05-01T09:00:00Z → 2024-05-01T09:00:50Z)",
    );
    expect(absence.description).toContain(
      "record retention and the trails' selectors are not in this evidence",
    );
  });

  it("a privileged change by the instance's session is one recorded fact (Medium); with an any-address rule it is two kinds (High); enumeration across three services is a fact; a denied call is not", () => {
    const priv = sessionCall({
      eventSource: "iam.amazonaws.com",
      eventName: "CreateAccessKey",
      eventTime: at(700),
      requestParameters: { userName: "svc" },
    });
    const [one] = rows([launch(), priv]);
    expect(one.severity).toBe("Medium");
    expect(one.mitre).toContain("T1098");
    expect(one.description).toContain(
      "privileged change by the instance-role credentials: iam CreateAccessKey at 2024-05-01T09:11:40.000Z (record:1)",
    );
    expect(one.description).toContain(
      "recorded facts: privileged change by the instance-role credentials (record:1) (1 kind)",
    );
    const [two] = rows([launch(), ingress(SG, "0.0.0.0/0", { eventTime: at(70) }), priv]);
    expect(two.severity).toBe("High");
    expect(two.description).toContain("(2 kinds)");
    const [denied] = rows([launch(), { ...priv, errorCode: "AccessDenied" }]);
    expect(denied.severity).toBe("Low");
    expect(denied.description).toContain("1 denied call of these shapes — not counted");
    const [enumerated] = rows([
      launch(),
      sessionCall({ eventSource: "ec2.amazonaws.com", eventName: "DescribeInstances", eventTime: at(300) }),
      sessionCall({ eventSource: "iam.amazonaws.com", eventName: "ListUsers", eventTime: at(360) }),
      sessionCall({ eventSource: "s3.amazonaws.com", eventName: "ListBuckets", eventTime: at(420) }),
    ]);
    expect(enumerated.severity).toBe("Medium");
    expect(enumerated.description).toContain(
      "enumeration by the instance-role credentials: ec2, iam, s3 within 10 min",
    );
    const [remote] = rows([
      launch(),
      sessionCall({ eventSource: "lambda.amazonaws.com", eventName: "Invoke", eventTime: at(300) }),
    ]);
    expect(remote.severity).toBe("Medium");
    expect(remote.description).toContain("remote execution by the instance-role credentials: lambda Invoke");
  });

  it("the session is joined by (account, instance id) across regions; the instance's row is scoped by its own region", () => {
    const [row] = rows([launch(), sessionCall({ awsRegion: "eu-west-1" })]);
    expect(row.description).toContain("API calls using instance-role credentials: 1 record");
  });
});

describe("awsComputeLifecycles — remote-access requests to the instance", () => {
  it("SendCommand by exact instanceIds or Targets[InstanceIds], StartSession by its target, SendSSHPublicKey by instanceId — 'requested', never 'ran'; a tag selector never names an instance", () => {
    const all = rows([
      launch(),
      sendCommand({ instanceIds: [INST] }),
      sendCommand({ targets: [{ key: "InstanceIds", values: [INST2, INST] }] }, { eventTime: at(1900) }),
      sendCommand({ targets: [{ key: "tag:Role", values: ["web"] }] }, { eventTime: at(2000) }),
      rec({
        eventSource: "ssm.amazonaws.com",
        eventName: "StartSession",
        eventTime: at(2100),
        requestParameters: { target: INST },
        responseElements: {
          sessionId: "alice-0123",
          tokenValue: "SECRET-TOKEN",
          streamUrl: "wss://secret.example/stream",
        },
      }),
      rec({
        eventSource: "ec2-instance-connect.amazonaws.com",
        eventName: "SendSSHPublicKey",
        eventTime: at(2200),
        requestParameters: {
          instanceId: INST,
          instanceOSUser: "ec2-user",
          sSHPublicKey: "ssh-rsa AAAASECRETKEY",
        },
        responseElements: { requestId: "r-2", success: true },
      }),
    ]);
    // The second instance the command named has its own row — a remote-access request alone forms one.
    expect(all).toHaveLength(2);
    const row = all.find((r) => r.description.includes(INST))!;
    expect(all.find((r) => r.description.includes(INST2))!.description).toContain(
      "launch not in this upload",
    );
    expect(row.description).toContain(`AWS compute lifecycle: ${INST} `);
    expect(row.severity).toBe("Medium");
    expect(row.description).toContain(
      `remote-access requests (requested; whether anything ran is not in CloudTrail): ssm SendCommand [AWS-RunShellScript] at 2024-05-01T09:30:00.000Z by IAMUser user/alice (record:1)`,
    );
    expect(row.description).toContain("ssm SendCommand [AWS-RunShellScript] at 2024-05-01T09:31:40.000Z");
    expect(row.description).not.toContain("2024-05-01T09:33:20.000Z");
    expect(row.description).toContain("ssm StartSession at 2024-05-01T09:35:00.000Z");
    expect(row.description).toContain("ec2-instance-connect SendSSHPublicKey at 2024-05-01T09:36:40.000Z");
    expect(row.description).toContain(
      "recorded facts: remote-access request to the instance (record:1) (1 kind)",
    );
    expect(row.mitre).toContain("T1651");
    for (const s of [row.description, row.aggKey, JSON.stringify(row.canonical)]) {
      expect(s).not.toContain("SECRET-TOKEN");
      expect(s).not.toContain("secret.example");
      expect(s).not.toContain("AAAASECRETKEY");
    }
  });

  it("a denied SendCommand reads denied and does not join; a validation error reads failed", () => {
    const [row] = rows([
      launch(),
      sendCommand({ instanceIds: [INST] }, { errorCode: "AccessDeniedException", responseElements: null }),
      sendCommand(
        { instanceIds: [INST] },
        { eventTime: at(1900), errorCode: "InvalidInstanceId", responseElements: null },
      ),
    ]);
    expect(row.severity).toBe("Low");
    expect(row.description).not.toContain("remote-access requests");
    expect(row.description).toContain("attempts: 1 denied, 1 failed — not joined");
  });
});

describe("awsComputeLifecycles — redaction, neutralisation, bounds, the importer seam", () => {
  it("no secret from any sensitive path reaches the row, the key or the envelope", () => {
    const poison = [
      "POISON-USERDATA",
      "POISON-KEYMATERIAL",
      "POISON-PUBKEY",
      "POISON-SSHKEY",
      "POISON-TOKEN",
      "POISON-URL",
      "POISON-ATTRVALUE",
    ];
    const out = awsComputeLifecycles(
      [
        launch({}, [instanceItem()], { userData: "POISON-USERDATA" }),
        rec({
          eventName: "ModifyInstanceAttribute",
          eventTime: at(10),
          requestParameters: { instanceId: INST, attribute: "userData", value: "POISON-ATTRVALUE" },
          responseElements: { _return: true },
        }),
        rec({
          eventName: "CreateKeyPair",
          eventTime: at(20),
          requestParameters: { keyName: "deploy-key" },
          responseElements: {
            keyName: "deploy-key",
            keyMaterial: "POISON-KEYMATERIAL",
            keyPairId: "key-0aaa",
          },
        }),
        rec({
          eventName: "ImportKeyPair",
          eventTime: at(30),
          requestParameters: { keyName: "deploy-key", publicKeyMaterial: "POISON-PUBKEY" },
          responseElements: { keyName: "deploy-key" },
        }),
        rec({
          eventSource: "ec2-instance-connect.amazonaws.com",
          eventName: "SendSSHPublicKey",
          eventTime: at(40),
          requestParameters: { instanceId: INST, sSHPublicKey: "POISON-SSHKEY" },
          responseElements: { success: true },
        }),
        rec({
          eventSource: "ssm.amazonaws.com",
          eventName: "StartSession",
          eventTime: at(50),
          requestParameters: { target: INST },
          responseElements: { sessionId: "s-1", tokenValue: "POISON-TOKEN", streamUrl: "POISON-URL" },
        }),
      ],
      "upload-a",
    );
    const text = JSON.stringify(out);
    for (const p of poison) expect(text).not.toContain(p);
    const [row] = out;
    expect(row.description).toContain(
      "ModifyInstanceAttribute: startup configuration replaced (content not shown)",
    );
    expect(row.severity).toBe("High");
  });

  it("hostile names are neutralised in the words; the row's parts stay bounded", () => {
    const evil = "ami-0] [fake: launched by root";
    const [row] = rows([
      launch({}, [
        instanceItem(INST, {
          imageId: evil,
          keyName: "k​] x",
          groupSet: { items: [{ groupId: SG, groupName: "n] [z" }] },
        }),
      ]),
    ]);
    expect(row.description).not.toContain(evil);
    expect(row.description).not.toContain("​");
    expect(row.description.length).toBeLessThanOrEqual(1400);
    expect(row.description.endsWith("]")).toBe(true);
  });

  it("257 launches → 256 rows by grade then time then id, plus one omitted row; 40 lifecycle records → 24 earliest + 8 latest named and the rest counted", () => {
    const many = Array.from({ length: AWS_COMPUTE_MAX + 1 }, (_, i) =>
      launch({ eventTime: at(i) }, [instanceItem(`i-${String(i).padStart(17, "0")}`)]),
    );
    const out = awsComputeLifecycles(many, "upload-a");
    expect(out.filter((e) => e.description.startsWith("AWS compute lifecycle:"))).toHaveLength(
      AWS_COMPUTE_MAX,
    );
    const omitted = out.find((e) => e.description.includes("further instance"));
    expect(omitted?.description).toContain(
      `1 further instance with a lifecycle in this upload beyond the ${AWS_COMPUTE_MAX} reported — not shown`,
    );
    const busy = [
      launch(),
      ...Array.from({ length: 40 }, (_, i) =>
        state(
          i % 2 ? "StartInstances" : "StopInstances",
          i % 2 ? "stopped" : "running",
          i % 2 ? "pending" : "stopping",
          { eventTime: at(60 + i) },
        ),
      ),
    ];
    const [row] = rows(busy);
    expect(row.description).toContain(
      "recorded configuration changes (8 named, 32 further not individually named)",
    );
    const env = envelopeOf(row);
    expect(env.awsCompute?.lifecycle).toHaveLength(32);
    expect(env.awsCompute?.lifecycle[23].time).toBe(at(83));
    expect(env.awsCompute?.lifecycle[24].time).toBe(at(92));
    expect(env.awsCompute?.lifecycleBeyond).toBe(8);
  });

  it("the importer appends the rows after the source-row cap and counts source rows alone", () => {
    const records = [
      launch(),
      sessionCall(),
      state("TerminateInstances", "running", "shutting-down", { eventTime: at(600) }),
    ];
    const r = imported(records, { maxEvents: 1 });
    const lifecycle = r.events.filter((e) => e.description.startsWith("AWS compute lifecycle:"));
    expect(lifecycle).toHaveLength(1);
    expect(r.kept).toBe(1);
    expect(r.summaries).toBe(1);
    expect(r.dropped).toBe(2);
    expect(lifecycle[0].canonical?.evidence.sourceArtifactHash).toMatch(/^sha256:/);
    expect(lifecycle[0].canonical?.event).toEqual({
      category: "cloud",
      type: "compute-lifecycle",
      action: "lifecycle",
      outcome: "success",
    });
    expect(lifecycle[0].canonical?.cloud?.resource).toBe(INST);
    expect(lifecycle[0].canonical?.cloud?.region).toBe(REGION);
    expect(lifecycle[0].canonical?.awsCompute?.basis).toBe(
      "records of this upload only; joined through the instance id; what ran on the instance and its network egress are not in CloudTrail",
    );
  });
});
