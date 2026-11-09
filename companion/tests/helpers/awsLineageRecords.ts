// Synthetic CloudTrail records that form a credential lineage (#2482): one AssumeRole issuance that
// exposes a temporary key, and uses of that key from two sources. Documentation account ids and
// TEST-NET addresses only.

export const LINEAGE_ACCT = "111122223333";
export const LINEAGE_KEY = "ASIAEXAMPLEKEY000001";
export const LINEAGE_IP = "203.0.113.5";
export const LINEAGE_IP2 = "198.51.100.7";
const ROLE = `arn:aws:iam::${LINEAGE_ACCT}:role/Deploy`;
const T0 = Date.parse("2026-10-01T09:00:00Z");
const at = (s: number) => new Date(T0 + s * 1000).toISOString().replace(".000Z", "Z");

const base = (i: number) => ({
  eventVersion: "1.08",
  eventTime: at(i * 60),
  awsRegion: "us-east-1",
  userAgent: "aws-cli/2.15",
  recipientAccountId: LINEAGE_ACCT,
  eventID: `00000000-0000-4000-a000-${String(i).padStart(12, "0")}`,
});

/** The AssumeRole that issued `key` (LINEAGE_KEY by default). */
export function lineageIssuance(i = 0, key = LINEAGE_KEY): Record<string, unknown> {
  return {
    ...base(i),
    eventSource: "sts.amazonaws.com",
    eventName: "AssumeRole",
    sourceIPAddress: LINEAGE_IP,
    userIdentity: {
      type: "IAMUser",
      principalId: "AIDAEXAMPLE",
      arn: `arn:aws:iam::${LINEAGE_ACCT}:user/alice`,
      accountId: LINEAGE_ACCT,
      accessKeyId: "AKIAEXAMPLEKEY000009",
      userName: "alice",
    },
    requestParameters: { roleArn: ROLE, roleSessionName: "ci-42" },
    responseElements: {
      credentials: { accessKeyId: key, expiration: "Oct 1, 2026, 10:00:00 PM" },
      assumedRoleUser: {
        arn: `arn:aws:sts::${LINEAGE_ACCT}:assumed-role/Deploy/ci-42`,
        assumedRoleId: "AROAEXAMPLEID:ci-42",
      },
    },
  };
}

/** A use of `key`; `i` sets its time and id, odd `i` comes from the second source. */
export function lineageUse(i: number, key = LINEAGE_KEY): Record<string, unknown> {
  return {
    ...base(i),
    eventSource: "s3.amazonaws.com",
    eventName: "GetObject",
    sourceIPAddress: i % 2 ? LINEAGE_IP2 : LINEAGE_IP,
    userIdentity: {
      type: "AssumedRole",
      principalId: "AROAEXAMPLEID:ci-42",
      arn: `arn:aws:sts::${LINEAGE_ACCT}:assumed-role/Deploy/ci-42`,
      accountId: LINEAGE_ACCT,
      accessKeyId: key,
      sessionContext: {
        sessionIssuer: {
          type: "Role",
          principalId: "AROAEXAMPLEID",
          arn: ROLE,
          accountId: LINEAGE_ACCT,
          userName: "Deploy",
        },
        attributes: { creationDate: at(0), mfaAuthenticated: "false" },
      },
    },
  };
}

/** A RunInstances that launched `instanceId`; `i` sets its time and id. */
export function computeLaunch(i: number, instanceId: string): Record<string, unknown> {
  return {
    ...base(i),
    eventSource: "ec2.amazonaws.com",
    eventName: "RunInstances",
    sourceIPAddress: LINEAGE_IP,
    userIdentity: {
      type: "IAMUser",
      principalId: "AIDAEXAMPLE",
      arn: `arn:aws:iam::${LINEAGE_ACCT}:user/alice`,
      accountId: LINEAGE_ACCT,
      userName: "alice",
    },
    requestParameters: { instanceType: "t3.micro" },
    responseElements: {
      ownerId: LINEAGE_ACCT,
      instancesSet: {
        items: [{ instanceId, imageId: "ami-0123456789abcdef0", instanceState: { name: "pending" } }],
      },
    },
  };
}

export const isLineageRow = (e: { description: string }): boolean =>
  e.description.startsWith("AWS credential lineage:");

export const isComputeRow = (e: { description: string }): boolean =>
  e.description.startsWith("AWS compute lifecycle");
