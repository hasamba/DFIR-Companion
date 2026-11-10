// The SANS 504 S3 ransomware lab (#2542), reduced to the records that tell its story and the noise
// that used to hide it. Shape and timing follow the public lab; every identity is synthetic:
// account 123456789012, documentation addresses (198.51.100.0/24 attacker, 203.0.113.0/24 the
// company), example buckets and users, and AWS's own documented example key ids. Reused by #2543.
//
// The story (2021-07-29 UTC): an IAM user's access key is used from a cloud host — a caller check,
// denied probes, a Boto3 burst of IAM reads, a `*:*` inline policy granted to itself, a new access
// key and its first use, then a versioning check on the target bucket. The object encryption that
// followed is NOT in the evidence: S3 data events were off until the responder turned them on at
// 23:53:36. Around it: the responder's root console checks (several "not found" answers), the
// CloudTrail console wizard, and AWS log delivery writing into the log bucket.

type Rec = Record<string, unknown>;

export const LAB_ACCOUNT = "123456789012";
export const ATTACKER_IP = "198.51.100.23";
export const COMPANY_IP = "203.0.113.10";
export const ATTACKER_KEY = "AKIAIOSFODNN7EXAMPLE";
export const CREATED_KEY = "AKIAI44QH8DHBEXAMPLE";
export const TARGET_BUCKET = "example-eng";
export const LOG_BUCKET = "example-log";
export const SELECTORS_AT = "2021-07-29T23:53:36Z";

const CLI = "aws-cli/2.2.23 Python/3.8.8 Linux/4.14.238 exe/x86_64.amzn.2 prompt/off";
const S3_CLI = `[${CLI}]`;
const BOTO = "Boto3/1.18.1 Python/3.9.5 Linux/4.14.238 Botocore/1.21.1";
const CONSOLE_S3 = "[S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.1002]";
const WIZARD = "AWSCloudTrail, aws-internal/3 aws-sdk-java/1.11.991";
const BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/92.0";

let seq = 0;
const eventId = (): string => `00000000-2542-4000-8000-${String(++seq).padStart(12, "0")}`;

const attacker = (key = ATTACKER_KEY): Rec => ({
  type: "IAMUser",
  principalId: "AIDAEXAMPLEUSER00001",
  arn: `arn:aws:iam::${LAB_ACCOUNT}:user/example-user`,
  accountId: LAB_ACCOUNT,
  accessKeyId: key,
  userName: "example-user",
});
const root = (key = "ASIAEXAMPLEROOTSES01"): Rec => ({
  type: "Root",
  principalId: LAB_ACCOUNT,
  arn: `arn:aws:iam::${LAB_ACCOUNT}:root`,
  accountId: LAB_ACCOUNT,
  accessKeyId: key,
  sessionContext: { attributes: { creationDate: "2021-07-29T12:54:17Z", mfaAuthenticated: "false" } },
});
const service = (by: string): Rec => ({ type: "AWSService", invokedBy: by });

function rec(
  time: string,
  source: string,
  name: string,
  who: Rec,
  ip: string,
  agent: string,
  extra: Rec = {},
): Rec {
  return {
    eventVersion: "1.08",
    userIdentity: who,
    eventTime: time,
    eventSource: `${source}.amazonaws.com`,
    eventName: name,
    awsRegion: "us-west-1",
    sourceIPAddress: ip,
    userAgent: agent,
    requestParameters: null,
    responseElements: null,
    eventID: eventId(),
    readOnly: true,
    eventType: "AwsApiCall",
    recipientAccountId: LAB_ACCOUNT,
    ...extra,
  };
}
const t = (hms: string, day = "29"): string => `2021-07-${day}T${hms}Z`;
const denied = (code = "AccessDenied"): Rec => ({ errorCode: code, errorMessage: "Access Denied" });
const notFound = (code: string, message: string): Rec => ({ errorCode: code, errorMessage: message });
const write: Rec = { readOnly: false };
const bucket = (name: string): Rec => ({ bucketName: name, Host: `${name}.s3.us-west-1.amazonaws.com` });

const A = (hms: string, source: string, name: string, agent: string, extra: Rec = {}): Rec =>
  rec(t(hms), source, name, attacker(), ATTACKER_IP, agent, extra);
const R = (hms: string, source: string, name: string, agent: string, extra: Rec = {}): Rec =>
  rec(t(hms), source, name, root(), COMPANY_IP, agent, extra);

/** The attacker's steps, in time order. */
export const ATTACK: readonly Rec[] = [
  A("13:02:53", "sts", "GetCallerIdentity", CLI),
  A("13:03:25", "s3", "ListBuckets", S3_CLI, denied()),
  A("13:03:31", "ec2", "DescribeInstances", CLI, denied("Client.UnauthorizedOperation")),
  A("13:03:37", "lambda", "ListFunctions20150331", CLI, denied()),
  A("13:03:42", "iam", "ListRoles", CLI),
  A("13:04:13", "iam", "ListUsers", CLI),
  A("13:04:57", "logs", "DescribeLogGroups", CLI, denied()),
  A("13:06:30", "sts", "GetCallerIdentity", BOTO),
  A("13:06:31", "iam", "GetPolicyVersion", BOTO),
  A("13:06:31", "iam", "GetPolicy", BOTO),
  A("13:06:31", "iam", "ListGroupsForUser", BOTO),
  A("13:06:31", "iam", "ListAttachedUserPolicies", BOTO),
  A("13:06:31", "iam", "ListUserPolicies", BOTO),
  A("13:06:31", "iam", "ListGroupPolicies", BOTO),
  A("13:06:41", "iam", "ListPolicies", BOTO),
  A("13:06:49", "iam", "PutUserPolicy", BOTO, {
    ...write,
    awsRegion: "us-east-1",
    requestParameters: {
      userName: "example-user",
      policyName: "examplepolicy1",
      policyDocument:
        '{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "*","Resource": "*"}]}',
    },
  }),
  A("13:07:12", "s3", "ListBuckets", S3_CLI),
  A("13:10:42", "iam", "CreateAccessKey", CLI, {
    ...write,
    awsRegion: "us-east-1",
    requestParameters: { userName: "example-user" },
    responseElements: {
      accessKey: {
        userName: "example-user",
        accessKeyId: CREATED_KEY,
        status: "Active",
        createDate: "Jul 29, 2021 1:10:42 PM",
      },
    },
  }),
  rec(t("13:11:40"), "sts", "GetCallerIdentity", attacker(CREATED_KEY), ATTACKER_IP, CLI),
  A("13:11:54", "ec2", "DescribeInstances", CLI),
  A("14:01:48", "s3", "GetBucketVersioning", S3_CLI, {
    requestParameters: { ...bucket(TARGET_BUCKET), versioning: "" },
  }),
];

/** The root console login (one mistyped password, then success) and the responder's checks. */
export const RESPONDER: readonly Rec[] = [
  rec(t("12:53:34"), "signin", "ConsoleLogin", { ...root(), accessKeyId: "" }, COMPANY_IP, BROWSER, {
    ...write,
    eventType: "AwsConsoleSignIn",
    errorMessage: "Failed authentication",
    responseElements: { ConsoleLogin: "Failure" },
    additionalEventData: { MFAUsed: "No" },
  }),
  rec(t("12:54:17"), "signin", "ConsoleLogin", { ...root(), accessKeyId: "" }, COMPANY_IP, BROWSER, {
    ...write,
    eventType: "AwsConsoleSignIn",
    responseElements: { ConsoleLogin: "Success" },
    additionalEventData: { MFAUsed: "No" },
  }),
  R("19:57:42", "s3", "GetBucketPolicyStatus", CONSOLE_S3, {
    ...notFound("NoSuchBucketPolicy", "The bucket policy does not exist"),
    requestParameters: bucket(TARGET_BUCKET),
  }),
  R("19:57:44", "s3", "GetBucketPolicy", CONSOLE_S3, {
    ...notFound("NoSuchBucketPolicy", "The bucket policy does not exist"),
    requestParameters: bucket(TARGET_BUCKET),
  }),
  R("19:57:44", "s3", "GetBucketWebsite", CONSOLE_S3, {
    ...notFound("NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration"),
    requestParameters: bucket(TARGET_BUCKET),
  }),
  R("19:57:45", "s3", "GetBucketAcl", CONSOLE_S3, { requestParameters: bucket(TARGET_BUCKET) }),
  R("20:31:10", "s3", "GetBucketVersioning", CONSOLE_S3, { requestParameters: bucket(TARGET_BUCKET) }),
  R("20:31:12", "s3", "GetBucketObjectLockConfiguration", CONSOLE_S3, {
    ...notFound(
      "ObjectLockConfigurationNotFoundError",
      "Object Lock configuration does not exist for this bucket",
    ),
    requestParameters: bucket(TARGET_BUCKET),
  }),
  R("23:44:47", "monitoring", "GetDashboard", "AWS CloudWatch Console", {
    ...notFound("DashboardNotFoundError", "Dashboard CloudWatch-Default does not exist"),
  }),
  R("23:51:20", "cloudtrail", "GetInsightSelectors", "console.amazonaws.com", {
    ...notFound("InsightNotEnabledException", "Trail does not have Insights enabled"),
    requestParameters: { trailName: `arn:aws:cloudtrail:us-west-1:${LAB_ACCOUNT}:trail/cluster` },
  }),
];

const KEY_ARN = `arn:aws:kms:us-west-1:${LAB_ACCOUNT}:key/11111111-2222-3333-4444-555555555555`;

const OWN_TRAILS = `arn:aws:cloudtrail:*:${LAB_ACCOUNT}:trail/*`;
const callerIsOwn = { StringEquals: { "kms:CallerAccount": LAB_ACCOUNT } };

/** The key policy the CloudTrail wizard writes: this account, the CloudTrail service, and `*` held to this account. */
const TRAIL_KEY_POLICY = {
  Version: "2012-10-17",
  Id: "Key policy created by CloudTrail",
  Statement: [
    {
      Sid: "Enable IAM User Permissions",
      Effect: "Allow",
      Principal: { AWS: [`arn:aws:iam::${LAB_ACCOUNT}:root`, LAB_ACCOUNT] },
      Action: "kms:*",
      Resource: "*",
    },
    {
      Sid: "Allow CloudTrail to encrypt logs",
      Effect: "Allow",
      Principal: { Service: "cloudtrail.amazonaws.com" },
      Action: "kms:GenerateDataKey*",
      Resource: "*",
      Condition: { StringLike: { "kms:EncryptionContext:aws:cloudtrail:arn": [OWN_TRAILS] } },
    },
    {
      Sid: "Allow principals in the account to decrypt log files",
      Effect: "Allow",
      Principal: { AWS: "*" },
      Action: ["kms:Decrypt", "kms:ReEncryptFrom"],
      Resource: "*",
      Condition: {
        ...callerIsOwn,
        StringLike: { "kms:EncryptionContext:aws:cloudtrail:arn": [OWN_TRAILS] },
      },
    },
    {
      Sid: "Allow alias creation during setup",
      Effect: "Allow",
      Principal: { AWS: "*" },
      Action: ["kms:CreateAlias"],
      Resource: "*",
      Condition: {
        StringEquals: { "kms:CallerAccount": LAB_ACCOUNT, "kms:ViaService": "ec2.us-west-1.amazonaws.com" },
      },
    },
  ],
};

/** The CloudTrail console wizard, all inside two seconds — the logging the responder turned on. */
export const WIZARD_BURST: readonly Rec[] = [
  R("23:53:36", "kms", "CreateKey", WIZARD, {
    ...write,
    requestParameters: {
      description: "The key created by CloudTrail to encrypt log files.",
      origin: "AWS_KMS",
      keyUsage: "ENCRYPT_DECRYPT",
      policy: JSON.stringify(TRAIL_KEY_POLICY),
    },
    responseElements: {
      keyMetadata: { aWSAccountId: LAB_ACCOUNT, origin: "AWS_KMS", keyManager: "CUSTOMER" },
    },
  }),
  R("23:53:36", "kms", "CreateAlias", WIZARD, {
    ...write,
    requestParameters: { aliasName: "alias/example-trail-key", targetKeyId: KEY_ARN },
  }),
  R("23:53:36", "cloudtrail", "PutEventSelectors", "console.amazonaws.com", {
    ...write,
    requestParameters: {
      trailName: "management-events",
      eventSelectors: [
        {
          readWriteType: "All",
          includeManagementEvents: true,
          dataResources: [{ type: "AWS::S3::Object", values: ["arn:aws:s3"] }],
          excludeManagementEventSources: [],
        },
      ],
    },
  }),
  R("23:53:36", "cloudtrail", "CreateTrail", "console.amazonaws.com", {
    ...write,
    requestParameters: {
      name: "management-events",
      s3BucketName: LOG_BUCKET,
      isMultiRegionTrail: true,
      enableLogFileValidation: true,
      kmsKeyId: KEY_ARN,
    },
  }),
  R("23:53:36", "cloudtrail", "StartLogging", "console.amazonaws.com", {
    ...write,
    requestParameters: { name: "management-events" },
  }),
  R("23:53:36", "s3", "PutBucketPolicy", `[${WIZARD}]`, {
    ...write,
    requestParameters: {
      ...bucket(LOG_BUCKET),
      bucketPolicy: {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "AWSCloudTrailAclCheck",
            Effect: "Allow",
            Principal: { Service: "cloudtrail.amazonaws.com" },
            Action: "s3:GetBucketAcl",
            Resource: `arn:aws:s3:::${LOG_BUCKET}`,
          },
          {
            Sid: "AWSCloudTrailWrite",
            Effect: "Allow",
            Principal: { Service: "cloudtrail.amazonaws.com" },
            Action: "s3:PutObject",
            Resource: `arn:aws:s3:::${LOG_BUCKET}/AWSLogs/${LAB_ACCOUNT}/*`,
          },
        ],
      },
    },
  }),
  R("23:53:37", "iam", "CreateRole", "Coral/Jakarta", {
    ...write,
    awsRegion: "us-east-1",
    requestParameters: {
      path: "/service-role/",
      roleName: "ExampleTrailRoleForCloudWatchLogs",
      assumeRolePolicyDocument:
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
    },
  }),
  R("23:53:37", "iam", "AttachRolePolicy", "Coral/Jakarta", {
    ...write,
    awsRegion: "us-east-1",
    requestParameters: {
      roleName: "ExampleTrailRoleForCloudWatchLogs",
      policyArn: `arn:aws:iam::${LAB_ACCOUNT}:policy/service-role/ExampleTrailPolicyForCloudWatchLogs`,
    },
  }),
];

const logObject = (n: number): string =>
  `AWSLogs/${LAB_ACCOUNT}/vpcflowlogs/us-west-1/2021/07/29/${LAB_ACCOUNT}_vpcflowlogs_fl-0example_${n}.log.gz`;
const trailObject = (n: number): string =>
  `AWSLogs/${LAB_ACCOUNT}/CloudTrail/us-west-1/2021/07/29/${LAB_ACCOUNT}_CloudTrail_us-west-1_${n}.json.gz`;
const dataEvent: Rec = { eventCategory: "Data", managementEvent: false };

/** AWS log delivery writing into the log bucket — the noise that used to grade Medium and Low. */
export const LOG_DELIVERY: readonly Rec[] = [
  rec(
    t("23:58:37"),
    "s3",
    "PutObject",
    service("delivery.logs.amazonaws.com"),
    "delivery.logs.amazonaws.com",
    "delivery.logs.amazonaws.com",
    {
      ...write,
      ...dataEvent,
      ...denied(),
      requestParameters: { ...bucket(LOG_BUCKET), key: logObject(1) },
    },
  ),
  rec(
    t("23:59:37"),
    "s3",
    "PutObject",
    service("delivery.logs.amazonaws.com"),
    "delivery.logs.amazonaws.com",
    "delivery.logs.amazonaws.com",
    {
      ...write,
      ...dataEvent,
      ...denied(),
      requestParameters: { ...bucket(LOG_BUCKET), key: logObject(2) },
    },
  ),
  rec(
    t("00:13:37", "30"),
    "s3",
    "HeadBucket",
    service("delivery.logs.amazonaws.com"),
    "delivery.logs.amazonaws.com",
    "delivery.logs.amazonaws.com",
    {
      ...dataEvent,
      ...denied(),
      requestParameters: bucket(LOG_BUCKET),
    },
  ),
  rec(
    t("23:58:42"),
    "s3",
    "PutObject",
    service("cloudtrail.amazonaws.com"),
    "cloudtrail.amazonaws.com",
    "cloudtrail.amazonaws.com",
    {
      ...write,
      ...dataEvent,
      requestParameters: {
        ...bucket(LOG_BUCKET),
        key: trailObject(1),
        "x-amz-server-side-encryption": "aws:kms",
      },
    },
  ),
  rec(
    t("02:44:13", "30"),
    "s3",
    "PutObject",
    service("cloudtrail.amazonaws.com"),
    "cloudtrail.amazonaws.com",
    "cloudtrail.amazonaws.com",
    {
      ...write,
      ...dataEvent,
      errorCode: "InternalError",
      errorMessage: "We encountered an internal error. Please try again.",
      requestParameters: { ...bucket(LOG_BUCKET), key: trailObject(2) },
    },
  ),
];

/** The first object reads in the evidence: an administrator syncing the log bucket the next day. */
export const LATER_READS: readonly Rec[] = [
  rec(
    t("16:32:44", "30"),
    "s3",
    "ListObjects",
    {
      type: "IAMUser",
      principalId: "AIDAEXAMPLEADMIN0001",
      arn: `arn:aws:iam::${LAB_ACCOUNT}:user/example-admin`,
      accountId: LAB_ACCOUNT,
      accessKeyId: "AKIAEXAMPLEADMINKEY1",
      userName: "example-admin",
    },
    COMPANY_IP,
    "[aws-cli/2.2.16 command/s3.sync]",
    { ...dataEvent, requestParameters: { ...bucket(LOG_BUCKET), prefix: "" } },
  ),
  rec(
    t("16:32:46", "30"),
    "s3",
    "GetObject",
    {
      type: "IAMUser",
      principalId: "AIDAEXAMPLEADMIN0001",
      arn: `arn:aws:iam::${LAB_ACCOUNT}:user/example-admin`,
      accountId: LAB_ACCOUNT,
      accessKeyId: "AKIAEXAMPLEADMINKEY1",
      userName: "example-admin",
    },
    COMPANY_IP,
    "[aws-cli/2.2.16 command/s3.sync]",
    { ...dataEvent, requestParameters: { ...bucket(LOG_BUCKET), key: trailObject(1) } },
  ),
];

/** Every record of the lab fixture, in time order. */
export function sans504Records(): Rec[] {
  return [...ATTACK, ...RESPONDER, ...WIZARD_BURST, ...LOG_DELIVERY, ...LATER_READS].sort((a, b) =>
    String(a.eventTime).localeCompare(String(b.eventTime)),
  );
}

/** The lab as one CloudTrail upload. */
export function sans504Upload(): string {
  return JSON.stringify({ Records: sans504Records() });
}
