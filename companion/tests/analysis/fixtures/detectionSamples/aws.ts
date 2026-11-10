// AWS CloudTrail samples for the detection-overlap check (#2348), copied from the records the cloud
// tagger and Sigma tests already use (tagsYamlCloudGaps, tagsYamlRemainingSources,
// tagsYamlSigmaOverlap, sigmaCloudImport, tagsYamlTrailDiscover). The originals stay in their tests.
import { sample, type DetectionSample } from "./types.js";

/** The CloudTrail record base every sample (and every Sigma-built sample) starts from. */
export const cloudTrailBase = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  eventVersion: "1.08",
  eventTime: "2026-03-01T10:00:00Z",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: {
    type: "IAMUser",
    userName: "alice",
    accountId: "111111111111",
    arn: "arn:aws:iam::111111111111:user/alice",
  },
  recipientAccountId: "111111111111",
  readOnly: false,
  eventID: "00000000-0000-4000-8000-000000000001",
  ...o,
});

const ct = (id: string, from: string, eventSource: string, eventName: string, extra = {}) =>
  sample("cloudtrail", id, from, cloudTrailBase({ eventSource, eventName, ...extra }));

const GAPS = "tagsYamlCloudGaps";
const TS = "tagsYamlRemainingSources (Timesketch AWS)";
const SIGMA = "sigmaCloudImport";
const LAB = "awsSans504Lab (#2542)";
const TD = "tagsYamlTrailDiscover (#2345)";
const S3_BROWSER = "S3 Browser 11.5.7 https://s3browser.com";

const snapshotPerm = (perm: unknown) => ({
  requestParameters: {
    snapshotId: "snap-0123456789abcdef0",
    attributeType: "CREATE_VOLUME_PERMISSION",
    createVolumePermission: perm,
  },
});
const recorder = { requestParameters: { configurationRecorderName: "default" } };
const channel = { requestParameters: { deliveryChannelName: "default" } };

export const AWS_SAMPLES: readonly DetectionSample[] = [
  ct("aws.PutEventSelectors", GAPS, "cloudtrail.amazonaws.com", "PutEventSelectors", {
    requestParameters: {
      trailName: "main",
      eventSelectors: [{ readWriteType: "WriteOnly", includeManagementEvents: false }],
    },
  }),
  ct("aws.ModifySnapshotAttribute.shareAccount", GAPS, "ec2.amazonaws.com", "ModifySnapshotAttribute", {
    ...snapshotPerm({ add: { items: [{ userId: "444455556666" }] } }),
  }),
  ct("aws.ModifySnapshotAttribute.public", GAPS, "ec2.amazonaws.com", "ModifySnapshotAttribute", {
    ...snapshotPerm({ add: { items: [{ group: "all" }] } }),
  }),
  ct("aws.ModifySnapshotAttribute.unshare", GAPS, "ec2.amazonaws.com", "ModifySnapshotAttribute", {
    ...snapshotPerm({ remove: { items: [{ userId: "444455556666" }] } }),
  }),
  ct("aws.PutBucketPolicy.public", GAPS, "s3.amazonaws.com", "PutBucketPolicy", {
    requestParameters: {
      bucketName: "b1",
      bucketPolicy: {
        Version: "2012-10-17",
        Statement: [
          { Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::b1/*" },
        ],
      },
    },
  }),
  ct("aws.PutBucketAcl.allUsers", GAPS, "s3.amazonaws.com", "PutBucketAcl", {
    requestParameters: {
      bucketName: "b3",
      AccessControlPolicy: {
        AccessControlList: {
          Grant: [
            { Grantee: { URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "READ" },
          ],
        },
      },
    },
  }),
  ct("aws.PutBucketAcl.cannedPublic", GAPS, "s3.amazonaws.com", "PutBucketAcl", {
    requestParameters: { bucketName: "b4", "x-amz-acl": ["public-read"] },
  }),
  ct("aws.ConsoleLogin", TS, "signin.amazonaws.com", "ConsoleLogin"),
  ct("aws.GetCallerIdentity", TS, "sts.amazonaws.com", "GetCallerIdentity", { readOnly: true }),
  ct("aws.CreateAccessKey", TS, "iam.amazonaws.com", "CreateAccessKey", {
    requestParameters: { userName: "bob" },
  }),
  ct("aws.CreateAccessKey.s3browser", SIGMA, "iam.amazonaws.com", "CreateAccessKey", {
    requestParameters: { userName: "bob" },
    userAgent: S3_BROWSER,
  }),
  ct("aws.AttachUserPolicy", TS, "iam.amazonaws.com", "AttachUserPolicy", {
    requestParameters: { userName: "bob", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" },
  }),
  ct("aws.StartSSO", TS, "sso.amazonaws.com", "StartSSO"),
  ct("aws.CreatePermissionSet", TS, "sso.amazonaws.com", "CreatePermissionSet"),
  ct("aws.AuthorizeSecurityGroupIngress", TS, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress"),
  ct("aws.CreateNetworkAcl", TS, "ec2.amazonaws.com", "CreateNetworkAcl"),
  ct("aws.CreateRouteTable", TS, "ec2.amazonaws.com", "CreateRouteTable"),
  ct("aws.CreateVpc", TS, "ec2.amazonaws.com", "CreateVpc"),
  ct("aws.AttachInternetGateway", TS, "ec2.amazonaws.com", "AttachInternetGateway"),
  ct("aws.CreateUser", SIGMA, "iam.amazonaws.com", "CreateUser", { requestParameters: { userName: "eve" } }),
  ct("aws.CreateUser.s3browser", SIGMA, "iam.amazonaws.com", "CreateUser", {
    requestParameters: { userName: "eve" },
    userAgent: S3_BROWSER,
  }),
  ct("aws.StopLogging", SIGMA, "cloudtrail.amazonaws.com", "StopLogging", {
    requestParameters: { name: "main" },
  }),
  ct("aws.UpdateTrail", SIGMA, "cloudtrail.amazonaws.com", "UpdateTrail", {
    requestParameters: { name: "main" },
  }),
  ct("aws.BatchUpdateFindings", SIGMA, "securityhub.amazonaws.com", "BatchUpdateFindings"),
  ct("aws.StopConfigurationRecorder", SIGMA, "config.amazonaws.com", "StopConfigurationRecorder", recorder),
  ct("aws.StopConfigurationRecorder.notFound", SIGMA, "config.amazonaws.com", "StopConfigurationRecorder", {
    ...recorder,
    errorCode: "NoSuchConfigurationRecorderException",
  }),
  ct("aws.StopConfigurationRecorder.denied", SIGMA, "config.amazonaws.com", "StopConfigurationRecorder", {
    ...recorder,
    errorCode: "AccessDenied",
  }),
  ct("aws.DeleteDeliveryChannel.notFound", SIGMA, "config.amazonaws.com", "DeleteDeliveryChannel", {
    ...channel,
    errorCode: "NoSuchDeliveryChannelException",
  }),
  // TrailDiscover graded rules (#2345): one sample per operation, plus a root caller.
  ct("aws.td.DisassociateFromMasterAccount", TD, "guardduty.amazonaws.com", "DisassociateFromMasterAccount", {
    requestParameters: { detectorId: "12abc34d567e8fa901bc2d34e56789f0" },
  }),
  ct(
    "aws.td.DisassociateFromMasterAccount.root",
    TD,
    "guardduty.amazonaws.com",
    "DisassociateFromMasterAccount",
    {
      userIdentity: {
        type: "Root",
        principalId: "111111111111",
        accountId: "111111111111",
        arn: "arn:aws:iam::111111111111:root",
      },
    },
  ),
  ct(
    "aws.td.DisassociateFromAdministratorAccount",
    TD,
    "guardduty.amazonaws.com",
    "DisassociateFromAdministratorAccount",
  ),
  ct("aws.td.DeleteInvitations", TD, "guardduty.amazonaws.com", "DeleteInvitations", {
    requestParameters: { accountIds: ["222222222222"] },
  }),
  ct("aws.td.AcceptHandshake", TD, "organizations.amazonaws.com", "AcceptHandshake", {
    requestParameters: { handshakeId: "h-examplehandshakeid111" },
  }),
  ct("aws.td.PutAccountDetails", TD, "ses.amazonaws.com", "PutAccountDetails"),
  ct("aws.td.EnableSerialConsoleAccess", TD, "ec2.amazonaws.com", "EnableSerialConsoleAccess"),
  ct(
    "aws.td.SendSerialConsoleSSHPublicKey",
    TD,
    "ec2-instance-connect.amazonaws.com",
    "SendSerialConsoleSSHPublicKey",
    {
      requestParameters: { instanceId: "i-0123456789abcdef0", serialPort: 0 },
    },
  ),
  ct(
    "aws.td.ReplaceIamInstanceProfileAssociation",
    TD,
    "ec2.amazonaws.com",
    "ReplaceIamInstanceProfileAssociation",
    {
      requestParameters: {
        associationId: "iip-assoc-0123456789abcdef0",
        iamInstanceProfile: { name: "AdminProfile" },
      },
    },
  ),
  ...["SharedSnapshotCopyInitiated", "SharedSnapshotVolumeCreated"].map((name) =>
    ct(`aws.td.${name}`, TD, "ec2.amazonaws.com", name, {
      eventType: "AwsServiceEvent",
      sourceIPAddress: "ec2.amazonaws.com",
      userIdentity: { type: "AWSAccount", principalId: "", accountId: "222222222222" },
      serviceEventDetails: { snapshotId: "snap-0123456789abcdef0" },
    }),
  ),
  ...["CreateSAMLProvider", "CreateOpenIDConnectProvider"].map((name) =>
    ct(`aws.td.${name}`, TD, "iam.amazonaws.com", name, { requestParameters: { name: "ExampleIdP" } }),
  ),
  ct("aws.td.DeleteDBInstance", TD, "rds.amazonaws.com", "DeleteDBInstance", {
    requestParameters: { dBInstanceIdentifier: "prod-db-1", skipFinalSnapshot: true },
  }),
  ...["PutUseCaseForModelAccess", "CreateFoundationModelAgreement", "PutFoundationModelEntitlement"].map(
    (name) => ct(`aws.td.${name}`, TD, "bedrock.amazonaws.com", name),
  ),
  ct("aws.td.PasswordRecoveryRequested.root", TD, "signin.amazonaws.com", "PasswordRecoveryRequested", {
    eventType: "AwsConsoleSignIn",
    userIdentity: {
      type: "Root",
      principalId: "111111111111",
      accountId: "111111111111",
      arn: "arn:aws:iam::111111111111:root",
    },
    responseElements: { PasswordRecoveryRequested: "Success" },
  }),
  // #2542: AWS log delivery (an AWSService caller) and a read-only "not found" answer — the importer
  // now leaves both at Info — and a self-granted *:* inline policy, which it grades Critical.
  ...[
    ["PutObject", false, "AccessDenied"],
    ["HeadBucket", true, "AccessDenied"],
    ["PutObject", false, ""],
  ].map(([name, readOnly, errorCode], i) =>
    ct(`aws.2542.service.${name}.${i}`, LAB, "s3.amazonaws.com", name as string, {
      userIdentity: { type: "AWSService", invokedBy: "delivery.logs.amazonaws.com" },
      sourceIPAddress: "delivery.logs.amazonaws.com",
      userAgent: "delivery.logs.amazonaws.com",
      readOnly,
      ...(errorCode ? { errorCode, errorMessage: "Access Denied" } : {}),
      requestParameters: { bucketName: "example-log", key: `AWSLogs/111111111111/x-${i}.log.gz` },
    }),
  ),
  ct(
    "aws.2542.notfound.GetBucketObjectLockConfiguration",
    LAB,
    "s3.amazonaws.com",
    "GetBucketObjectLockConfiguration",
    {
      readOnly: true,
      errorCode: "ObjectLockConfigurationNotFoundError",
      errorMessage: "Object Lock configuration does not exist for this bucket",
      requestParameters: { bucketName: "example-eng" },
    },
  ),
  ct("aws.2542.PutUserPolicy.self.admin", LAB, "iam.amazonaws.com", "PutUserPolicy", {
    requestParameters: {
      userName: "alice",
      policyName: "examplepolicy1",
      policyDocument: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    },
  }),
];
