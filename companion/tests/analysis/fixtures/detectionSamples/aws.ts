// AWS CloudTrail samples for the detection-overlap check (#2348), copied from the records the cloud
// tagger and Sigma tests already use (tagsYamlCloudGaps, tagsYamlRemainingSources,
// tagsYamlSigmaOverlap, sigmaCloudImport). The originals stay in their tests.
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
];
