import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { createCheckClientFactory } from "../../../src/integrations/cloudCheck/checkClients.js";
import { runCloudAccountCheck } from "../../../src/integrations/cloudCheck/runCloudCheck.js";
import { createCloudTransport } from "../../../src/integrations/cloudTransport/cloudAgent.js";
import type { CloudFetch } from "../../../src/integrations/cloudTransport/cloudFetch.js";
import type { OpenCloudAccount } from "../../../src/integrations/cloudAccounts/types.js";
import { fakeAccessKeyId, fakeAwsSecret } from "../../helpers/cloudAccountFixtures.js";

// #2309 acceptance: the check never calls a write or simulate API. The unit tests prove it on mocks;
// this proves it on the WIRE, through the real AWS SDK clients the check builds, by recording every
// HTTP request they send — and sweeps the check's source for any write or simulate API name.

interface WireRequest {
  method: string;
  hostname: string;
  path: string;
  query: Record<string, unknown>;
  headers: Record<string, string>;
  body?: unknown;
}

const STS_OK =
  '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>' +
  "<Arn>arn:aws:iam::123456789012:user/collector</Arn><UserId>U1</UserId><Account>123456789012</Account>" +
  "</GetCallerIdentityResult><ResponseMetadata><RequestId>r1</RequestId></ResponseMetadata></GetCallerIdentityResponse>";
const S3_LIST =
  '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
  "<Name>trail-bucket</Name><Prefix>AWSLogs/</Prefix><KeyCount>1</KeyCount><MaxKeys>1</MaxKeys>" +
  "<IsTruncated>false</IsTruncated><Contents><Key>AWSLogs/123456789012/CloudTrail/a.json.gz</Key><Size>9</Size>" +
  "</Contents></ListBucketResult>";
const DENIED =
  '<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>';

function bodyText(body: unknown): string {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return Buffer.from(body).toString("utf8");
  return "";
}

/** Answers STS sign-in and the S3 listing; denies every other request (403). Records them all. */
function recordingHandler(sent: WireRequest[]) {
  const reply = (status: number, xml: string) => ({
    response: {
      statusCode: status,
      headers: { "content-type": "application/xml" },
      body: Readable.from([Buffer.from(xml)]),
    },
  });
  return {
    metadata: { handlerProtocol: "http/1.1" },
    handle: async (req: WireRequest) => {
      sent.push(req);
      if (req.hostname.startsWith("sts.")) return reply(200, STS_OK);
      if (req.hostname.includes("s3") && req.query["list-type"] === "2") return reply(200, S3_LIST);
      return reply(403, DENIED);
    },
    updateHttpClientConfig: () => undefined,
    httpHandlerConfigs: () => ({}),
    destroy: () => undefined,
  };
}

/** The operation each recorded request names, the way AWS routes it. */
function operation(req: WireRequest): string {
  const target = req.headers["x-amz-target"];
  if (target) return target.split(".").pop() ?? target;
  const action = /(?:^|&)Action=([A-Za-z]+)/.exec(bodyText(req.body))?.[1];
  if (action) return action;
  if (req.hostname.includes("s3") && req.method === "GET")
    return req.query["list-type"] === "2" ? "ListObjectsV2" : "GetObject";
  return `${req.method} ${req.hostname}${req.path}`;
}

const awsAccount = (): OpenCloudAccount => ({
  id: "a1",
  name: "AWS wire",
  revision: 1,
  createdAt: "",
  updatedAt: "",
  provider: "aws",
  settings: { authMode: "access-key", region: "eu-west-1" },
  secrets: { accessKeyId: fakeAccessKeyId(), secretAccessKey: fakeAwsSecret() },
});

describe("the read check on the wire", () => {
  it("sends only the four allow-listed AWS reads, and never a write or simulate call", async () => {
    const sent: WireRequest[] = [];
    const neverFetch: CloudFetch = async () => {
      throw new Error("no Graph call expected for AWS");
    };
    const transport = createCloudTransport({});
    const factory = createCheckClientFactory(transport, {
      awsConfig: { requestHandler: recordingHandler(sent) },
      fetch: neverFetch,
    });
    const report = await runCloudAccountCheck(
      awsAccount(),
      { sources: ["cloudtrail-lookup", "s3-trail"], s3Bucket: "trail-bucket" },
      () => factory,
    );
    const ops = sent.map(operation);
    expect(ops).toEqual(["GetCallerIdentity", "LookupEvents", "ListObjectsV2", "GetObject"]);
    for (const req of sent) expect(["GET", "POST"]).toContain(req.method);
    expect(sent.filter((r) => r.method === "POST").map(operation)).toEqual([
      "GetCallerIdentity",
      "LookupEvents",
    ]);
    expect(report.signedInAs).toBe("arn:aws:iam::123456789012:user/collector");
    expect(report.results.map((r) => r.status)).toEqual(["failed", "failed"]);
    expect(report.summary).toMatch(/^Tested reads succeeded for: none\. Failed: CloudTrail event history/);
  });
});

describe("the read check's source", () => {
  const dir = new URL("../../../src/integrations/cloudCheck/", import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith(".ts"));
  const code = files.map((f) => readFileSync(join(dir.pathname, f), "utf8")).join("\n");

  it("names no write, delete or simulate API", () => {
    expect(files.length).toBeGreaterThan(5);
    const forbidden = [
      /Simulate[A-Za-z]*Polic/,
      /\b(?:Put|Delete|Create|Update|Copy|Restore)[A-Z][A-Za-z]*Command\b/,
      /\bentries:write\b/,
      /security\/auditLog\/queries/,
      /method:\s*"(?:PUT|PATCH|DELETE)"/,
    ];
    for (const re of forbidden) expect(code, String(re)).not.toMatch(re);
  });

  it("imports only the read commands from the AWS SDK", () => {
    const commands = [...code.matchAll(/\b([A-Z][A-Za-z0-9]*Command)\b/g)].map((m) => m[1]);
    expect(new Set(commands)).toEqual(
      new Set([
        "GetCallerIdentityCommand",
        "LookupEventsCommand",
        "ListObjectsV2Command",
        "GetObjectCommand",
      ]),
    );
  });

  it("only ever POSTs to entries:list", () => {
    // A call site's `method: "POST",` — the GcpRequester type spells it `method: "POST";`.
    expect([...code.matchAll(/method:\s*"POST"\s*[,}]/g)].length).toBe(1);
    expect(code).toMatch(/url: GCP_ENTRIES_LIST_URL,\s*method: "POST"/);
  });
});
