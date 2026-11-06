import type { AwsCheckClients, AwsCommandSender } from "../../../src/integrations/cloudCheck/awsReadCheck.js";
import type { GcpRequester } from "../../../src/integrations/cloudCheck/gcpReadCheck.js";
import type { MicrosoftCheckClients } from "../../../src/integrations/cloudCheck/microsoftReadCheck.js";
import type { CloudFetch } from "../../../src/integrations/cloudTransport/cloudFetch.js";

// Mocked cloud clients for the read check (#2309). Every call is recorded, so a test can assert the
// check sent only allow-listed READ operations.

/** The only operations the check may ever send. */
export const ALLOWED_AWS_COMMANDS = new Set([
  "GetCallerIdentityCommand",
  "LookupEventsCommand",
  "ListObjectsV2Command",
  "GetObjectCommand",
  "ListDetectorsCommand",
]);

export function awsDenied(name = "AccessDenied", message = "Access Denied"): Error {
  return Object.assign(new Error(message), { name, $metadata: { httpStatusCode: 403 } });
}

type AwsAnswer = (input: Record<string, unknown>) => unknown;

/** AWS clients whose commands answer from `answers` by command name; anything else is denied. */
export function mockAws(answers: Record<string, AwsAnswer | Error>): {
  clients: AwsCheckClients;
  sent: string[];
} {
  const sent: string[] = [];
  const sender: AwsCommandSender = {
    send: async (command) => {
      const name = command.constructor.name;
      sent.push(name);
      const answer = answers[name];
      if (answer === undefined) throw awsDenied();
      if (answer instanceof Error) throw answer;
      return answer((command as { input: Record<string, unknown> }).input);
    },
  };
  return { clients: { sts: sender, cloudtrail: sender, s3: sender, ec2: sender, guardduty: sender }, sent };
}

export const AWS_ALL_OK: Record<string, AwsAnswer> = {
  GetCallerIdentityCommand: () => ({ Arn: "arn:aws:sts::123456789012:assumed-role/dfir-collector/check" }),
  LookupEventsCommand: () => ({ Events: [{}] }),
  ListObjectsV2Command: () => ({ Contents: [{ Key: "AWSLogs/123456789012/CloudTrail/x.json.gz" }] }),
  GetObjectCommand: () => ({ Body: { transformToByteArray: async () => new Uint8Array([31]) } }),
  // #2363: the regions enabled on the account.
  DescribeRegionsCommand: () => ({ Regions: [{ RegionName: "eu-west-1" }, { RegionName: "af-south-1" }] }),
  ListDetectorsCommand: () => ({ DetectorIds: ["12abc34d567e8fa901bc2d34e56789f0"] }),
};

export interface RecordedCall {
  method: string;
  url: string;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** A Graph fetch that answers by URL path; anything unlisted is 403. */
export function mockGraph(
  byPath: Record<string, { status: number; body?: unknown }>,
  token: string | Error = "graph-token-abc",
): { clients: MicrosoftCheckClients; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetch: CloudFetch = async (input, init = {}) => {
    const url = new URL(input);
    calls.push({ method: init.method ?? "GET", url: url.href });
    const answer = byPath[url.pathname];
    if (!answer)
      return json(403, {
        error: { code: "Authorization_RequestDenied", message: "Insufficient privileges" },
      });
    return json(answer.status, answer.body ?? { value: [] });
  };
  const getToken = async () => {
    if (token instanceof Error) throw token;
    return token;
  };
  return { clients: { getToken, fetch }, calls };
}

export function gcpDenied(message = "Permission denied"): Error {
  return Object.assign(new Error("Request failed with status code 403"), {
    name: "GaxiosError",
    response: { status: 403, data: { error: { status: "PERMISSION_DENIED", message } } },
  });
}

/** A Google auth client that answers entries:list by which audit log the filter names. */
export function mockGcp(answer: (filter: string) => { entries?: unknown[] } | Error): {
  client: GcpRequester;
  calls: (RecordedCall & { data: Record<string, unknown> })[];
} {
  const calls: (RecordedCall & { data: Record<string, unknown> })[] = [];
  const client: GcpRequester = {
    request: async (opts) => {
      const data = opts.data as Record<string, unknown>;
      calls.push({ method: opts.method, url: opts.url, data });
      const out = answer(String(data.filter));
      if (out instanceof Error) throw out;
      return { data: out };
    },
  };
  return { client, calls };
}
