// The AWS identity reader (#931 item 5): what ONE CloudTrail record says about who called — the
// kind, the credential in use, the session's issuer, the session's own attributes, the accounts —
// in the record's words, and the STS issuance rows, each with its own documented layout. Nothing
// is inferred from a key prefix, a type label alone, or a display name.
import { describe, expect, it } from "vitest";
import { readAwsIdentity, readCredentialIssuance } from "../../src/analysis/awsIdentity.js";

const ACCT = "111122223333";
const OTHER = "444455556666";
const ROLE_ARN = `arn:aws:iam::${ACCT}:role/admin-role`;
const assumed = (over: Record<string, unknown> = {}, rec: Record<string, unknown> = {}) => ({
  userIdentity: {
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
      ...(over.sessionContext as Record<string, unknown> | undefined),
    },
    ...over,
  },
  recipientAccountId: ACCT,
  eventID: "evt-1",
  ...rec,
});

describe("readAwsIdentity — kinds and words", () => {
  it("an assumed role: kind, key, issuer with the record's type, session name, since, CloudTrail's own MFA claim", () => {
    const id = readAwsIdentity(assumed());
    expect(id.kind).toBe("AssumedRole");
    expect(id.credential).toMatchObject({ accessKeyId: "ASIAEXAMPLEKEY000001", class: "temporary" });
    expect(id.issuer).toMatchObject({ type: "Role", arn: ROLE_ARN, accountId: ACCT, userName: "admin-role" });
    expect(id.session).toMatchObject({
      name: "i-0abc123",
      creationDate: "2024-05-01T09:00:00Z",
      mfa: "false",
    });
    expect(id.words).toBe(
      `AssumedRole key ASIAEXAMPLEKEY000001 (temporary) session i-0abc123 since 2024-05-01T09:00:00Z CloudTrail mfaAuthenticated=false issuer Role ${ROLE_ARN}`,
    );
    expect(id.words).not.toMatch(/no MFA|issued by role/);
  });
  it("an IAM user: long-term without a sessionContext, temporary with one (GetSessionToken)", () => {
    const user = readAwsIdentity({
      userIdentity: {
        type: "IAMUser",
        principalId: "AIDAEXAMPLE",
        arn: `arn:aws:iam::${ACCT}:user/bob`,
        accountId: ACCT,
        accessKeyId: "AKIAEXAMPLEKEY000001",
        userName: "bob",
      },
    });
    expect(user.kind).toBe("IAMUser");
    expect(user.credential.class).toBe("long-term");
    expect(user.words).toBe("IAMUser key AKIAEXAMPLEKEY000001 (long-term)");
    const token = readAwsIdentity({
      userIdentity: {
        type: "IAMUser",
        principalId: "AIDAEXAMPLE",
        accountId: ACCT,
        accessKeyId: "ASIAEXAMPLEKEY000002",
        userName: "bob",
        sessionContext: { attributes: { creationDate: "2024-05-01T09:00:00Z", mfaAuthenticated: "true" } },
      },
    });
    expect(token.credential.class).toBe("temporary");
    expect(token.words).toContain("CloudTrail mfaAuthenticated=true");
  });
  it("Role without a sessionContext is a persistent identity of unknown credential class — never 'temporary' from the label", () => {
    const r = readAwsIdentity({
      userIdentity: { type: "Role", principalId: "AROAEXAMPLEID", arn: ROLE_ARN, accountId: ACCT },
    });
    expect(r.credential.class).toBe("persistent identity, credential class unknown");
  });
  it("a federated user names its issuer with the issuer's own type, never 'role'", () => {
    const f = readAwsIdentity({
      userIdentity: {
        type: "FederatedUser",
        principalId: `${ACCT}:contractor`,
        arn: `arn:aws:sts::${ACCT}:federated-user/contractor`,
        accountId: ACCT,
        accessKeyId: "ASIAEXAMPLEKEY000003",
        sessionContext: {
          sessionIssuer: {
            type: "IAMUser",
            principalId: "AIDAEXAMPLE",
            arn: `arn:aws:iam::${ACCT}:user/bob`,
            accountId: ACCT,
            userName: "bob",
          },
          attributes: { creationDate: "2024-05-01T09:00:00Z", mfaAuthenticated: "false" },
        },
      },
    });
    expect(f.kind).toBe("FederatedUser");
    expect(f.session.name).toBe("contractor");
    expect(f.words).toContain(`issuer IAMUser arn:aws:iam::${ACCT}:user/bob`);
    expect(f.credential.class).toBe("temporary");
  });
  it("SAMLUser and WebIdentityUser are the external caller of an issuance, not a credential in use", () => {
    const s = readAwsIdentity({
      userIdentity: {
        type: "SAMLUser",
        principalId: "idp:alice",
        userName: "alice",
        identityProvider: "https://idp.example.invalid",
      },
    });
    expect(s.credential.class).toBe("not a credential in use");
    expect(s.words).toBe("SAMLUser (not a credential in use) provider https://idp.example.invalid");
    expect(
      readAwsIdentity({
        userIdentity: {
          type: "WebIdentityUser",
          principalId: "accounts.google.com:123",
          identityProvider: "accounts.google.com",
        },
      }).credential.class,
    ).toBe("not a credential in use");
  });
  it("a service request, another account, root, Identity Center, and an unknown type kept verbatim", () => {
    const svc = readAwsIdentity({ userIdentity: { type: "AWSService", invokedBy: "ec2.amazonaws.com" } });
    expect(svc.kind).toBe("AWSService");
    expect(svc.words).toBe(
      "AWSService (not a credential in use) request made by AWS service ec2.amazonaws.com",
    );
    const acct = readAwsIdentity({
      userIdentity: { type: "AWSAccount", principalId: "AIDAEXAMPLE", accountId: OTHER },
      recipientAccountId: ACCT,
    });
    expect(acct.words).toBe(
      `AWSAccount (not a credential in use) cross-account: caller ${OTHER}, recipient ${ACCT}`,
    );
    expect(acct.accounts).toEqual({ caller: OTHER, recipient: ACCT, crossAccount: true });
    const root = readAwsIdentity({
      userIdentity: {
        type: "Root",
        principalId: ACCT,
        arn: `arn:aws:iam::${ACCT}:root`,
        accountId: ACCT,
        accessKeyId: "AKIAEXAMPLEKEY000009",
      },
    });
    expect(root.words).toBe("Root key AKIAEXAMPLEKEY000009 (long-term)");
    const ic = readAwsIdentity({
      userIdentity: {
        type: "IdentityCenterUser",
        accountId: ACCT,
        credentialId: "cred-1",
        onBehalfOf: {
          userId: "u-1",
          identityStoreArn: "arn:aws:identitystore::111122223333:identitystore/d-1",
        },
      },
    });
    expect(ic.credential).toMatchObject({ credentialId: "cred-1", class: "temporary" });
    expect(ic.words).toContain("key cred-1 (temporary)");
    const odd = readAwsIdentity({ userIdentity: { type: "SomethingNew", principalId: "x" } });
    expect(odd.kind).toBe("Unknown");
    expect(odd.words).toContain("type SomethingNew");
  });
  it("console origin, instance-role delivery, source identity, federation and assumed-root are literal", () => {
    const id = readAwsIdentity(
      assumed(
        {
          sessionContext: {
            sourceIdentity: "alice",
            ec2RoleDelivery: "2.0",
            webIdFederationData: {
              federatedProvider:
                "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
            },
            assumedRoot: "true",
          },
        },
        { sessionCredentialFromConsole: "true" },
      ),
    );
    expect(id.words).toContain("source identity alice");
    expect(id.words).toContain("credential originated from a console session");
    expect(id.words).toContain("instance-role credentials delivered via IMDSv2");
    expect(id.words).toContain(
      "federated via arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
    );
    expect(id.words).toContain("assumed-root session");
    expect(id.assumedRoot).toBe(true);
    expect(id.protocol).toBe("IMDSv2");
    expect(readAwsIdentity(assumed({ sessionContext: { ec2RoleDelivery: "1.0" } })).words).toContain(
      "via IMDSv1",
    );
    expect(readAwsIdentity(assumed({ sessionContext: { ec2RoleDelivery: "3.0" } })).words).toContain(
      "ec2RoleDelivery=3.0",
    );
    expect(readAwsIdentity(assumed({ sessionContext: { assumedRoot: true } })).assumedRoot).toBe(false);
  });
  it("cross-account is a fact of two account fields; equal or absent accounts are not cross-account", () => {
    expect(readAwsIdentity(assumed({}, { recipientAccountId: OTHER })).words).toContain(
      `cross-account: caller ${ACCT}, recipient ${OTHER}`,
    );
    expect(readAwsIdentity(assumed()).accounts.crossAccount).toBe(false);
    expect(readAwsIdentity(assumed({}, { recipientAccountId: undefined })).accounts).toEqual({
      caller: ACCT,
      recipient: "",
      crossAccount: false,
    });
  });
});

describe("readAwsIdentity — the key ladder and replicas", () => {
  it("a reused session name under two access keys is two keys; an absent or empty key falls down the ladder", () => {
    const k = (over: Record<string, unknown>, rec: Record<string, unknown> = {}) =>
      readAwsIdentity(assumed(over, rec)).keySegment;
    expect(k({ accessKeyId: "ASIAEXAMPLEKEY000001" })).not.toBe(k({ accessKeyId: "ASIAEXAMPLEKEY000002" }));
    const noKey = readAwsIdentity(assumed({ accessKeyId: undefined }));
    expect(noKey.credentialIdentity).toBe("AROAEXAMPLEID:i-0abc123@2024-05-01T09:00:00Z");
    expect(readAwsIdentity(assumed({ accessKeyId: "" })).credentialIdentity).toBe(
      "AROAEXAMPLEID:i-0abc123@2024-05-01T09:00:00Z",
    );
    expect(
      readAwsIdentity(
        assumed({ accessKeyId: "", signInSessionArn: "arn:aws:sts::111122223333:sign-in-session/x" }),
      ).credentialIdentity,
    ).toBe("arn:aws:sts::111122223333:sign-in-session/x");
    expect(readAwsIdentity(assumed({ accessKeyId: "", credentialId: "cred-9" })).credentialIdentity).toBe(
      "cred-9",
    );
    expect(
      k({ accessKeyId: undefined, sessionContext: { attributes: { creationDate: "2024-05-01T09:00:00Z" } } }),
    ).not.toBe(
      k({ accessKeyId: undefined, sessionContext: { attributes: { creationDate: "2024-05-01T10:00:00Z" } } }),
    );
  });
  it("the recipient account is not in the key (replicas of one action share a sharedEventID instead)", () => {
    const a = readAwsIdentity(assumed({}, { recipientAccountId: ACCT, sharedEventID: "shared-1" }));
    const b = readAwsIdentity(assumed({}, { recipientAccountId: OTHER, sharedEventID: "shared-1" }));
    expect(a.keySegment).toBe(b.keySegment);
    expect(a.replicaId).toBe("shared-1");
  });
  it("is safe on malformed shapes", () => {
    for (const ui of [
      null,
      "str",
      42,
      [],
      { sessionContext: [] },
      { sessionContext: { sessionIssuer: "x", attributes: 5 } },
      { type: ["AssumedRole"] },
    ]) {
      expect(() => readAwsIdentity({ userIdentity: ui })).not.toThrow();
    }
    expect(readAwsIdentity({}).kind).toBe("Unknown");
  });
});

describe("readCredentialIssuance — each STS action, its own layout", () => {
  const ok = (
    name: string,
    request: Record<string, unknown>,
    response: Record<string, unknown> | null,
    code = "",
    rec: Record<string, unknown> = {},
  ) =>
    readCredentialIssuance(
      name,
      request,
      response,
      code,
      { requestID: "req-1", eventID: "evt-1", ...rec },
      7,
    );
  const creds = {
    accessKeyId: "ASIAEXAMPLEISSUED001",
    expiration: "May 1, 2024, 10:00:00 AM",
    sessionToken: "SHOULD-NEVER-APPEAR",
    secretAccessKey: "NEVER-EITHER",
  };
  it("AssumeRole: role, session, issued key, expiration, MFA device, source identity, external id present (value never shown)", () => {
    const i = ok(
      "AssumeRole",
      {
        roleArn: ROLE_ARN,
        roleSessionName: "deploy",
        serialNumber: "arn:aws:iam::111122223333:mfa/bob",
        sourceIdentity: "bob",
        externalId: "SECRET-EXT",
        durationSeconds: 3600,
      },
      {
        assumedRoleUser: {
          arn: `arn:aws:sts::${ACCT}:assumed-role/admin-role/deploy`,
          assumedRoleId: "AROAEXAMPLEID:deploy",
        },
        credentials: creds,
      },
    )!;
    expect(i.action).toBe("AssumeRole");
    expect(i.words).toBe(
      `issues temporary credentials: role ${ROLE_ARN} session deploy → key ASIAEXAMPLEISSUED001 expires May 1, 2024, 10:00:00 AM MFA device arn:aws:iam::111122223333:mfa/bob source identity bob external id supplied`,
    );
    expect(JSON.stringify(i)).not.toMatch(/SECRET-EXT|SHOULD-NEVER-APPEAR|NEVER-EITHER/);
    expect(i.issuedKey).toBe("ASIAEXAMPLEISSUED001");
    expect(i.role).toMatchObject({
      arn: ROLE_ARN,
      assumedArn: `arn:aws:sts::${ACCT}:assumed-role/admin-role/deploy`,
    });
    expect(i.keySegment).toBe(`|issued:ASIAEXAMPLEISSUED001|${ROLE_ARN.toLowerCase()}`);
  });
  it("AssumeRoleWithSAML and AssumeRoleWithWebIdentity carry their session name, source identity, subject and provider", () => {
    const s = ok(
      "AssumeRoleWithSAML",
      {
        roleArn: ROLE_ARN,
        principalArn: `arn:aws:iam::${ACCT}:saml-provider/idp`,
        roleSessionName: "alice@example.invalid",
        sourceIdentity: "alice",
      },
      {
        assumedRoleUser: { arn: "x", assumedRoleId: "y" },
        credentials: creds,
        subject: "alice",
        subjectType: "persistent",
        issuer: "https://idp.example.invalid",
        audience: "https://signin.aws.amazon.com/saml",
      },
    )!;
    expect(s.words).toBe(
      `issues temporary credentials via SAML: provider arn:aws:iam::${ACCT}:saml-provider/idp subject alice (persistent) role ${ROLE_ARN} session alice@example.invalid → key ASIAEXAMPLEISSUED001 expires May 1, 2024, 10:00:00 AM source identity alice`,
    );
    const w = ok(
      "AssumeRoleWithWebIdentity",
      { roleArn: ROLE_ARN, roleSessionName: "gh", providerId: "token.actions.githubusercontent.com" },
      {
        assumedRoleUser: { arn: "x", assumedRoleId: "y" },
        credentials: creds,
        subjectFromWebIdentityToken: "repo:org/repo:ref:refs/heads/main",
        provider: "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
        audience: "sts.amazonaws.com",
      },
    )!;
    expect(w.words).toContain(
      "via web identity: provider arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com subject repo:org/repo:ref:refs/heads/main audience sts.amazonaws.com",
    );
  });
  it("GetFederationToken names the federated user; GetSessionToken has no role and no session entity", () => {
    const f = ok(
      "GetFederationToken",
      { name: "contractor", durationSeconds: 900, policy: "{}" },
      {
        federatedUser: {
          arn: `arn:aws:sts::${ACCT}:federated-user/contractor`,
          federatedUserId: `${ACCT}:contractor`,
        },
        credentials: creds,
        packedPolicySize: 6,
      },
    )!;
    expect(f.words).toBe(
      `issues federated credentials: user contractor → arn:aws:sts::${ACCT}:federated-user/contractor key ASIAEXAMPLEISSUED001 expires May 1, 2024, 10:00:00 AM policy supplied`,
    );
    const t = ok(
      "GetSessionToken",
      { durationSeconds: 3600, serialNumber: "arn:aws:iam::111122223333:mfa/bob" },
      { credentials: creds },
    )!;
    expect(t.words).toBe(
      "issues session credentials for the caller → key ASIAEXAMPLEISSUED001 expires May 1, 2024, 10:00:00 AM MFA device arn:aws:iam::111122223333:mfa/bob",
    );
    expect(t.role).toBeNull();
  });
  it("AssumeRoot reads the nested task policy ARN and is High on success, Medium when denied", () => {
    const r = ok(
      "AssumeRoot",
      {
        targetPrincipal: OTHER,
        taskPolicyArn: { arn: "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials" },
        durationSeconds: 900,
      },
      { credentials: creds, sourceIdentity: "bob" },
    )!;
    expect(r.words).toBe(
      `issues ROOT session credentials for account ${OTHER} under task policy arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials → key ASIAEXAMPLEISSUED001 expires May 1, 2024, 10:00:00 AM source identity bob`,
    );
    expect(r.severity).toBe("High");
    expect(r.mitre).toEqual(["T1078.004"]);
    const denied = ok(
      "AssumeRoot",
      { targetPrincipal: OTHER, taskPolicyArn: { arn: "x" } },
      null,
      "AccessDenied",
    )!;
    expect(denied.words).toBe(
      `attempted to issue ROOT session credentials for account ${OTHER} under task policy x — denied (AccessDenied)`,
    );
    expect(denied.severity).toBe("Medium");
    expect(denied.issuedKey).toBe("");
  });
  it("a denied AssumeRole is an attempt with no issued key; a success with no response says so and never invents a key", () => {
    const d = ok("AssumeRole", { roleArn: ROLE_ARN, roleSessionName: "deploy" }, null, "AccessDenied")!;
    expect(d.words).toBe(`attempted to assume role ${ROLE_ARN} session deploy — denied (AccessDenied)`);
    expect(d.issuedKey).toBe("");
    for (const response of [
      null,
      undefined,
      [],
      42,
      "x",
      { credentials: null },
      { credentials: [] },
      { credentials: { accessKeyId: 5 } },
    ]) {
      const t = ok("AssumeRole", { roleArn: ROLE_ARN, roleSessionName: "deploy" }, response as never)!;
      expect(t.words).toBe(
        `issues temporary credentials: role ${ROLE_ARN} session deploy — response details unavailable`,
      );
      expect(t.issuedKey).toBe("");
    }
  });
  it("the discriminator ladder: issued key → requestID → eventID → record index; two same-role calls with nothing else are two rows", () => {
    expect(ok("AssumeRole", { roleArn: ROLE_ARN }, null)!.keySegment).toBe(
      `|issued:req-1|${ROLE_ARN.toLowerCase()}`,
    );
    expect(ok("AssumeRole", { roleArn: ROLE_ARN }, null, "", { requestID: "" })!.keySegment).toBe(
      `|issued:evt-1|${ROLE_ARN.toLowerCase()}`,
    );
    const a = readCredentialIssuance("AssumeRole", { roleArn: ROLE_ARN }, null, "", {}, 1)!;
    const b = readCredentialIssuance("AssumeRole", { roleArn: ROLE_ARN }, null, "", {}, 2)!;
    expect(a.keySegment).toBe(`|issued:record:1|${ROLE_ARN.toLowerCase()}`);
    expect(a.keySegment).not.toBe(b.keySegment);
  });
  it("an operation that is not an STS issuance yields null", () => {
    expect(readCredentialIssuance("GetCallerIdentity", {}, {}, "", {}, 0)).toBeNull();
    expect(readCredentialIssuance("RunInstances", {}, {}, "", {}, 0)).toBeNull();
  });
});
