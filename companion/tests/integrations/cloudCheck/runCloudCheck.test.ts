import { describe, expect, it, vi } from "vitest";
import type { CheckClientFactory } from "../../../src/integrations/cloudCheck/checkClients.js";
import { createCheckClientFactory } from "../../../src/integrations/cloudCheck/checkClients.js";
import { X509Certificate } from "node:crypto";
import { PFX_UNREADABLE } from "../../../src/integrations/cloudAccounts/microsoftCertificate.js";
import { makeCertPem, makePfxBase64InMemory } from "../../helpers/cloudAccountFixtures.js";
import {
  parseCloudCheckRequest,
  runCloudAccountCheck,
} from "../../../src/integrations/cloudCheck/runCloudCheck.js";
import { createCloudTransport } from "../../../src/integrations/cloudTransport/cloudAgent.js";
import { CloudTransportError } from "../../../src/integrations/cloudTransport/destinationTls.js";
import type { OpenCloudAccount } from "../../../src/integrations/cloudAccounts/types.js";
import { AWS_ALL_OK, mockAws, mockGcp, mockGraph } from "./readCheckMocks.js";

// #2309: the orchestrator — request parsing, which clients it builds, and the report it returns.

const meta = { id: "a1", name: "acct", revision: 1, createdAt: "", updatedAt: "" };
const aws = (
  secrets: Record<string, string> = { accessKeyId: "id-1", secretAccessKey: "aws-secret-sentinel-x1" },
) => ({ ...meta, provider: "aws", settings: { authMode: "access-key" }, secrets }) as OpenCloudAccount;
const microsoft = (format: "pem" | "pfx", secrets: Record<string, string>) =>
  ({
    ...meta,
    provider: "microsoft",
    settings: { tenantId: "t", clientId: "c", certificateFormat: format },
    secrets,
  }) as OpenCloudAccount;
const gcp = {
  ...meta,
  provider: "gcp",
  settings: { projectId: "p1", authMode: "service-account-key" },
  secrets: {},
} as OpenCloudAccount;

function factoryOf(parts: Partial<CheckClientFactory>): () => CheckClientFactory {
  return () => ({
    aws: () => {
      throw new Error("unexpected aws");
    },
    microsoft: () => {
      throw new Error("unexpected microsoft");
    },
    gcp: async () => {
      throw new Error("unexpected gcp");
    },
    ...parts,
  });
}

describe("parseCloudCheckRequest", () => {
  it("defaults to every source of the provider, in report order", () => {
    expect(parseCloudCheckRequest("aws", {})).toEqual({
      ok: true,
      value: { sources: ["cloudtrail-lookup", "s3-trail", "guardduty"] },
    });
    expect(parseCloudCheckRequest("gcp", { sources: [] })).toEqual({
      ok: true,
      value: { sources: ["audit-logs", "data-access-logs"] },
    });
    expect(
      parseCloudCheckRequest("aws", { sources: ["s3-trail", "cloudtrail-lookup", "s3-trail"] }),
    ).toMatchObject({
      value: { sources: ["cloudtrail-lookup", "s3-trail"] },
    });
  });

  it("refuses a source of another provider and names the valid ones", () => {
    const out = parseCloudCheckRequest("microsoft", { sources: ["s3-trail"] });
    expect(out).toEqual({
      ok: false,
      error: "Unknown source for this account: s3-trail. Valid: entra-signins, entra-directory-audits.",
    });
    expect(parseCloudCheckRequest("aws", { sources: "s3-trail" }).ok).toBe(false);
  });

  it("checks the bucket name and prefix", () => {
    expect(
      parseCloudCheckRequest("aws", { s3Bucket: " trail-bucket ", s3Prefix: "org/AWSLogs/" }),
    ).toMatchObject({
      value: { s3Bucket: "trail-bucket", s3Prefix: "org/AWSLogs/" },
    });
    expect(parseCloudCheckRequest("aws", { s3Bucket: "Bad_Bucket" }).ok).toBe(false);
    expect(parseCloudCheckRequest("aws", { s3Bucket: 7 }).ok).toBe(false);
    expect(parseCloudCheckRequest("aws", { s3Prefix: "a\nb" }).ok).toBe(false);
  });
});

describe("runCloudAccountCheck", () => {
  it("runs the AWS check and returns the fixed summary", async () => {
    const { clients } = mockAws(AWS_ALL_OK);
    const report = await runCloudAccountCheck(
      aws(),
      { sources: ["cloudtrail-lookup"] },
      factoryOf({ aws: () => clients }),
    );
    expect(report).toMatchObject({ provider: "aws", signedInAs: expect.stringContaining("arn:aws:sts::") });
    expect(report.summary).toBe(
      "Tested reads succeeded for: CloudTrail event history. Failed: none. " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("signs in with a PFX certificate opened in memory (#2315)", async () => {
    const { pem } = makeCertPem();
    const pfxBase64 = makePfxBase64InMemory(pem, "pw-pfx");
    const { clients } = mockGraph({ "/v1.0/auditLogs/signIns": { status: 200 } });
    const seen: string[] = [];
    const report = await runCloudAccountCheck(
      microsoft("pfx", { pfxBase64, pfxPassword: "pw-pfx" }),
      { sources: ["entra-signins"] },
      factoryOf({ microsoft: (_s, derived) => (seen.push(derived), clients) }),
    );
    expect(seen).toHaveLength(1);
    expect(new X509Certificate(seen[0]).fingerprint256).toBe(new X509Certificate(pem).fingerprint256);
    expect(report.results[0].status).toBe("succeeded");
  });

  it("fails every source with fixed text when the PFX will not open, building no client", async () => {
    const factory = vi.fn(factoryOf({}));
    const report = await runCloudAccountCheck(
      microsoft("pfx", { pfxBase64: "AAAA", pfxPassword: "pw-wrong-sentinel" }),
      { sources: ["entra-signins", "entra-directory-audits"] },
      factory,
    );
    expect(factory).not.toHaveBeenCalled();
    expect(report.results.every((r) => r.status === "failed" && r.detail === PFX_UNREADABLE)).toBe(true);
    expect(JSON.stringify(report)).not.toContain("sentinel");
  });

  it("checks a PEM Microsoft account with the stored certificate", async () => {
    const { clients } = mockGraph({ "/v1.0/auditLogs/signIns": { status: 200 } });
    const seen: string[] = [];
    const report = await runCloudAccountCheck(
      microsoft("pem", { certificatePem: "pem-text" }),
      { sources: ["entra-signins"] },
      factoryOf({ microsoft: (_s, pem) => (seen.push(pem), clients) }),
    );
    expect(seen).toEqual(["pem-text"]);
    expect(report.results[0].status).toBe("succeeded");
  });

  it("runs the GCP check against the account's project", async () => {
    const { client, calls } = mockGcp(() => ({ entries: [{}] }));
    const report = await runCloudAccountCheck(
      gcp,
      { sources: ["audit-logs"] },
      factoryOf({ gcp: async () => client }),
    );
    expect(calls[0].data.resourceNames).toEqual(["projects/p1"]);
    expect(report.results[0].status).toBe("succeeded");
  });

  it("fails every source with a fixed reason when the account lacks its credential", async () => {
    const factory = () => createCheckClientFactory(createCloudTransport({}));
    const report = await runCloudAccountCheck(
      aws({}),
      { sources: ["cloudtrail-lookup", "s3-trail"] },
      factory,
    );
    expect(report.results.map((r) => r.detail)).toEqual([
      "the account has no stored access key",
      "the account has no stored access key",
    ]);
    const key = await runCloudAccountCheck(gcp, { sources: ["audit-logs"] }, factory);
    expect(key.results[0].detail).toBe("the account has no stored service-account key");
  });

  it("does not quote a broken key file", async () => {
    const leaked = "private-key-fragment-sentinel";
    const broken = {
      ...gcp,
      secrets: { serviceAccountKeyJson: `{"private_key": "${leaked}` },
    } as OpenCloudAccount;
    const report = await runCloudAccountCheck(broken, { sources: ["audit-logs"] }, () =>
      createCheckClientFactory(createCloudTransport({})),
    );
    expect(report.results[0].detail).toBe("the stored service-account key is not valid JSON");
    expect(JSON.stringify(report)).not.toContain(leaked);
  });

  it("reports bad cloud connection settings on every source", async () => {
    const report = await runCloudAccountCheck(aws(), { sources: ["cloudtrail-lookup"] }, () => {
      throw new CloudTransportError("Cloud proxy URL is not a valid URL — expected http://host:port");
    });
    expect(report.results[0]).toMatchObject({ status: "failed" });
    expect(report.results[0].detail).toContain("Cloud proxy URL is not a valid URL");
  });
});
