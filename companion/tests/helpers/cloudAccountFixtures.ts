import { execFileSync } from "node:child_process";
import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCertificatePem } from "../../src/http/x509Builder.js";
import type { CloudAccountInput } from "../../src/integrations/cloudAccounts/types.js";

// Credentials for cloud vault tests, all made at runtime: none is a real key, and each run's values
// differ, so a sentinel found in a response can only have come from the vault under test.

const DAY = 86_400_000;

/** A self-signed certificate and its private key, one PEM text. */
export function makeCertPem(): { pem: string; keyLines: string[] } {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pub = createPublicKey(privateKey);
  const now = new Date();
  const cert = buildCertificatePem({
    subjectCommonName: "cloud-vault-test",
    issuerCommonName: "cloud-vault-test",
    publicKey: pub,
    signingKey: privateKey,
    issuerPublicKey: pub,
    notBefore: now,
    notAfter: new Date(now.getTime() + DAY),
    isCa: false,
  });
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const keyLines = keyPem.split("\n").filter((l) => l && !l.startsWith("-----"));
  return { pem: `${cert.trim()}\n${keyPem}`, keyLines };
}

/** A PFX of `pem` made with the openssl CLI, or undefined when openssl is not installed. */
export function makePfxBase64(pem: string, password: string): string | undefined {
  const dir = mkdtempSync(join(tmpdir(), "cloud-pfx-"));
  try {
    writeFileSync(join(dir, "in.pem"), pem);
    execFileSync(
      "openssl",
      [
        "pkcs12",
        "-export",
        "-in",
        join(dir, "in.pem"),
        "-out",
        join(dir, "out.pfx"),
        "-passout",
        `pass:${password}`,
      ],
      { stdio: "ignore" },
    );
    return readFileSync(join(dir, "out.pfx")).toString("base64");
  } catch {
    return undefined;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A service-account key JSON shaped like Google's, with a freshly generated private key. */
export function makeGcpKeyJson(email = "collector@test-project-01.iam.gserviceaccount.com"): string {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return JSON.stringify({
    type: "service_account",
    project_id: "test-project-01",
    private_key_id: randomBytes(20).toString("hex"),
    private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    client_email: email,
  });
}

/** A random string of the shape AWS uses for a secret access key. */
export const fakeAwsSecret = (): string => randomBytes(30).toString("base64").slice(0, 40);
export const fakeAccessKeyId = (): string => `AKIATEST${randomBytes(6).toString("hex").toUpperCase()}`;

export function awsKeyInput(
  name: string,
  secretAccessKey: string,
  accessKeyId = fakeAccessKeyId(),
): CloudAccountInput {
  return {
    name,
    provider: "aws",
    settings: { authMode: "access-key", region: "eu-west-1" },
    secrets: { accessKeyId, secretAccessKey },
  };
}

export function awsRoleInput(name: string, secretAccessKey: string, externalId: string): CloudAccountInput {
  return {
    name,
    provider: "aws",
    settings: {
      authMode: "assume-role",
      roleArn: "arn:aws:iam::123456789012:role/dfir-collector",
      baseCredential: "access-key",
      sessionSeconds: 3600,
    },
    secrets: { externalId, accessKeyId: fakeAccessKeyId(), secretAccessKey },
  };
}

export function gcpKeyInput(name: string, keyJson: string): CloudAccountInput {
  return {
    name,
    provider: "gcp",
    settings: { projectId: "test-project-01", authMode: "service-account-key" },
    secrets: { serviceAccountKeyJson: keyJson },
  };
}

export function microsoftPemInput(name: string, pem: string): CloudAccountInput {
  return {
    name,
    provider: "microsoft",
    settings: {
      tenantId: "00000000-0000-4000-8000-000000000001",
      clientId: "00000000-0000-4000-8000-000000000002",
      certificateFormat: "pem",
    },
    secrets: { certificatePem: pem },
  };
}
