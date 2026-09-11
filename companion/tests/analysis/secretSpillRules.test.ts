import { describe, it, expect } from "vitest";
import { secretSpillSignal } from "../../src/analysis/secretSpillRules.js";

// Fixtures for the eleven surfaces exercised by the EvidenceForge `spillage-full-matrix-test`
// scenario. The values are synthetic ("EvidenceForgeFake") and cryptographically worthless, but
// they are SHAPE-accurate by design — which is exactly what secret scanners (GitHub push
// protection) match on. So every token is assembled at runtime and no full-length literal ever
// appears in source, the same convention syslogImport.test.ts already uses for its Slack token.
const FAKE = "EvidenceForgeFake";
const AWS_KEY = ["AKIA", "EVIDENCEFORGEFAK"].join(""); // AKIA + 16
const GH_PAT = ["ghp", "_", `${FAKE}0Yl4nQxsCkGvHzTbWpF`].join(""); // ghp_ + 36
const GH_FINE = [
  "github",
  "_pat_",
  "11ABCDEFGHIJKLMNOPQRST_",
  "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijkl9",
].join("");
const SLACK = ["xoxb", "32926872419", "2302548692720", `${FAKE}NgxR2jaCkfeCIUn3GZNVGjPU`].join("-");
const GCP_KEY = ["AIza", `Sy${FAKE}0kHqLmNpQrStUvWx`].join(""); // AIza + 35
const STRIPE = ["sk", "test", `${FAKE}0BGU06yXEsv2`].join("_"); // sk_test_ + 24
const JWT = [
  "eyJhbGciOiJIUzI1NiJ9",
  `PLrHlT5ZCqAkOKuZTbSs8l${FAKE}`,
  "q49IPRweqJIPujRX6DlFYJ2OcXnuAvXW",
].join(".");
// Split for the same reason: a spelled-out DSN with inline credentials is a shape TruffleHog's
// Postgres detector reports as an unverified secret, and CI runs with --results=verified,unknown.
const PG = ["post", "gres"].join("");

describe("secretSpillRules — credential material in event text", () => {
  it("flags an AWS IAM access key id", () => {
    const r = secretSpillSignal(`aws configure set aws_access_key_id ${AWS_KEY}`);
    expect(r?.families).toContain("aws_iam");
    expect(r?.mitre).toContain("T1552.001");
  });

  it("flags a classic GitHub PAT", () => {
    expect(
      secretSpillSignal(`git remote set-url origin https://${GH_PAT}@github.com/x/y.git`)?.families,
    ).toContain("github_pat");
  });

  it("flags a fine-grained GitHub PAT", () => {
    expect(secretSpillSignal(`curl -H 'Authorization: bearer ${GH_FINE}'`)?.families).toContain(
      "github_fine_pat",
    );
  });

  it("flags a Slack bot token", () => {
    expect(secretSpillSignal(`alertbot: posting to slack with token ${SLACK}`)?.families).toContain(
      "slack_token",
    );
  });

  it("flags a GCP API key", () => {
    expect(secretSpillSignal(`GET /v1/geocode?key=${GCP_KEY}`)?.families).toContain("gcp_api_key");
  });

  it("flags a Stripe secret key", () => {
    expect(
      secretSpillSignal(`GET /dashboard -> 200 (ref https://portal.example.com/login?token=${STRIPE})`)
        ?.families,
    ).toContain("stripe_key");
  });

  it("flags a JWT", () => {
    expect(secretSpillSignal(`(ref https://app.example.com/dashboard?jwt=${JWT})`)?.families).toContain(
      "jwt",
    );
  });

  it("flags a database URI carrying inline credentials", () => {
    expect(
      secretSpillSignal(`${PG}://reportsvc:${FAKE}R2p@db-01.example.com:5432/reports`)?.families,
    ).toContain("db_uri");
  });

  it("flags a bearer/API token assigned on a command line", () => {
    expect(secretSpillSignal(`cmd.exe /c set API_TOKEN=${FAKE}P6QAohyaDZgPGfOTsNYGKTmq`)?.families).toContain(
      "password_generic",
    );
  });

  it("flags a generic shared secret logged in plaintext", () => {
    expect(
      secretSpillSignal(`app: loaded shared secret ${FAKE}-wPndDbHjZm! from /etc/users/secret.conf`)
        ?.families,
    ).toContain("password_generic");
  });

  it("is surface-agnostic — the same secret grades identically from any importer's text", () => {
    for (const text of [
      `aws s3 ls --profile x  # ${AWS_KEY}`, // shell history
      `syslog app: deploy used ${AWS_KEY}`, // syslog
      `GET /api?key=${AWS_KEY} -> 200`, // web access log
      `Process created: python deploy.py --key ${AWS_KEY}`, // ECAR / Linux EDR
      `Sysmon Process create (EID 1) - CommandLine=set K=${AWS_KEY}`, // Windows Sysmon
    ]) {
      expect(secretSpillSignal(text)?.families, text).toContain("aws_iam");
    }
  });

  it("reports every distinct family present in one line", () => {
    const r = secretSpillSignal(`export AWS=${AWS_KEY} GH=${GH_PAT}`);
    expect(r?.families).toEqual(expect.arrayContaining(["aws_iam", "github_pat"]));
  });
});

// Signal-to-noise discipline, mirroring tradecraftRules' "ordinary administration" tests: a rule
// that fires on routine log chatter manufactures Mediums and buries the real spill.
describe("secretSpillRules — does not fire on ordinary text", () => {
  it("ignores routine authentication and administration logging", () => {
    for (const text of [
      "sshd[2311]: Failed password for invalid user admin from 10.0.0.5 port 55234 ssh2",
      "pam_unix(sudo:auth): authentication failure; logname=jordan uid=1000",
      "app: password authentication succeeded for reportsvc",
      "systemd: Starting Secret Service daemon...",
      "app: secret not found, falling back to instance metadata",
      "user changed their password successfully",
      "GET /login?next=/dashboard -> 302",
      "Process created: /usr/bin/apt-get install -y nginx",
      "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
    ]) {
      expect(secretSpillSignal(text), text).toBeNull();
    }
  });

  it("ignores values that are already masked or redacted", () => {
    for (const text of [
      "app: loaded shared secret **** from /etc/users/secret.conf",
      "cmd.exe /c set API_TOKEN=[REDACTED]",
      "GET /api?key=<REDACTED> -> 200",
      `${PG}://reportsvc:***@db-01.example.com:5432/reports`,
      "aws_access_key_id AKIA****************",
    ]) {
      expect(secretSpillSignal(text), text).toBeNull();
    }
  });

  it("ignores near-miss tokens that are too short to be real key material", () => {
    for (const text of [
      "AKIASHORT",
      "ghp_abc",
      "xoxb-1",
      `${PG}://db-01.example.com:5432/reports`, // no inline credentials
      "eyJhbGciOiJIUzI1NiJ9", // a bare JWT header, not a full token
    ]) {
      expect(secretSpillSignal(text), text).toBeNull();
    }
  });

  it("returns null for empty input", () => {
    expect(secretSpillSignal("")).toBeNull();
    expect(secretSpillSignal("   ")).toBeNull();
  });
});

// A masked value elsewhere on the line used to silence EVERY rule for that line: the old check ran
// MASKED over the whole text once, before any rule, so `note=REDACTED` beside a real JWT, or a
// vendor's own masked example beside a real key, hid the spill. Masking is judged per occurrence
// now, and the scan runs on until a real occurrence is found or the line is exhausted — a cap of N
// occurrences would just mean N decoys before the real key.
describe("secretSpillRules — a masked value never hides a real one on the same line", () => {
  const AWS_DECOY = ["AKIA", "X".repeat(16)].join(""); // matches the AWS shape, reads as masked
  const GENERIC_REAL = `${FAKE}0Yl4nQxsCkGv!`;

  it("flags a real JWT beside a redaction note", () => {
    const r = secretSpillSignal(`note=REDACTED user=svc token=${JWT}`);
    expect(r?.families).toEqual(["jwt"]);
  });

  it("flags the real generic secret after a masked one", () => {
    const r = secretSpillSignal(`API_TOKEN=xxxxxxxxxxxxxxxx API_TOKEN=${GENERIC_REAL}`);
    expect(r?.families).toEqual(["password_generic"]);
  });

  it("flags a real vendor key after any number of masked-shaped decoys", () => {
    const decoys = Array.from({ length: 40 }, () => AWS_DECOY).join(" ");
    expect(secretSpillSignal(`${decoys} ${AWS_KEY}`)?.families).toEqual(["aws_iam"]);
    // and the decoys alone are still not a spill
    expect(secretSpillSignal(decoys)).toBeNull();
  });

  it("finds the real value after a masked one even when the two sit in one query string", () => {
    // The generic value class runs over `&` and `=`, so both assignments are one match whose
    // masked head must not hide the real tail.
    const r = secretSpillSignal(`GET /cb?API_TOKEN=xxxxxxxxxxxxxxxx&API_TOKEN=${GENERIC_REAL} HTTP/1.1`);
    expect(r?.families).toEqual(["password_generic"]);
  });

  it("judges a database URI on its password, not its username", () => {
    expect(
      secretSpillSignal(`${PG}://REDACTED-user:ActualPass9!@db-01.example.com:5432/reports`)?.families,
    ).toEqual(["db_uri"]);
    expect(secretSpillSignal(`${PG}://reportsvc:********@db-01.example.com:5432/reports`)).toBeNull();
  });

  it("does not carry scan position from one call into the next", () => {
    // A shared global regex would keep `lastIndex` past the first line's key and skip the start of
    // the second line, where its key sits.
    expect(secretSpillSignal(`${"pad ".repeat(20)}${AWS_KEY}`)?.families).toEqual(["aws_iam"]);
    expect(secretSpillSignal(`${AWS_KEY} trailing`)?.families).toEqual(["aws_iam"]);
  });
});
