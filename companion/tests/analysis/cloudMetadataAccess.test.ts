import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  metadataTarget,
  isCredentialPath,
  looksLikeSsrf,
  readHit,
  gradeHit,
  explainMetadataAccess,
  instanceCredentialUseAway,
  isInstanceRoleIdentity,
  explainVisibility,
  METADATA_TARGETS,
} from "../../src/analysis/cloudMetadataAccess.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const ev = (over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: `e${++seq}`,
  timestamp: "2026-01-01T10:00:00Z",
  description: "",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "web-01",
  ...over,
});

const CRED = "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role";

describe("what counts as a metadata request", () => {
  it("recognises each provider's endpoint", () => {
    for (const t of METADATA_TARGETS) expect(metadataTarget(`GET http://${t}/x`)).toBe(t);
  });

  it("does not match a longer address that merely starts the same way", () => {
    expect(metadataTarget("connected to 169.254.169.2540")).toBe("");
    expect(metadataTarget("resolved notmetadata.google.internal")).toBe("");
  });

  it("separates the credential paths from ordinary instance facts", () => {
    expect(isCredentialPath("/latest/meta-data/iam/security-credentials/app-role")).toBe(true);
    expect(isCredentialPath("/computeMetadata/v1/instance/service-accounts/default/token")).toBe(true);
    expect(isCredentialPath("/metadata/identity/oauth2/token?api-version=2018-02-01")).toBe(true);
    expect(isCredentialPath("/latest/meta-data/instance-id")).toBe(false);
    expect(isCredentialPath("/latest/meta-data/placement/availability-zone")).toBe(false);
  });
});

describe("the SSRF shape", () => {
  it("sees a metadata URL inside a query parameter", () => {
    expect(looksLikeSsrf("GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/ HTTP/1.1")).toBe(true);
    expect(looksLikeSsrf("GET /img?src=http%3a%2f%2f169.254.169.254/latest/ HTTP/1.1")).toBe(true);
  });

  it("sees two URLs in one request", () => {
    expect(looksLikeSsrf("https://app.test/proxy?to=https://169.254.169.254/latest/")).toBe(true);
  });

  it("sees an obfuscated spelling alongside the literal", () => {
    expect(looksLikeSsrf("GET /f?u=http://2852039166/latest/ and 169.254.169.254")).toBe(true);
  });

  it("does not call an outbound request to the service an SSRF", () => {
    expect(looksLikeSsrf(`curl ${CRED}`)).toBe(false);
  });

  it("says nothing when no metadata target is named at all", () => {
    expect(looksLikeSsrf("GET /fetch?url=http://example.test/a")).toBe(false);
  });
});

describe("gradeHit — the endpoint alone is never the finding", () => {
  const hit = (
    over: Partial<NonNullable<ReturnType<typeof readHit>>> = {},
  ): NonNullable<ReturnType<typeof readHit>> => ({
    id: "e1",
    target: "169.254.169.254",
    credentialPath: true,
    process: "",
    ssrfShaped: false,
    commandLineNamesTarget: false,
    ...over,
  });

  // This is how an instance role works. It happens continuously on every healthy instance.
  it("says nothing about an SDK reading the credential path", () => {
    for (const p of ["aws", "amazon-ssm-agent", "cloud-init", "kubelet", "google_guest_agent"]) {
      expect(gradeHit(hit({ process: p }), CRED)).toBeNull();
    }
  });

  it("says nothing about ordinary instance facts", () => {
    expect(
      gradeHit(
        hit({ credentialPath: false, process: "curl" }),
        "curl http://169.254.169.254/latest/meta-data/instance-id",
      ),
    ).toBeNull();
  });

  // PUT /latest/api/token is the FIRST half of every correct IMDSv2 call.
  it("says nothing about the IMDSv2 token handshake", () => {
    expect(
      gradeHit(
        hit({ credentialPath: false, process: "curl" }),
        "curl -X PUT http://169.254.169.254/latest/api/token",
      ),
    ).toBeNull();
  });

  // ON A CONTAINER THE APPLICATION IS THE SDK. An ECS task's executable is "node", an EKS pod's is
  // "java", a boto3 worker's is "python3", and reading this endpoint is how all three get
  // credentials at all. Grading those High fired on every healthy workload in a container estate.
  it("reports a language runtime or web server at Medium, and says why the name cannot decide", () => {
    for (const p of ["nginx", "php-fpm8.2", "java", "node", "python3.11", "gunicorn", "ruby", "w3wp.exe"]) {
      const v = gradeHit(hit({ process: p }), CRED);
      expect(v?.severity, p).toBe("Medium");
      expect(v?.reason).toContain("the application and the SDK are the same process");
      expect(v?.reason).toContain("What would");
    }
  });

  // An SDK's HTTP call never appears on a command line. A hand-written request does.
  it("raises a runtime to High when the command line itself names the URL", () => {
    const v = gradeHit(hit({ process: "node", commandLineNamesTarget: true }), CRED);
    expect(v?.severity).toBe("High");
    expect(v?.reason).toContain("written by hand rather than made by a library");
  });

  it("reports a transfer tool reading the credential path", () => {
    for (const p of ["curl", "wget", "socat", "ncat"]) {
      const v = gradeHit(hit({ process: p }), CRED);
      expect(v?.severity, p).toBe("High");
    }
    expect(gradeHit(hit({ process: "curl" }), CRED)?.reason).toContain("a library never runs curl");
  });

  it("reports an SSRF-shaped request whatever the path", () => {
    const v = gradeHit(hit({ ssrfShaped: true, credentialPath: false }), "x");
    expect(v?.severity).toBe("High");
    expect(v?.mitre).toContain("T1190");
    expect(v?.reason).toContain("may be a probe");
  });

  // The issue requires credential path AND context. With no process there is no context, and a
  // credential-path read is indistinguishable from the SDK traffic every instance produces — so
  // reporting it Medium put a finding on ordinary traffic whenever telemetry lacked attribution.
  it("says nothing when the evidence recorded no process", () => {
    expect(gradeHit(hit({ process: "" }), CRED)).toBeNull();
  });

  // Most applications have a custom executable name. That is not a signal either.
  it("says nothing about an application with a name it does not recognise", () => {
    expect(gradeHit(hit({ process: "order-service" }), CRED)).toBeNull();
    expect(gradeHit(hit({ process: "acme-worker" }), CRED)).toBeNull();
  });

  // Metadata, not a credential — and every SDK asks for the service-account information path.
  it("does not treat instance information as a credential", () => {
    expect(isCredentialPath("/latest/dynamic/instance-identity/document")).toBe(false);
    expect(isCredentialPath("/computeMetadata/v1/instance/service-accounts/default/?recursive=true")).toBe(
      false,
    );
    expect(isCredentialPath("/computeMetadata/v1/instance/service-accounts/default/token")).toBe(true);
  });

  // An evasion is the signal. Requiring the literal address as well defeated the point.
  it("sees an obfuscated address on its own", () => {
    expect(looksLikeSsrf("GET /fetch?url=http://2852039166/latest/meta-data/iam/")).toBe(true);
    expect(looksLikeSsrf("GET /fetch?url=http://0xa9fea9fe/latest/")).toBe(true);
  });

  it("recognises the ECS relative-URI and GCP IPv6 forms", () => {
    expect(isCredentialPath("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/abc")).toBe(true);
    expect(metadataTarget("http://[fd20:ce::254]/computeMetadata/v1/")).toBe("fd20:ce::254");
    expect(metadataTarget("http://metadata.google.internal./computeMetadata/v1/")).toBeTruthy();
  });

  // A plain `includes` trusted adversary-chosen text: a query parameter carrying the marker
  // string turned the detection off.
  it("cannot be silenced by putting the marker in the request text", () => {
    const [out] = explainMetadataAccess([
      ev({
        description: `GET /proxy?note=[metadata credential access:&url=${CRED}`,
        processName: "/usr/bin/curl",
      }),
    ]);
    expect(out.severity).toBe("High");
  });
});

describe("explainMetadataAccess — the timeline pass", () => {
  it("explains a web server reading the credential path, at Medium", () => {
    const [out] = explainMetadataAccess([
      ev({
        description: `Process created: nginx requested ${CRED}`,
        processName: "/usr/sbin/nginx",
        severity: "Info",
      }),
    ]);
    expect(out.severity).toBe("Medium");
    expect(out.description).toContain("[metadata credential access:");
    expect(out.mitreTechniques).toContain("T1552.005");
  });

  // A percent-encoded user agent is the ORDINARY spelling. Joining the raw and decoded text into
  // one string made every URL count twice, so one URL plus one percent sign read as a forgery —
  // and the SSRF branch runs before the SDK allow-list, so nothing downstream could save it.
  it("does not call an SDK reading its own role an SSRF because the line contains a percent sign", () => {
    const events = [
      ev({
        description: `GET ${CRED} UA=aws-sdk-go%2F1.44`,
        processName: "/usr/bin/amazon-ssm-agent",
      }),
    ];
    expect(explainMetadataAccess(events)).toBe(events);
  });

  it("does not call an ordinary web log line an SSRF for carrying a referrer", () => {
    const events = [
      ev({
        description:
          '10.0.0.1 - - [01/Jan/2026:10:00:00] "GET /a HTTP/1.1" 200 12 "http://app.test/b" "Mozilla/5.0" 169.254.169.254',
      }),
    ];
    expect(explainMetadataAccess(events)).toBe(events);
  });

  it("leaves ordinary SDK traffic alone", () => {
    const events = [ev({ description: `GET ${CRED}`, processName: "/usr/bin/aws" })];
    expect(explainMetadataAccess(events)).toBe(events);
  });

  it("returns the input untouched when nothing matches", () => {
    const events = [ev({ description: "Process created: bash" })];
    expect(explainMetadataAccess(events)).toBe(events);
  });

  it("is idempotent", () => {
    const once = explainMetadataAccess([ev({ description: `nginx ${CRED}`, processName: "nginx" })]);
    expect(explainMetadataAccess(once)[0].description).toBe(once[0].description);
  });

  it("never lowers a severity the event already had", () => {
    const [out] = explainMetadataAccess([
      ev({ description: `nginx ${CRED}`, processName: "nginx", severity: "Critical" }),
    ]);
    expect(out.severity).toBe("Critical");
  });

  it("reads the request out of a web access log line with no process at all", () => {
    const [out] = explainMetadataAccess([
      ev({ description: "GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/ HTTP/1.1 200" }),
    ]);
    expect(out.severity).toBe("High");
    expect(out.description).toContain("server-side request forgery");
  });
});

describe("instance credentials used from somewhere the instance is not", () => {
  const call = (over: Partial<ForensicEvent> = {}) =>
    ev({
      description:
        "CloudTrail: s3:ListBuckets by arn:aws:sts::123456789012:assumed-role/app-role/i-0abc123def456789",
      srcIp: "203.0.113.9",
      ...over,
    });

  it("recognises an instance-role identity", () => {
    expect(isInstanceRoleIdentity("arn:aws:sts::123456789012:assumed-role/app-role/i-0abc123def456789")).toBe(
      true,
    );
    expect(isInstanceRoleIdentity("arn:aws:sts::123456789012:assumed-role/admin/alice")).toBe(false);
  });

  // Descriptions are built from IMPORTED data. The bare assumed-role/…/i-… fragment matched a URL
  // path, an S3 key and a filename, planting a High credential-theft claim on unrelated evidence.
  it("cannot be planted by an attacker-chosen path", () => {
    for (const text of [
      "Squid: GET https://cdn.evil.test/assumed-role/x/i-0123456789abcdef/payload.bin",
      "/var/tmp/assumed-role/loader/i-deadbeefcafe0001",
      "SharePoint FileDownloaded: notes-on-assumed-role/policy/i-0000000000000000.docx",
    ]) {
      expect(isInstanceRoleIdentity(text), text).toBe(false);
    }
  });

  // awsImport puts the caller address in the canonical envelope and never sets the flat field, so
  // reading only srcIp meant this never fired on the one CloudTrail importer the product has.
  it("reads the source address out of the canonical envelope", () => {
    const e = {
      ...call({ srcIp: undefined }),
      canonical: { network: { source: { address: "203.0.113.9" } } },
    } as unknown as ForensicEvent;
    expect(instanceCredentialUseAway([e])[0].severity).toBe("High");
  });

  // An address the code cannot read is a gap, not a finding either way.
  it("says an unreadable address could not be read, and does not raise on it", () => {
    const [out] = instanceCredentialUseAway([call({ srcIp: "not-an-address" })]);
    expect(out.severity).toBe("Info");
    expect(out.description).toContain("could not be read as an address");
    expect(out.description).toContain("not evidence that they were not");
  });

  it("treats an IPv6 source as public rather than silently as internal", () => {
    expect(instanceCredentialUseAway([call({ srcIp: "2001:db8::1" })])[0].severity).toBe("High");
    const local = instanceCredentialUseAway([call({ srcIp: "fe80::1" })]);
    expect(local[0].severity).toBe("Info");
  });

  it("raises a call made from a public address", () => {
    const [out] = instanceCredentialUseAway([call()]);
    expect(out.severity).toBe("High");
    expect(out.mitreTechniques).toContain("T1078.004");
    expect(out.description).toContain("203.0.113.9");
  });

  // A NAT gateway is the honest alternative, and the note has to say so.
  it("names the NAT gateway alternative", () => {
    expect(instanceCredentialUseAway([call()])[0].description).toContain("NAT gateway");
  });

  it("says nothing about a call from a private address", () => {
    for (const ip of ["10.0.1.5", "172.16.0.4", "192.168.1.10", "127.0.0.1", "100.64.0.1"]) {
      const events = [call({ srcIp: ip })];
      expect(instanceCredentialUseAway(events)).toBe(events);
    }
  });

  it("says nothing about a human role used from anywhere", () => {
    const events = [
      call({
        description: "CloudTrail: s3:ListBuckets by arn:aws:sts::123456789012:assumed-role/admin/alice",
      }),
    ];
    expect(instanceCredentialUseAway(events)).toBe(events);
  });

  it("says nothing when the audit log recorded no source address", () => {
    const events = [call({ srcIp: undefined })];
    expect(instanceCredentialUseAway(events)).toBe(events);
  });
});

// The absence of findings from audit logs alone means nothing, and has to say so.
describe("explainVisibility", () => {
  it("states that the metadata service produces no audit-log record", () => {
    const note = explainVisibility(false, true);
    expect(note).toContain("NO audit-log record");
    expect(note).toContain("either way");
  });

  it("states what host telemetry does and does not cover", () => {
    expect(explainVisibility(true, true)).toContain("still invisible");
  });

  it("states plainly when nothing can answer the question", () => {
    expect(explainVisibility(false, false)).toContain("No evidence in this case");
  });
});

describe("reachability", () => {
  it("runs from the merge", () => {
    const merge = readFileSync(join(process.cwd(), "src/analysis/stateMerge.ts"), "utf8");
    expect(merge).toContain("explainMetadataAccess");
    expect(merge).toContain("instanceCredentialUseAway");
  });

  it("has its marker stripped before correlation keys a duplicate", () => {
    const corr = readFileSync(join(process.cwd(), "src/analysis/correlate.ts"), "utf8");
    expect(corr).toContain("metadata credential access");
  });
});
