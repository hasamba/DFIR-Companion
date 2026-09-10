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
  const hit = (over: Partial<NonNullable<ReturnType<typeof readHit>>> = {}) => ({
    id: "e1",
    target: "169.254.169.254",
    credentialPath: true,
    process: "",
    ssrfShaped: false,
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

  it("reports a web server reading the credential path", () => {
    for (const p of ["nginx", "php-fpm8.2", "java", "gunicorn", "w3wp.exe"]) {
      const v = gradeHit(hit({ process: p }), CRED);
      expect(v?.severity).toBe("High");
      expect(v?.mitre).toContain("T1552.005");
    }
  });

  it("reports a shell or transfer tool reading the credential path", () => {
    const v = gradeHit(hit({ process: "curl" }), CRED);
    expect(v?.severity).toBe("High");
    expect(v?.reason).toContain("used from anywhere");
  });

  it("reports an SSRF-shaped request whatever the path", () => {
    const v = gradeHit(hit({ ssrfShaped: true, credentialPath: false }), "x");
    expect(v?.severity).toBe("High");
    expect(v?.mitre).toContain("T1190");
    expect(v?.reason).toContain("may be a probe");
  });

  // Without the process there is nothing to separate this from the SDK traffic.
  it("says the process was not recorded rather than guessing", () => {
    const v = gradeHit(hit({ process: "" }), CRED);
    expect(v?.severity).toBe("Medium");
    expect(v?.reason).toContain("did not record which process");
  });

  it("reports an unknown process at Medium and names what to confirm", () => {
    const v = gradeHit(hit({ process: "backup-agent" }), CRED);
    expect(v?.severity).toBe("Medium");
    expect(v?.reason).toContain("confirm what backup-agent is");
  });
});

describe("explainMetadataAccess — the timeline pass", () => {
  it("raises and explains a web server reading the credential path", () => {
    const [out] = explainMetadataAccess([
      ev({
        description: `Process created: nginx requested ${CRED}`,
        processName: "/usr/sbin/nginx",
        severity: "Info",
      }),
    ]);
    expect(out.severity).toBe("High");
    expect(out.description).toContain("[metadata credential access:");
    expect(out.mitreTechniques).toContain("T1552.005");
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
      description: "CloudTrail: s3:ListBuckets by arn:aws:sts::1234:assumed-role/app-role/i-0abc123def456",
      srcIp: "203.0.113.9",
      ...over,
    });

  it("recognises an instance-role identity", () => {
    expect(isInstanceRoleIdentity("arn:aws:sts::1234:assumed-role/app-role/i-0abc123def456")).toBe(true);
    expect(isInstanceRoleIdentity("arn:aws:sts::1234:assumed-role/admin/alice")).toBe(false);
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
      call({ description: "CloudTrail: s3:ListBuckets by arn:aws:sts::1234:assumed-role/admin/alice" }),
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
