// Cloud instance-metadata credential access (#908 item 7).
//
// Every cloud instance has a link-local address that hands out the instance's own role
// credentials to anything that asks from inside the machine. No authentication. No network
// controls. That is the design, and it is also why a server-side request forgery in a web
// application is a full credential theft: the attacker makes the web server fetch a URL, points it
// at the metadata service, and reads the role's access key out of the response.
//
// ─────────────────────────── WHY THE ENDPOINT ALONE CANNOT BE THE FINDING ───────────────────────
//
// The issue says it plainly: "Ordinary instance metadata access is common." It is far worse than
// common. EVERY AWS SDK on the instance fetches those exact credentials, continuously, forever —
// that is how an instance role works at all. A rule that fires on the credential path produces a
// finding every few minutes on every healthy instance in the estate.
//
// So this needs a SECOND fact, and the issue names it: process or request context.
//
//   • a WEB-SERVER process asked for the credentials. nginx does not need the instance role. That
//     is SSRF, or something running inside the web server that should not be.
//   • the metadata URL appears INSIDE a request — in a query parameter, a header, a redirect
//     target. That is the SSRF attempt itself, visible in the web log.
//   • a SHELL or transfer tool asked. curl and python fetching the credential path is a person or
//     a script, not the SDK.
//
// Without one of those, the credential path is reported as Medium at most, and the note says why
// it could not be judged: the process was not recorded.
//
// ─────────────────────────── WHAT AUDIT LOGS CANNOT SHOW ───────────────────────────
//
// The metadata service does not appear in CloudTrail. There is no API call, no principal, no
// source IP — the request never leaves the instance. So when a case holds only cloud audit logs,
// this pass has nothing to grade, and the absence of findings means nothing at all. That is stated
// rather than left to be inferred: see explainVisibility.
//
// What audit logs CAN show is the other half — the credentials being used from somewhere the
// instance is not. That is a different finding and it is graded separately below.

import type { ForensicEvent, Severity } from "./stateTypes.js";

/** The link-local addresses and names that serve instance metadata. */
export const METADATA_TARGETS: readonly string[] = [
  "169.254.169.254", // AWS, Azure, and most others
  "fd00:ec2::254", // AWS IPv6
  "169.254.170.2", // AWS ECS task role
  "metadata.google.internal",
  "metadata.goog",
  "100.100.100.200", // Alibaba Cloud
  "169.254.169.253", // Oracle Cloud
];

/** The marker this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const METADATA_MARKER = "[metadata credential access:";

/**
 * The paths that return CREDENTIALS, as opposed to the harmless instance facts.
 *
 * The distinction carries the whole rule. `/latest/meta-data/instance-id` tells you the machine's
 * name; `/latest/meta-data/iam/security-credentials/<role>` returns an access key, a secret and a
 * session token. Only the second is worth a finding.
 */
const CREDENTIAL_PATH_RES: readonly RegExp[] = [
  /\/latest\/meta-data\/iam\/security-credentials/i, // AWS IMDS
  /\/computeMetadata\/v1\/instance\/service-accounts\/[^\s"'&?]*\/(?:token|identity)/i, // GCP
  /\/metadata\/identity\/oauth2\/token/i, // Azure managed identity
  /\/v1\/instance\/service-accounts/i, // GCP, short form
  /\/latest\/dynamic\/instance-identity\/document/i, // AWS identity document
  /\/v2\/credentials\//i, // ECS task role
];

/**
 * IMDSv2's token request. NOT credential access.
 *
 * `PUT /latest/api/token` is the first half of every well-behaved SDK call and of every hardened
 * instance's normal traffic. Grading it would fire on precisely the instances that are configured
 * correctly.
 */
const IMDS_TOKEN_RE = /\/latest\/api\/token\b/i;

/** Processes that serve web requests. None of them has a reason to read the instance role. */
const WEB_SERVER_RE =
  /^(?:nginx|httpd|apache2?|caddy|lighttpd|php-fpm[\d.]*|php|w3wp|node|java|tomcat\d*|catalina|gunicorn|uwsgi|uvicorn|puma|unicorn|passenger|ruby|rails)(?:\.exe)?$/i;

/** Shell and transfer tools. A person or a script, not an SDK. */
const TOOL_RE =
  /^(?:curl|wget|python[\d.]*|perl|ruby|nc|ncat|socat|powershell|pwsh|bash|sh|zsh|busybox|lynx|links|httpie|http)(?:\.exe)?$/i;

/** Clients that are SUPPOSED to read the credential path. Their presence is not evidence of anything. */
const SDK_RE =
  /^(?:aws(?:-cli)?|aws_completer|amazon-ssm-agent|amazon-cloudwatch-agent|cloud-init|google_guest_agent|google_metadata_script_runner|WindowsAzureGuestAgent|waagent|kubelet|ecs-agent|fluent-?bit|telegraf|datadog-agent|vector|otelcol[\w-]*)(?:\.exe)?$/i;

export interface MetadataHit {
  /** The event this came from. */
  id: string;
  /** Which link-local target the request named. */
  target: string;
  /** true when the request asked for credentials rather than ordinary instance facts. */
  credentialPath: boolean;
  /** The process that made the request, "" when the evidence did not record one. */
  process: string;
  /** true when the metadata URL sits INSIDE another request — the shape of an SSRF attempt. */
  ssrfShaped: boolean;
}

const baseName = (p: string): string => {
  const s = (p ?? "").replace(/["']/g, "").trim();
  const cut = s.slice(s.lastIndexOf("/") + 1);
  return cut.slice(cut.lastIndexOf("\\") + 1);
};

/** The text an event offers for URL matching: its description, command line and destination. */
function searchText(e: ForensicEvent): string {
  return [e.description ?? "", e.commandLine ?? "", e.path ?? "", e.dstIp ?? ""].join(" ");
}

/**
 * The text as written, plus its percent-decoded form.
 *
 * An SSRF payload arrives URL-encoded far more often than not — `http%3a%2f%2f169.254.169.254` is
 * the ordinary spelling once the address is a parameter VALUE. Matching only the raw text missed
 * every encoded attempt, and the boundary check made it worse: the character before the address was
 * then `f`, from `%2f`, which reads as "part of a longer word".
 *
 * decodeURIComponent throws on a malformed sequence, and half an attacker's payload is malformed on
 * purpose, so a manual pass handles what it rejects. Decoding runs ONCE: repeating it until stable
 * would turn a double-encoded literal into a match that the server would never have made.
 */
function expand(text: string): string {
  const t = text ?? "";
  if (!t.includes("%")) return t;
  let decoded: string;
  try {
    decoded = decodeURIComponent(t);
  } catch {
    decoded = t.replace(/%([0-9a-f]{2})/gi, (m, hex: string) => {
      const code = parseInt(hex, 16);
      return code >= 0x20 && code < 0x7f ? String.fromCharCode(code) : m;
    });
  }
  return `${t} ${decoded}`;
}

/** Which metadata target this text names, or "". */
export function metadataTarget(text: string): string {
  const t = expand(text ?? "").toLowerCase();
  for (const target of METADATA_TARGETS) {
    // A bare address match would hit a longer address that merely starts the same way, and the
    // hostname forms need a boundary too — "notmetadata.google.internal" is a different host.
    const escaped = target.replace(/[.[\]]/g, "\\$&");
    if (new RegExp(`(?:^|[^\\w.:-])${escaped}(?:[^\\w.-]|$)`, "i").test(t)) return target;
  }
  return "";
}

/** Does this text ask for credentials rather than ordinary instance facts? */
export function isCredentialPath(text: string): boolean {
  const t = expand(text ?? "");
  return CREDENTIAL_PATH_RES.some((re) => re.test(t));
}

/**
 * Is the metadata URL sitting INSIDE another request?
 *
 * That is what SSRF looks like in a web log: the application's own URL carries the metadata address
 * as a parameter value, or as a redirect target the server was told to follow. An outbound request
 * TO the metadata service looks nothing like this — it has no host of its own in front of it.
 */
export function looksLikeSsrf(text: string): boolean {
  const t = expand(text ?? "");
  if (!metadataTarget(t)) return false;
  // A parameter whose value is a metadata URL, encoded or not.
  if (/[?&][\w.\-[\]]+=(?:https?(?::|%3a)(?:\/\/|%2f%2f))?(?:169\.254\.|metadata\.goog)/i.test(t))
    return true;
  // Two schemes in one string: the request's own URL, then the metadata URL inside it.
  const schemes = t.match(/https?:\/\//gi) ?? [];
  if (schemes.length >= 2) return true;
  // A decimal, octal or hex spelling of 169.254.169.254 alongside the literal — an evasion attempt
  // is itself the signal, and it only counts when a metadata target was already named.
  return /\b(?:2852039166|0250\.0376\.0250\.0376|0xa9fea9fe)\b/i.test(t);
}

/** Read one event as a metadata request, or null when it is not one. */
export function readHit(e: ForensicEvent): MetadataHit | null {
  const text = searchText(e);
  const target = metadataTarget(text);
  if (!target) return null;
  return {
    id: e.id,
    target,
    credentialPath: isCredentialPath(text),
    process: baseName(e.processName ?? ""),
    ssrfShaped: looksLikeSsrf(e.description ?? ""),
  };
}

export interface MetadataVerdict {
  severity: Severity;
  mitre: string[];
  reason: string;
}

/**
 * Grade one metadata request.
 *
 * Returns null for everything that is ordinary, which on a healthy instance is almost all of it.
 */
export function gradeHit(hit: MetadataHit, rawText: string): MetadataVerdict | null {
  // The IMDSv2 token handshake, on its own, is the CORRECT way to talk to the service.
  if (!hit.credentialPath && IMDS_TOKEN_RE.test(rawText)) return null;

  if (hit.ssrfShaped) {
    return {
      severity: "High",
      mitre: ["T1552.005", "T1190"],
      reason:
        `A request carried the instance metadata address ${hit.target} inside it, which is what a server-side request forgery looks like in a web log — the application was asked to fetch a URL and the URL points at the credential service. ` +
        (hit.credentialPath
          ? "The path requested is the credential path, so this is an attempt to read the instance role's access key, not to read the machine's name."
          : "The path requested is not the credential path, so this may be a probe rather than a successful theft — check whether a credential-path request followed."),
    };
  }

  // Everything below needs the credential path. Ordinary metadata reads are not findings.
  if (!hit.credentialPath) return null;

  if (WEB_SERVER_RE.test(hit.process)) {
    return {
      severity: "High",
      mitre: ["T1552.005"],
      reason: `${hit.process} requested the instance role's credentials from ${hit.target}. A web server has no reason to read the instance role — this is the shape of a server-side request forgery, or of something running inside the web server that should not be.`,
    };
  }

  if (TOOL_RE.test(hit.process)) {
    return {
      severity: "High",
      mitre: ["T1552.005"],
      reason: `${hit.process} requested the instance role's credentials from ${hit.target}. The SDKs read this endpoint on their own; a shell or transfer tool reading it is a person or a script, and the credentials it returns can be used from anywhere.`,
    };
  }

  if (SDK_RE.test(hit.process)) {
    // This is the endpoint's entire purpose. Saying nothing is the correct answer.
    return null;
  }

  if (!hit.process) {
    return {
      severity: "Medium",
      mitre: ["T1552.005"],
      reason: `Something on this host requested the instance role's credentials from ${hit.target}. The evidence did not record which process made the request, so this cannot be separated from the SDK traffic every cloud instance produces continuously. Recover the process — an EDR process event or an auditd record for the same second — before treating it either way.`,
    };
  }

  return {
    severity: "Medium",
    mitre: ["T1552.005"],
    reason: `${hit.process} requested the instance role's credentials from ${hit.target}. That is not a client known to need them, but it is also not a web server or a shell tool — confirm what ${hit.process} is on this host.`,
  };
}

const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const DESCRIPTION_MAX = 700;

/**
 * Explain metadata credential access on the timeline.
 *
 * Only ever raises, and appends its marker once.
 */
export function explainMetadataAccess(events: readonly ForensicEvent[]): ForensicEvent[] {
  let changed = false;
  const out = events.map((e) => {
    if ((e.description ?? "").includes(METADATA_MARKER)) return e;
    const hit = readHit(e);
    if (!hit) return e;
    const verdict = gradeHit(hit, searchText(e));
    if (!verdict) return e;
    changed = true;
    const severity: Severity = RANK[verdict.severity] > RANK[e.severity] ? verdict.severity : e.severity;
    return {
      ...e,
      severity,
      mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), ...verdict.mitre])],
      description:
        `${(e.description ?? "").slice(0, DESCRIPTION_MAX)} ${METADATA_MARKER} ${verdict.reason}]`.trim(),
    };
  });
  return changed ? out : (events as ForensicEvent[]);
}

// ─────────────────────────── the other half: use from elsewhere ───────────────────────────

/** A public IPv4, i.e. not one an instance would present to its own control plane. */
function isPublicIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((ip ?? "").trim());
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
  return a <= 255 && b <= 255;
}

/** Does this identity look like an EC2 instance role rather than a person or a service? */
export function isInstanceRoleIdentity(text: string): boolean {
  return /\bassumed-role\/[^\s/"']+\/i-[0-9a-f]{8,}/i.test(text ?? "");
}

/**
 * Instance-role credentials used from an address the instance does not have.
 *
 * This is the half that DOES appear in cloud audit logs, and it is the stronger finding: the
 * metadata request only shows an attempt, while this shows the credentials working somewhere else.
 * The session name of an instance role carries the instance id, so a call made under that identity
 * from a public address means the credentials left the instance.
 *
 * A NAT gateway is the honest false positive here, and the note says so: an instance behind NAT
 * presents the gateway's public address on egress, and CloudTrail records the address it saw.
 */
export function instanceCredentialUseAway(events: readonly ForensicEvent[]): ForensicEvent[] {
  let changed = false;
  const out = events.map((e) => {
    if ((e.description ?? "").includes(METADATA_MARKER)) return e;
    const text = `${e.description ?? ""} ${e.path ?? ""}`;
    if (!isInstanceRoleIdentity(text)) return e;
    const ip = (e.srcIp ?? "").trim();
    if (!ip || !isPublicIp(ip)) return e;
    changed = true;
    const severity: Severity = RANK.High > RANK[e.severity] ? "High" : e.severity;
    const reason =
      `An API call was made with an EC2 instance role's credentials from ${ip}, a public address. ` +
      "Instance-role credentials are meant to be used by the instance itself; a call from outside it means the credentials were taken off the host. " +
      "One honest alternative exists: an instance behind a NAT gateway presents the gateway's public address, and the audit log records the address it saw. Confirm against the instance's egress address before acting on this.";
    return {
      ...e,
      severity,
      mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), "T1552.005", "T1078.004"])],
      description: `${(e.description ?? "").slice(0, DESCRIPTION_MAX)} ${METADATA_MARKER} ${reason}]`.trim(),
    };
  });
  return changed ? out : (events as ForensicEvent[]);
}

/**
 * What this pass could and could not see, for the import note.
 *
 * The metadata service leaves no trace in any cloud audit log — the request never leaves the
 * instance. A case holding only CloudTrail, Azure Activity or GCP audit logs therefore gets no
 * findings from the first half of this pass, and that absence is not evidence.
 */
export function explainVisibility(hasHostTelemetry: boolean, hasCloudAudit: boolean): string {
  if (hasHostTelemetry) {
    return "Instance metadata requests are visible here because the case holds host telemetry. A request that a process event did not capture is still invisible.";
  }
  if (hasCloudAudit) {
    return "This case holds cloud audit logs but no host telemetry. The instance metadata service produces NO audit-log record — the request never leaves the instance — so no conclusion about metadata credential access can be drawn from these logs either way. Collect host process telemetry, web-server access logs, or VPC flow logs from the instance to answer the question.";
  }
  return "No evidence in this case can show whether the instance metadata service was queried.";
}
