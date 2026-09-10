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
import { addressReach } from "./publicAddress.js";

/** The link-local addresses and names that serve instance metadata. */
export const METADATA_TARGETS: readonly string[] = [
  "169.254.169.254", // AWS, Azure, and most others
  "fd00:ec2::254", // AWS IPv6
  "169.254.170.2", // AWS ECS task role
  "metadata.google.internal",
  "metadata.goog",
  "fd20:ce::254", // GCP IPv6
  "100.100.100.200", // Alibaba Cloud
  "169.254.169.253", // Oracle Cloud
];

/** The marker this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const METADATA_MARKER = "[metadata credential access:";

/**
 * Has this pass already annotated this description?
 *
 * ANCHORED AT THE END, where the pass puts its marker. A plain `includes` trusted adversary-chosen
 * text: a request whose own query string carried the marker string suppressed grading entirely,
 * which is a one-parameter way to turn the detection off.
 */
export function alreadyMarked(description: string): boolean {
  return /\[metadata credential access:[\s\S]*\]\s*$/.test(description ?? "");
}

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
  // GCP short form, but only the paths that RETURN a token. `/service-accounts/default/?recursive`
  // returns the account's aliases, email and scopes — information, not a credential — and every SDK
  // asks for it.
  /\/v1\/instance\/service-accounts\/[^\s"'&?]*\/(?:token|identity)\b/i,
  /\/v2\/credentials\//i, // ECS task role
  // The ECS relative-URI form, which is how a task is TOLD where its credentials are.
  /\bAWS_CONTAINER_CREDENTIALS_(?:RELATIVE_URI|FULL_URI)\s*=/i,
];

/**
 * IMDSv2's token request. NOT credential access.
 *
 * `PUT /latest/api/token` is the first half of every well-behaved SDK call and of every hardened
 * instance's normal traffic. Grading it would fire on precisely the instances that are configured
 * correctly.
 */
const IMDS_TOKEN_RE = /\/latest\/api\/token\b/i;

/**
 * THE PROCESS NAME ALONE CANNOT ANSWER THIS ON LINUX, AND PRETENDING OTHERWISE WAS THE FIRST
 * VERSION'S WORST DEFECT.
 *
 * On a container the application IS the SDK. An ECS task's executable basename is `node`; an EKS
 * pod's is `java`; a boto3 worker's is `python3`. All three read the credential endpoint
 * continuously, correctly, and by design — reading `/v2/credentials/<uuid>` is the ONLY way an ECS
 * task gets credentials at all. Grading those High fired on every healthy workload in a container
 * estate, which is precisely the failure the design set out to avoid.
 *
 * So the tables below are split by what the name actually tells you:
 *
 *   • TOOL_RE — curl, wget, nc, socat, httpie. No SDK is one of these. A hit here IS the finding.
 *   • RUNTIME_RE — node, java, python, ruby, php, and the web servers. The name says nothing on its
 *     own; it is the application and the SDK at the same time. Medium, with the ambiguity stated,
 *     and High ONLY when the command line itself names the metadata URL — which means a person
 *     typed the request rather than a library making it.
 *   • SDK_RE — the standalone agents. Nothing at all.
 */
const TOOL_RE =
  /^(?:curl|wget|nc|ncat|netcat|socat|lynx|links|httpie|http|fetch|aria2c|powershell|pwsh)(?:\.exe)?$/i;

const RUNTIME_RE =
  /^(?:nginx|httpd|apache2?|caddy|lighttpd|php-fpm[\d.]*|php|w3wp|node|deno|bun|java|tomcat\d*|catalina|gunicorn|uwsgi|uvicorn|puma|unicorn|passenger|ruby|rails|python[\d.]*|perl|dotnet|go|bash|sh|zsh|busybox)(?:\.exe)?$/i;

/** Clients that are SUPPOSED to read the credential path. Their presence is not evidence of anything. */
const SDK_RE =
  /^(?:aws(?:-cli)?|aws_completer|amazon-ssm-agent|amazon-cloudwatch-agent|ssm-agent|cloud-init|google_guest_agent|google_metadata_script_runner|WindowsAzureGuestAgent|waagent|kubelet|ecs-agent|agent|fluent-?bit|fluentd|telegraf|datadog-agent|vector|otelcol[\w-]*|node_exporter|consul|nomad|vault)(?:\.exe)?$/i;

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
  /**
   * true when the event's OWN command line names the metadata address.
   *
   * This is the fact that separates "a library made this call" from "someone typed this request".
   * An SDK's HTTP call never appears on a command line; `curl http://169.254.169.254/...` does.
   */
  commandLineNamesTarget: boolean;
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
 * The text as written and, when it differs, its percent-decoded form — as SEPARATE strings.
 *
 * An SSRF payload arrives URL-encoded far more often than not: `http%3a%2f%2f169.254.169.254` is
 * the ordinary spelling once the address is a parameter value. Matching only the raw text missed
 * every encoded attempt, and the address-boundary check made it worse — the character before the
 * address was then `f`, from `%2f`, which reads as part of a longer word.
 *
 * The first version JOINED the two forms into one string, and that broke the SSRF rule outright:
 * a rule that counted `http://` occurrences saw every single URL twice, so ANY description holding
 * one URL and one percent sign was graded as a forgery attempt — including an SDK reading its own
 * role with a percent-encoded user agent. Two strings, tested separately, cannot do that.
 *
 * decodeURIComponent throws on a malformed sequence, and half an attacker's payload is malformed on
 * purpose, so a manual pass handles what it rejects. Decoding runs ONCE: repeating it until stable
 * would match a double-encoded literal the server would never have followed.
 */
export function textVariants(text: string): string[] {
  const t = text ?? "";
  if (!t.includes("%")) return [t];
  let decoded: string;
  try {
    decoded = decodeURIComponent(t);
  } catch {
    decoded = t.replace(/%([0-9a-f]{2})/gi, (m, hex: string) => {
      const code = parseInt(hex, 16);
      return code >= 0x20 && code < 0x7f ? String.fromCharCode(code) : m;
    });
  }
  return decoded === t ? [t] : [t, decoded];
}

// Compiled once. Building seven RegExp objects per call cost 1.4 seconds over 100,000 log lines,
// and metadataTarget is called twice per event.
const TARGET_RES: readonly { target: string; re: RegExp }[] = METADATA_TARGETS.map((target) => ({
  target,
  re: new RegExp(`(?:^|[^\\w.:-])${target.replace(/[.[\]]/g, "\\$&")}(?:[^\\w.-]|$)`, "i"),
}));

/** Which metadata target this text names, or "". */
export function metadataTarget(text: string): string {
  for (const variant of textVariants(text)) {
    // A trailing root dot makes a fully qualified name — `metadata.google.internal.` is the same
    // host — so it is removed here rather than carried as a second entry in the target list.
    const t = variant.toLowerCase().replace(/(\.[a-z]+)\.(?=[^\w.]|$)/g, "$1");
    // A bare address match would hit a longer address that merely starts the same way, and the
    // hostname forms need a boundary too — "notmetadata.google.internal" is a different host.
    for (const { target, re } of TARGET_RES) if (re.test(t)) return target;
  }
  return "";
}

/** Does this text ask for credentials rather than ordinary instance facts? */
export function isCredentialPath(text: string): boolean {
  return textVariants(text ?? "").some((t) => CREDENTIAL_PATH_RES.some((re) => re.test(t)));
}

/**
 * Is the metadata URL sitting INSIDE another request?
 *
 * That is what SSRF looks like in a web log: the application's own URL carries the metadata address
 * as a parameter value, or as a redirect target the server was told to follow.
 *
 * THE RULE IS "IT IS A PARAMETER VALUE", NOT "THERE ARE TWO URLS". Counting schemes was the first
 * version's test and it was wrong twice over. An ordinary Apache combined-log line carries the
 * request URL AND the referrer, so two schemes is the NORMAL shape of a web log; and the decoded
 * and raw forms were being concatenated, so one URL counted as two. Between them, any log line
 * mentioning a metadata address and containing a percent sign was graded a forgery attempt — which
 * is how an SDK reading its own role, with a percent-encoded user agent, became a High SSRF claim.
 *
 * What actually identifies a forgery is position: the metadata address appears where a VALUE goes.
 */
const SSRF_PARAM_RE =
  /[?&][\w.\-[\]]{1,64}=(?:https?(?::|%3a)(?:\/\/|%2f%2f))?(?:169\.254\.|100\.100\.100\.200|metadata\.goog)/i;

/** A metadata address anywhere after the query separator is in value position. */
const SSRF_QUERY_RE = /\?[^\s]*(?:169\.254\.\d{1,3}\.\d{1,3}|metadata\.google\.internal)/i;

/** Decimal, octal and hex spellings of 169.254.169.254 — an evasion attempt is itself the signal. */
const SSRF_OBFUSCATED_RE = /\b(?:2852039166|0250\.0376\.0250\.0376|0xa9fea9fe)\b/i;

export function looksLikeSsrf(text: string): boolean {
  return textVariants(text ?? "").some((t) => {
    // An obfuscated spelling of the metadata address stands ALONE. Requiring the literal address
    // as well meant the evasion regex could only ever fire when the attacker had also written the
    // address in plain form — which defeats the point of writing it in decimal.
    if (SSRF_OBFUSCATED_RE.test(t)) return true;
    if (!metadataTarget(t)) return false;
    return SSRF_PARAM_RE.test(t) || SSRF_QUERY_RE.test(t);
  });
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
    commandLineNamesTarget: !!metadataTarget(e.commandLine ?? ""),
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
        `A request carried the instance metadata address ${hit.target} in a parameter value, which is what a server-side request forgery looks like in a web log — the application was asked to fetch a URL and the URL points at the credential service. ` +
        (hit.credentialPath
          ? "The path requested is the credential path, so this is an attempt to read the instance role's access key, not the machine's name."
          : "The path requested is not the credential path, so this may be a probe rather than a successful theft — check whether a credential-path request followed."),
    };
  }

  // Everything below needs the credential path. Ordinary metadata reads are not findings.
  if (!hit.credentialPath) return null;

  // This is the endpoint's entire purpose. Saying nothing is the correct answer.
  if (SDK_RE.test(hit.process)) return null;

  if (TOOL_RE.test(hit.process)) {
    return {
      severity: "High",
      mitre: ["T1552.005"],
      reason: `${hit.process} requested the instance role's credentials from ${hit.target}. No SDK is a transfer tool — a library never runs curl — so a person or a script made this request, and the credentials it returns work from anywhere.`,
    };
  }

  if (RUNTIME_RE.test(hit.process)) {
    // The command line is what separates "a library made this call" from "someone typed it". An
    // SDK's HTTP request never appears on a command line; a hand-made one does.
    if (hit.commandLineNamesTarget) {
      return {
        severity: "High",
        mitre: ["T1552.005"],
        reason: `${hit.process} was invoked with a command line that names ${hit.target} and the credential path. An SDK's request to the metadata service never appears on a command line, so this request was written by hand rather than made by a library.`,
      };
    }
    return {
      severity: "Medium",
      mitre: ["T1552.005"],
      reason:
        `${hit.process} requested the instance role's credentials from ${hit.target}. ` +
        `On a container the application and the SDK are the same process — an ECS task's executable is "node", an EKS pod's is "java", a boto3 worker's is "python3" — and reading this endpoint is how those workloads get credentials at all. ` +
        `So "${hit.process}" does not separate ordinary SDK traffic from a request made through the application. What would: a command line that names the URL, an SSRF-shaped entry in the web access log for the same second, or the credentials appearing in use from an address this instance does not have.`,
    };
  }

  // NO PROCESS CONTEXT MEANS NO FINDING. The issue requires "credential-path AND process/request
  // context", and a credential-path read with neither is indistinguishable from the SDK traffic
  // every cloud instance produces continuously. Reporting it Medium put a finding on ordinary
  // traffic whenever telemetry lacked attribution, or whenever an application had a custom
  // executable name — which is most of them. The case-level gap is stated once by the coverage
  // event instead of once per request.
  return null;
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
    if (alreadyMarked(e.description ?? "")) return e;
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

/**
 * Does this identity look like an EC2 instance role rather than a person or a service?
 *
 * THE WHOLE ARN IS REQUIRED, not the `assumed-role/…/i-…` fragment. Descriptions in this codebase
 * are built from IMPORTED data, so a URL path, an S3 key or a filename an attacker chose lands in
 * them verbatim — and the fragment alone matched
 * `GET https://cdn.evil.test/assumed-role/x/i-0123456789abcdef/payload.bin`, planting a High
 * "the credentials were taken off the host" claim on an unrelated proxy log line. An `arn:aws:sts`
 * prefix with an account number is not something that appears by accident in a URL.
 */
export function isInstanceRoleIdentity(text: string): boolean {
  return /\barn:aws(?:-[a-z-]+)?:sts::\d{12}:assumed-role\/[^\s/"']+\/i-[0-9a-f]{8,}/i.test(text ?? "");
}

/** The source address an event recorded, from the canonical envelope or the flat field. */
function sourceAddress(e: ForensicEvent): string {
  return (e.canonical?.network?.source?.address ?? e.srcIp ?? "").trim();
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
 *
 * The address is read from the canonical envelope FIRST. awsImport puts the caller address there
 * and never sets the flat `srcIp`, so reading only `srcIp` meant this never fired on the one
 * CloudTrail importer the product has — while still firing on proxy and firewall evidence, whose
 * descriptions carry adversary-chosen URLs. It was dead where it mattered and live where it hurt.
 */
export function instanceCredentialUseAway(events: readonly ForensicEvent[]): ForensicEvent[] {
  let changed = false;
  const out = events.map((e) => {
    if (alreadyMarked(e.description ?? "")) return e;
    const text = `${e.description ?? ""} ${e.path ?? ""}`;
    if (!isInstanceRoleIdentity(text)) return e;
    const ip = sourceAddress(e);
    // No address at all is not a gap this pass can speak to — plenty of audit records simply have
    // none. An address that IS recorded but cannot be parsed is different, and is reported below.
    if (!ip) return e;
    const reach = addressReach(ip);
    if (reach === "private") return e;
    changed = true;
    const severity: Severity = RANK.High > RANK[e.severity] ? "High" : e.severity;
    const reason =
      reach === "public"
        ? `An API call was made with an EC2 instance role's credentials from ${ip}, an address outside the network. ` +
          "Instance-role credentials are meant to be used by the instance itself; a call from outside it means they were taken off the host. " +
          "One honest alternative exists: an instance behind a NAT gateway presents the gateway's public address, and the audit log records the address it saw. Confirm against the instance's egress address before acting on this."
        : `An API call was made with an EC2 instance role's credentials, and the source address the log recorded (${ip}) could not be read as an address. ` +
          "Whether the credentials were used from off the host therefore could not be determined here — this is not a finding that they were, and not evidence that they were not. Read the raw record's source address.";
    return {
      ...e,
      // An unreadable address is a gap, not a finding. It is attached so the analyst sees it, but
      // it does not raise the event.
      severity: reach === "public" ? severity : e.severity,
      mitreTechniques:
        reach === "public"
          ? [...new Set([...(e.mitreTechniques ?? []), "T1552.005", "T1078.004"])]
          : (e.mitreTechniques ?? []),
      description: `${(e.description ?? "").slice(0, DESCRIPTION_MAX)} ${METADATA_MARKER} ${reason}]`.trim(),
    };
  });
  return changed ? out : (events as ForensicEvent[]);
}

/**
 * What this pass could and could not see.
 *
 * The metadata service leaves no trace in any cloud audit log — the request never leaves the
 * instance. A case holding only cloud audit logs therefore gets no findings from the first half of
 * this pass, and that absence is not evidence.
 */
export function explainVisibility(hasHostTelemetry: boolean, hasCloudAudit: boolean): string {
  if (hasHostTelemetry) {
    return "Instance metadata requests are visible here because the case holds host telemetry. A request that no process event captured is still invisible.";
  }
  if (hasCloudAudit) {
    return "This case holds cloud audit logs but no host telemetry. The instance metadata service produces NO audit-log record — the request never leaves the instance — so no conclusion about metadata credential access can be drawn from these logs either way. Collect host process telemetry, web-server access logs, or VPC flow logs from the instance to answer the question.";
  }
  return "No evidence in this case can show whether the instance metadata service was queried.";
}

/** The id of the coverage event, so a re-merge replaces it instead of adding another. */
export const COVERAGE_EVENT_ID = "cloud-metadata-coverage";

const CLOUD_AUDIT_RE = /^(?:AWS|GCP|Azure|M365|Google Workspace|Okta)\b/;

/**
 * One event saying the question could not be answered, when that is the case.
 *
 * Without this, explainVisibility was an exported string builder no analyst ever saw — the exact
 * defect this issue's earlier items already shipped twice. A silent pass over a case with no host
 * telemetry reads as "nothing found", and "nothing found" is the wrong answer when nothing could
 * have been found.
 */
export function metadataCoverageEvent(events: readonly ForensicEvent[]): ForensicEvent | null {
  let hasCloudAudit = false;
  let hasHostTelemetry = false;
  for (const e of events) {
    if (e.id === COVERAGE_EVENT_ID) continue;
    if (e.processName) hasHostTelemetry = true;
    if (CLOUD_AUDIT_RE.test(e.description ?? "")) hasCloudAudit = true;
    if (hasHostTelemetry) return null; // the gap does not exist
  }
  if (!hasCloudAudit) return null;
  return {
    id: COVERAGE_EVENT_ID,
    timestamp:
      events.find((e) => Number.isFinite(Date.parse(e.timestamp ?? "")))?.timestamp ??
      new Date().toISOString(),
    description: `Cloud coverage gap ${METADATA_MARKER} ${explainVisibility(false, true)}]`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Coverage"],
  };
}
