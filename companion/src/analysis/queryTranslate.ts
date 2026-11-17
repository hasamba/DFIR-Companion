import { z } from "zod";
import type { InvestigationState } from "./stateTypes.js";
import { HUNT_PLATFORMS, normalizeHuntPlatform, type HuntPlatform } from "./huntPlatforms.js";

// Natural-language → hunting-query translator (issue #100). The analyst types intent in plain
// English — "PowerShell downloading a file and then executing it", "outbound RDP from this host" —
// and the AI translates it into a runnable query for each requested platform (Velociraptor VQL,
// Defender/Sentinel KQL, Elastic ES|QL, Splunk SPL, Sigma, YARA, Suricata, CrowdStrike CQL, and since
// #2667 Carbon Black Cloud, Wazuh, SentinelOne, Cortex XDR and QRadar), grounded in that
// platform's REAL schema. This is the inverse of the entity-driven 🔍 pivot generator in the
// dashboard (which builds deterministic templates FROM a specific IOC/event); here the input is
// free-text intent and the mapping requires a model.
//
// The AI call lives in the pipeline (`translateQuery`); this module holds the PURE, unit-tested
// pieces: the response schema (lenient `.catch` like huntSuggest.ts so a slightly-off reply still
// parses), the per-platform schema reference that grounds the model, and the sanitizer that drops
// useless entries, normalizes the platform key, and clamps field lengths.
//
// Results are EPHEMERAL (generated on demand, shown for review) — like ask()/suggestHunts() they do
// NOT mutate InvestigationState. The Velociraptor card can be deployed through the existing
// launchHunt flow (POST /velociraptor/hunt), so the analyst always reviews the query first.

// One translated query, as the model returns it. Every field is lenient so one off value never
// rejects the whole reply. `platform` is a free string here (normalized in the sanitizer against the
// alias table) so a reply of "vql" / "Velociraptor VQL" still maps to the canonical key.
export const queryTranslationSchema = z.object({
  platform: z.string().catch(""),
  label: z.string().catch(""), // short human label for the card, e.g. "PowerShell download-and-execute"
  query: z.string().catch(""), // the translated query ("" when notApplicable)
  explanation: z.string().catch(""), // how it captures the request + what a hit looks like
  caveats: z.string().catch(""), // assumptions / field-mapping notes / what to verify (optional)
  notApplicable: z.boolean().catch(false), // true when the platform genuinely can't express the request
});

export type RawQueryTranslation = z.infer<typeof queryTranslationSchema>;

// The model returns { interpretation, queries: [...] }. `.catch` at every level keeps a partial
// reply usable.
export const queryTranslationResponseSchema = z.object({
  interpretation: z.string().catch(""), // one sentence: how the model read the request (lets the analyst confirm intent)
  queries: z.array(queryTranslationSchema).catch([]),
});

export type QueryTranslationResponse = z.infer<typeof queryTranslationResponseSchema>;

// A sanitized translation, ready for the dashboard. `platform` is the canonical HuntPlatform key.
export interface QueryTranslation {
  platform: HuntPlatform;
  label: string;
  query: string;
  explanation: string;
  caveats: string;
  notApplicable: boolean;
}

export interface QueryTranslationResult {
  interpretation: string;
  queries: QueryTranslation[];
}

const MAX_QUERY_LEN = 4000; // a runaway query is a sign of a confused model; keep it pasteable
const MAX_LABEL_LEN = 200;
const MAX_EXPLANATION_LEN = 1200;
const MAX_CAVEATS_LEN = 800;
const MAX_INTERPRETATION_LEN = 600;

// Human labels per platform (card titles; also the fallback when the model omits `label`).
export const PLATFORM_LABELS: Readonly<Record<HuntPlatform, string>> = {
  velociraptor: "Velociraptor (VQL)",
  defender: "Microsoft Defender / Sentinel (KQL)",
  elastic: "Elastic / Kibana (ES|QL)",
  splunk: "Splunk (SPL)",
  sigma: "Sigma rule (YAML)",
  yara: "YARA rule",
  suricata: "Suricata rules (network)",
  crowdstrike: "CrowdStrike Falcon LogScale / NG-SIEM (CQL)",
  carbonblack: "Carbon Black Cloud (process search)",
  wazuh: "Wazuh dashboard search (DQL)",
  sentinelone: "SentinelOne Data Lake (PowerQuery)",
  cortex: "Cortex XDR (XQL)",
  qradar: "IBM QRadar (AQL)",
};

// Per-platform schema reference fed to the model so it grounds each query in REAL tables / plugins /
// field names instead of inventing them. These mirror the conventions the deterministic 🔍 pivot
// generators already use in the dashboard, so the two stay consistent. Kept terse to bound the prompt.
export const PLATFORM_SCHEMA_HINTS: Readonly<Record<HuntPlatform, string>> = {
  velociraptor:
    "Client-side VQL — one `SELECT … FROM <plugin>(…) WHERE …`. Real plugins: pslist() (Pid,Ppid,Name,CommandLine,Exe), " +
    "netstat() (Pid,Name,Status,Laddr.IP,Raddr.IP,Raddr.Port), glob(globs='C:/**/x.exe' — FORWARD slashes; OSPath,Size,Mtime), " +
    "stat(), hash(path=OSPath), read_file(filenames=[...]), yara(), parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') " +
    "with System.EventID.Value / EventData.<Name>, reg_keys()/reg_value(). No SQL JOIN (use foreach() or inline calls); " +
    "no duration literals — use now() - N * 86400.",
  defender:
    "Microsoft Defender XDR / Sentinel KQL (Kusto). Tables: DeviceProcessEvents (FileName, ProcessCommandLine, " +
    "InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, SHA256, DeviceName), DeviceNetworkEvents " +
    "(RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName), DeviceFileEvents (FileName, FolderPath, SHA256), " +
    "DeviceRegistryEvents (RegistryKey, RegistryValueName, RegistryValueData), DeviceLogonEvents (LogonType, AccountName, RemoteIP), " +
    "DeviceImageLoadEvents. Pipe with `| where`; operators =~, in~, has_any, has, contains.",
  elastic:
    "Elastic ES|QL over ECS. `FROM logs-* | WHERE … | KEEP … | SORT @timestamp DESC | LIMIT 100`. ECS fields: process.name, " +
    "process.command_line, process.parent.name, process.executable, process.hash.sha256, file.path, file.name, source.ip, " +
    "destination.ip, destination.port, dns.question.name, url.full, url.domain, user.name, host.name, event.action, event.category. " +
    "Functions: TO_LOWER(), IN (...), LIKE/RLIKE.",
  splunk:
    "Splunk SPL (CIM-normalized). `index=* <field filters> | table _time host user process_name parent_process_name CommandLine " +
    "dest_ip url file_path`. Common fields: process_name, parent_process_name, process/CommandLine, user, dest_ip, src_ip, dest, " +
    "file_name, file_path, query, url, EventCode, signature. Shape output with `| stats` / `| table`.",
  sigma:
    "Sigma generic detection rule (YAML): title, status, logsource (category e.g. process_creation / network_connection / " +
    "file_event, product e.g. windows), detection (a `selection` map of `Field|modifier: value` then `condition`), level, " +
    "tags (attack.tXXXX). Field names follow Sysmon/Windows: Image, CommandLine, ParentImage, TargetFilename, DestinationIp.",
  yara:
    'YARA rule over FILE CONTENT — `strings:` (text/byte/regex patterns) + `condition:` (optional `import "hash"`). ' +
    "Use for file/sample signatures. NOT for process-behavior or pure-network intents — mark notApplicable for those.",
  suricata:
    'Suricata/Snort NETWORK rule: `alert <proto: ip|dns|tls|http> $HOME_NET any -> <dest> any (msg:"…"; <keyword:content>; ' +
    "sid:9000001; rev:1;)`. Keyword content matches: dns.query / tls.sni / http.host / http.uri. Use for network intents " +
    "(domain/IP/URL/SNI); mark notApplicable for host-only process intents.",
  crowdstrike:
    "CrowdStrike Falcon LogScale / Next-Gen SIEM CQL (NOT legacy FQL or Splunk-era Event Search). Filter on the event tag " +
    "`#event_simpleName=<Event>`, then pipe: `| <field filters> | table([...])` or `| groupBy([...])`. Events: ProcessRollup2 " +
    "(ImageFileName = full path, CommandLine, ParentBaseFileName, SHA256HashData, MD5HashData, UserName, aid), NetworkConnectIP4 " +
    "(RemoteAddressIP4, RemotePort, LocalAddressIP4), DnsRequest (DomainName), *Written e.g. PeFileWritten (TargetFileName). " +
    'ComputerName for the host. Filters: field="value" (`*` is an unescapable wildcard), field=/regex/i, ' +
    'in(field=F, values=["a","b"], ignoreCase=true).',
  // #2667. Fields checked against
  // https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/platform-search-fields/
  // Targets Carbon Black Cloud (Enterprise EDR / Investigate); CB Response uses other field names.
  carbonblack:
    "Carbon Black Cloud (Enterprise EDR / Investigate) process search — Lucene-style `field:value` terms joined with " +
    "AND / OR / NOT (or a leading `-`), parentheses, `*` wildcards, quotes for values with spaces. NO pipes, NO " +
    "SELECT/FROM. Fields: process_name, process_cmdline, process_username, process_hash (MD5 or SHA-256), " +
    "parent_name, childproc_name, netconn_ipv4, netconn_port, netconn_domain, regmod_name, filemod_name, " +
    "modload_name, device_name. Example: `process_name:powershell.exe AND process_cmdline:*-enc*`. " +
    "This is Carbon Black Cloud syntax; CB Response (EDR) uses different field names.",
  // #2667. The Wazuh dashboard's search bars over indexer data use OpenSearch syntax —
  // https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/queries.html — written here as
  // OpenSearch Dashboards Query Language: https://docs.opensearch.org/latest/dashboards/dql/
  // Alert fields (agent.*, rule.*, data.win.*, syscheck.*, full_log) follow the Wazuh 4.x alert document
  // (wazuh-alerts-*); Wazuh 5 renames them to its common schema, which this hint does not cover yet.
  wazuh:
    "Wazuh dashboard search bar over the wazuh-alerts-* index, in OpenSearch DQL (NOT Wazuh rule XML, NOT WQL): " +
    "`field:value` terms joined with and / or / not, parentheses, `*` wildcards, quotes for phrases, ranges like " +
    "`rule.level >= 10`. NO pipes. Fields: agent.name, agent.ip, rule.id, rule.level, rule.description, " +
    "rule.groups, rule.mitre.id, decoder.name, location, full_log, syscheck.path (FIM); Windows eventchannel " +
    "data under data.win.system.* (eventID, computer, channel) and data.win.eventdata.* with camelCase " +
    "names (image, commandLine, parentImage, targetFilename, destinationIp, destinationPort, queryName, " +
    "targetUserName, logonType). Example: `data.win.eventdata.image:*powershell.exe and data.win.system.eventID:1`.",
  // #2667. Singularity Data Lake dotted field names (the same raw names the Cloud Funnel export carries:
  // endpoint.name, event.type, src.process.cmdline, src.process.name, tgt.process.name, tgt.file.path),
  // seen in https://www.elastic.co/guide/en/integrations/current/sentinel_one_cloud_funnel.html and the
  // S1QL 2.0 examples at https://github.com/SentineLabs/S1QL-Queries. dst.ip.address / dst.port.number /
  // event.dns.request are the S1QL 2.0 names; SentinelOne's own field reference is behind a login.
  sentinelone:
    "SentinelOne Singularity Data Lake PowerQuery (S1QL 2.0 field names, NOT the legacy SrcProcName style). A " +
    "filter of `field operator value` terms (=, !=, contains, contains:anycase, in:anycase(...), matches) joined " +
    "with and / or / not, then optional pipes: `| columns a, b`, `| group count() by x`, `| sort -x`, `| limit N`. " +
    "Fields: event.type ('Process Creation', 'File Creation', 'IP Connect', 'DNS Resolved', 'Registry Value " +
    "Modified'), endpoint.name, src.process.name, src.process.cmdline, src.process.user, src.process.image.path, " +
    "tgt.process.name, tgt.process.cmdline, tgt.file.path, tgt.file.sha256, dst.ip.address, dst.port.number, " +
    "event.dns.request, registry.keyPath. Example: `event.type = 'Process Creation' and src.process.cmdline " +
    "contains:anycase '-enc' | columns endpoint.name, src.process.cmdline`.",
  // #2667. Fields checked against
  // https://cortex-docs.paloaltonetworks.com/xql-schema-reference/xdr-data-fields and
  // https://cortex-docs.paloaltonetworks.com/xql-schema-reference/xdr-data-fields-by-actor/action-actor
  cortex:
    "Cortex XDR XQL. Start with `dataset = xdr_data` (or a preset such as `preset = xdr_process`), then pipe " +
    "stages: `| filter …`, `| fields …`, `| comp count() by …`, `| sort desc _time`, `| limit N`. Operators =, !=, " +
    "~= (regex), contains, in (...); combine with and / or. Fields: event_type (ENUM.PROCESS, ENUM.NETWORK, " +
    "ENUM.FILE, ENUM.REGISTRY), event_sub_type, agent_hostname, actor_process_image_name, " +
    "actor_process_command_line, action_process_image_name, action_process_image_command_line, " +
    "action_process_image_sha256, action_remote_ip, action_remote_port, action_external_hostname, " +
    "dns_query_name, action_file_path, action_file_sha256, action_registry_key_name, action_registry_value_name.",
  // #2667. Functions and time clauses checked against
  // https://www.ibm.com/docs/en/SS42VS_7.5/com.ibm.qradar.doc/r_aql_data_functions.html
  qradar:
    "IBM QRadar AQL (Ariel Query Language) — QRadar's own SQL-like language, so here a SELECT statement IS the " +
    "right answer: `SELECT … FROM events WHERE … LAST 7 DAYS` (or FROM flows; time with LAST n MINUTES/HOURS/DAYS " +
    "or START '…' STOP '…'). Fields: starttime, devicetime, sourceip, destinationip, sourceport, destinationport, " +
    "username, qid, category, logsourceid, eventcount; functions QIDNAME(qid), LOGSOURCENAME(logsourceid), " +
    "CATEGORYNAME(category). Match text with ILIKE '%x%' or MATCHES; custom event properties are double-quoted, " +
    'e.g. "Process CommandLine", "Process Name". Group with GROUP BY, order with ORDER BY, cap with LIMIT.',
};

/**
 * Render the platform reference block for the prompt — only the requested platforms, in canonical
 * display order, each with its label + schema hint. Unknown keys are dropped; an empty/blank request
 * falls back to ALL platforms. Pure.
 */
export function renderPlatformGuide(platforms: readonly HuntPlatform[]): string {
  const want = new Set(
    (platforms.length ? platforms : HUNT_PLATFORMS).filter((p) => HUNT_PLATFORMS.includes(p)),
  );
  const ordered = HUNT_PLATFORMS.filter((p) => want.has(p));
  const list = ordered.length ? ordered : [...HUNT_PLATFORMS];
  return list.map((p) => `- ${p} — ${PLATFORM_LABELS[p]}\n  ${PLATFORM_SCHEMA_HINTS[p]}`).join("\n");
}

/**
 * Render the distinct tool/log sources this case already has data from, so the model can ground the
 * translation in the platforms the analyst actually runs (the "log schemas the tool already knows").
 * Pure — reads the corroboration `sources` carried on each forensic event. Capped for the budget.
 */
export function renderCaseDataSources(state: InvestigationState, limit = 30): string {
  const sources = new Set<string>();
  for (const e of state.forensicTimeline ?? []) {
    for (const s of e.sources ?? []) {
      const v = String(s).trim();
      if (v) sources.add(v);
    }
  }
  return sources.size
    ? [...sources].slice(0, limit).join(", ")
    : "(no specific tool sources recorded yet — translate generically across the target platforms)";
}

/**
 * Drop unusable entries, normalize the platform key, restrict to the allowed/requested platforms,
 * dedupe (first wins), and clamp field lengths. An entry is kept only when it has a usable query OR
 * it is explicitly flagged notApplicable WITH an explanation of why (so the analyst sees the reason a
 * platform was skipped rather than a silent gap). Pure — deterministic, no I/O. Output is sorted in
 * canonical platform display order.
 */
export function sanitizeQueryTranslations(
  raw: readonly RawQueryTranslation[] | undefined,
  allowed: readonly HuntPlatform[],
): QueryTranslation[] {
  const allow = new Set<HuntPlatform>(
    (allowed.length ? allowed : HUNT_PLATFORMS).filter((p) => HUNT_PLATFORMS.includes(p)),
  );
  const seen = new Set<HuntPlatform>();
  const out: QueryTranslation[] = [];
  for (const t of raw ?? []) {
    const platform = normalizeHuntPlatform(String(t?.platform ?? ""));
    if (!platform || !allow.has(platform) || seen.has(platform)) continue;
    const query = String(t?.query ?? "").trim();
    const explanation = String(t?.explanation ?? "").trim();
    const flagged = !!t?.notApplicable;
    // No query and no reason → nothing to show. (A query implies applicable; an empty query implies N/A.)
    if (!query && !(flagged && explanation)) continue;
    seen.add(platform);
    out.push({
      platform,
      label:
        String(t?.label ?? "")
          .trim()
          .slice(0, MAX_LABEL_LEN) || PLATFORM_LABELS[platform],
      query: query.slice(0, MAX_QUERY_LEN),
      explanation: explanation.slice(0, MAX_EXPLANATION_LEN),
      caveats: String(t?.caveats ?? "")
        .trim()
        .slice(0, MAX_CAVEATS_LEN),
      notApplicable: query ? false : true,
    });
  }
  return out.sort((a, b) => HUNT_PLATFORMS.indexOf(a.platform) - HUNT_PLATFORMS.indexOf(b.platform));
}

/** Clamp the model's one-line interpretation of the request. Pure. */
export function sanitizeInterpretation(raw: string | undefined): string {
  return String(raw ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_INTERPRETATION_LEN);
}
