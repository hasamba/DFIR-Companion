// Identify the DFIR/SOC tool behind a piece of evidence from free text — an import
// filename (e.g. "velociraptor_processes.csv") or a captured browser tab title (we bake
// the tab title into screenshot filenames). Used to tag forensic events with a real
// SOURCE name so cross-source correlation reads "corroborated by Velociraptor, THOR"
// instead of the generic "CSV import, screenshot".
//
// Ordered: more-specific patterns first (SentinelOne before a bare "Sentinel"; "Defender
// for Endpoint" maps to Microsoft Defender). First match wins; no match → undefined.

interface ToolPattern { re: RegExp; name: string; }

const TOOLS: ToolPattern[] = [
  { re: /velociraptor/i, name: "Velociraptor" },
  { re: /\bthor\b|nextron/i, name: "THOR" },
  { re: /crowdstrike|falcon/i, name: "CrowdStrike Falcon" },
  { re: /sentinel[\s_-]?one/i, name: "SentinelOne" },
  { re: /(?:microsoft|azure)[\s_-]*sentinel/i, name: "Microsoft Sentinel" },
  { re: /(?:microsoft|windows|ms)[\s_-]*defender|defender[\s_-]*for[\s_-]*endpoint|\bmde\b/i, name: "Microsoft Defender" },
  { re: /carbon[\s_-]?black|cb[\s_-]?response|\bvmware cb\b/i, name: "Carbon Black" },
  { re: /cortex[\s_-]?xdr|palo[\s_-]?alto/i, name: "Cortex XDR" },
  { re: /\bsplunk\b/i, name: "Splunk" },
  { re: /elastic(?:search)?|kibana|\belk\b/i, name: "Elastic" },
  { re: /\bqradar\b/i, name: "QRadar" },
  { re: /graylog/i, name: "Graylog" },
  { re: /grafana/i, name: "Grafana" },
  { re: /sysmon/i, name: "Sysmon" },
  { re: /wazuh/i, name: "Wazuh" },
  { re: /security[\s_-]?onion/i, name: "Security Onion" },
  { re: /arkime|moloch/i, name: "Arkime" },
  { re: /timesketch/i, name: "Timesketch" },
  { re: /volweb/i, name: "VolWeb" },
  { re: /volatility/i, name: "Volatility" },
  { re: /autopsy/i, name: "Autopsy" },
  { re: /virustotal|\bvt\b/i, name: "VirusTotal" },
  { re: /hayabusa/i, name: "Hayabusa" },
  { re: /chainsaw/i, name: "Chainsaw" },
  { re: /\bkape\b/i, name: "KAPE" },
  { re: /nessus|tenable/i, name: "Nessus" },
  { re: /wireshark/i, name: "Wireshark" },
  { re: /\bzeek\b|\bbro\b/i, name: "Zeek" },
  { re: /suricata/i, name: "Suricata" },
  { re: /misp/i, name: "MISP" },
  { re: /thehive|the[\s_-]hive/i, name: "TheHive" },
];

// Return the canonical tool name detected in the text, or undefined if none match.
// Underscores/hyphens/dots are normalized to spaces first so word-boundary patterns
// match inside filenames like "WIN11_thor_2026.json".
export function detectTool(text: string | undefined | null): string | undefined {
  if (!text) return undefined;
  const normalized = text.replace(/[_\-.]+/g, " ");
  for (const t of TOOLS) if (t.re.test(normalized)) return t.name;
  return undefined;
}
