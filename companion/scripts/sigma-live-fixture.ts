// Re-prove the Sigma → VQL templates against a live Velociraptor and refresh the fixture that
// tests/analysis/sigmaVqlLive.test.ts pins (#802 item 1).
//
// One rule per template (plus the mixed-category draft) is compiled by the real compiler, launched
// through VelociraptorClient.launchHunt() — the path the dashboard's Sigma card uses — and read back
// per source with hunt_results(). The fixture keeps the rule, the exact VQL that ran, the hunt id
// and a few rows per source, so the test can check the column shapes the templates rely on.
//
// Run it when a template's VQL changes:
//   DFIR_VELOCIRAPTOR_API_CONFIG=/path/api_client.yaml DFIR_VELOCIRAPTOR_BINARY=/path/velociraptor \
//     npm run sigma:live-fixture
// Needs at least one enrolled Windows client. `--dry` compiles and prints the rules without
// launching anything. `--rows N` caps rows kept per source (default 4).

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compileSigmaText } from "../src/analysis/sigmaToVql.js";
import { PROCESS_EVENTS } from "../src/analysis/sigmaVqlTemplates.js";
import {
  VelociraptorClient,
  loadVelociraptorConfig,
} from "../src/integrations/velociraptor/velociraptorApi.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, "../tests/analysis/fixtures/sigma-velociraptor-live.json");

const rule = (cat: string, det: string) =>
  `title: live fixture ${cat}\nlogsource:\n  category: ${cat}\n  product: windows\ndetection:\n${det}\n`;

// Every rule is written to MATCH on a stock Windows client, so the rows prove the column shapes.
export const LIVE_RULES: Readonly<Record<string, string>> = {
  // Fields both logs record: the event source keeps its Sysmon-or-4688 branch and is a real miss.
  process: rule(
    "process_creation",
    [
      "  sel:",
      String.raw`    Image|endswith: '\svchost.exe'`,
      String.raw`    ParentImage|endswith: '\services.exe'`,
      "  condition: sel",
    ].join("\n"),
  ),
  // A hash field: pslist() hashes the binary; the event source runs on the Sysmon branch alone.
  processHashes: rule(
    "process_creation",
    [
      "  sel:",
      String.raw`    Image|endswith: '\svchost.exe'`,
      "    Hashes|contains: 'a'",
      "  condition: sel",
    ].join("\n"),
  ),
  netPort: rule(
    "network_connection",
    ["  sel:", "    DestinationPort|gte: 1", "    Image|endswith: '.exe'", "  condition: sel"].join("\n"),
  ),
  netCidr: rule(
    "network_connection",
    [
      "  sel:",
      "    DestinationIp|cidr:",
      "      - '10.0.0.0/8'",
      "      - '192.168.0.0/16'",
      "      - '172.16.0.0/12'",
      "  condition: sel",
    ].join("\n"),
  ),
  file: rule(
    "file_event",
    ["  sel:", String.raw`    TargetFilename: 'C:\Windows\System32\cmd.exe'`, "  condition: sel"].join("\n"),
  ),
  registry: rule(
    "registry_set",
    [
      "  sel:",
      String.raw`    TargetObject|startswith: 'HKLM\Software\Microsoft\Windows NT\CurrentVersion'`,
      "    Details|contains: 'Windows'",
      "  condition: sel",
    ].join("\n"),
  ),
  mixed: rule(
    "process_creation",
    [
      "  sel_process:",
      String.raw`    Image|endswith: '\svchost.exe'`,
      String.raw`    ParentImage|endswith: '\services.exe'`,
      "  sel_hash:",
      "    Hashes|contains: 'a'",
      "  sel_network_ip:",
      "    DestinationIp|cidr: '10.0.0.0/8'",
      "  sel_file_path:",
      String.raw`    TargetFilename: 'C:\Windows\System32\cmd.exe'`,
      "  condition: 1 of sel_*",
    ].join("\n"),
  ),
};

// Raw VQL beside the rules, for a branch no rule can force: the Security 4688 fallback runs only
// where the Sysmon log is absent, and the lab client has Sysmon.
export const LIVE_PROBES: Readonly<Record<string, string>> = {
  security4688: [...(PROCESS_EVENTS.preStages ?? []), "SELECT * FROM SecurityEvents LIMIT 20"].join("\n"),
};

type Row = Record<string, unknown>;
interface Launched {
  key: string;
  huntId: string;
  artifact: string;
  sources: string[];
  probe?: boolean;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const argFlag = (name: string) => process.argv.includes(name);
const argValue = (name: string, fallback: number) => {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? Number(process.argv[i + 1]) || fallback : fallback;
};

async function main(): Promise<void> {
  const dry = argFlag("--dry");
  const keep = argValue("--rows", 4);
  const compiled: Record<string, { rule: string; vql: string; snapshot: boolean }> = {};
  for (const [key, text] of Object.entries(LIVE_RULES)) {
    const c = compileSigmaText(text);
    if (!c.ok) {
      throw new Error(`${key} refused:\n` + c.refusals.map((r) => `  ${r.path}: ${r.message}`).join("\n"));
    }
    compiled[key] = { rule: text, vql: c.vql, snapshot: c.snapshot };
    console.log(`\n===== ${key} =====\n${c.vql}`);
  }
  if (dry) return;

  const config = loadVelociraptorConfig();
  if (!config) throw new Error("set DFIR_VELOCIRAPTOR_API_CONFIG (and DFIR_VELOCIRAPTOR_BINARY)");
  const client = new VelociraptorClient({ ...config, maxRows: Math.max(keep, 1) });

  const server = (await client.run("SELECT Hostname, OS FROM info()")).rows[0] as Row | undefined;
  const clients = (
    await client.run(
      "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, os_info.release AS release, agent_information.version AS agent FROM clients() WHERE os_info.system = 'windows'",
    )
  ).rows as Row[];
  if (!clients.length) throw new Error("no enrolled Windows client — the templates are Windows plugins");
  console.log(`\nserver ${String(server?.Hostname ?? "?")}; ${clients.length} Windows client(s)`);

  const launched: Launched[] = [];
  for (const [key, c] of Object.entries(compiled)) {
    // "Sigma: " first — an artifact name part may not start with a digit, and the launcher derives
    // the name from this description exactly as the dashboard's Sigma card does.
    const h = await client.launchHunt(c.vql, `Sigma: live fixture ${key}`, { expirySeconds: 1800 });
    console.log(`launched ${key}: ${h.huntId} (${h.sources.join(", ")})`);
    launched.push({ key, huntId: h.huntId, artifact: h.artifact, sources: h.sources });
  }
  for (const [key, text] of Object.entries(LIVE_PROBES)) {
    const h = await client.launchHunt(text, `Sigma: live probe ${key}`, { expirySeconds: 1800 });
    console.log(`launched probe ${key}: ${h.huntId} (${h.sources.join(", ")})`);
    launched.push({ key, huntId: h.huntId, artifact: h.artifact, sources: h.sources, probe: true });
  }

  const hunts: Record<string, unknown> = {};
  const probes: Record<string, unknown> = {};
  const done = new Set<string>();
  for (let i = 0; i < 24 && done.size < launched.length; i++) {
    await sleep(15_000);
    for (const h of launched) {
      if (done.has(h.key)) continue;
      const flows = (
        await client.run(
          `SELECT Flow.state AS State, Flow.status AS Status FROM hunt_flows(hunt_id='${h.huntId}')`,
        )
      ).rows as Row[];
      if (!flows.length || flows.some((f) => f.State === "RUNNING")) continue;
      const failed = flows.filter((f) => f.State !== "FINISHED");
      if (failed.length) throw new Error(`${h.key}: flow ${JSON.stringify(failed[0])}`);
      const sources: Record<string, Row[]> = {};
      for (const src of h.sources) {
        const res = await client.huntResults(h.huntId, h.artifact, [src]);
        sources[src] = (res.rows as Row[]).slice(0, keep);
        console.log(`  ${h.key}/${src}: ${res.rows.length} row(s)`);
      }
      if (h.probe) probes[h.key] = { huntId: h.huntId, vql: LIVE_PROBES[h.key], sources };
      else hunts[h.key] = { huntId: h.huntId, ...compiled[h.key], sources };
      done.add(h.key);
    }
  }
  const missing = launched.filter((h) => !done.has(h.key)).map((h) => h.key);
  if (missing.length) throw new Error(`no result within six minutes for: ${missing.join(", ")}`);

  const first = clients[0];
  const fixture = {
    capturedAt: new Date().toISOString().slice(0, 10),
    server: { hostname: String(server?.Hostname ?? ""), os: String(server?.OS ?? "") },
    client: {
      clientId: String(first.client_id ?? ""),
      hostname: String(first.hostname ?? ""),
      os: String(first.os ?? ""),
      release: String(first.release ?? ""),
      agent: String(first.agent ?? ""),
    },
    launcher: "VelociraptorClient.launchHunt() — the path the dashboard's Sigma card uses",
    hunts,
    probes,
  };
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(fixture, null, 2) + "\n");
  console.log(`\nwrote ${OUT}`);
}

main().catch((e: unknown) => {
  console.error((e as Error).message);
  process.exit(1);
});
