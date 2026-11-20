// AI Agent Forensics (#2690): the VQL of the generated client artifact's sources. Pure strings, no
// I/O; aiAgentArtifact.ts assembles them into YAML.
//
// SERIALIZATION RULE: no rule text, path, glob, rule title or any other data string is ever written
// into VQL. Everything the artifact needs travels as ONE base64 JSON blob, split into chunks held by
// small import-only artifacts, and is read back with parse_json(base64decode(...)). The only literals
// in this VQL are fixed identifiers and the base64 alphabet, so no rule content can break the YAML,
// the VQL string syntax or the ''' launch literal (§13.8).

const MARK = "1 AS DFIRCompanionAIAgent";

/** The preamble every source starts with: rebuild `cfg` from the imported chunks. */
export function cfgPreamble(partVars: string[]): string {
  return [
    `LET cfg <= parse_json(data=base64decode(string=join(array=[${partVars.join(", ")}], sep="")))`,
    "LET scan_time <= timestamp(epoch=now())",
  ].join("\n");
}

/** One YARA scope: list its files once, scan them, emit hit rows and one coverage row. */
export function yaraScopeVql(key: string): { lets: string; hits: string; coverage: string } {
  const s = `cfg.${key}`;
  const lets = [
    `LET files_${key} <= SELECT OSPath, Size, Mtime, Btime FROM glob(globs=${s}.Globs)`,
    `  WHERE NOT IsDir AND NOT OSPath =~ cfg.CredentialRegex AND NOT (${s}.SkipRegex AND OSPath =~ ${s}.SkipRegex)`,
    `LET scan_${key} = SELECT * FROM foreach(`,
    `  row={ SELECT * FROM files_${key} WHERE Size <= cfg.ScanMaxBytes },`,
    `  query={ SELECT Rule, String, OSPath AS HitPath, Size AS HitSize, Mtime AS HitMtime, Btime AS HitBtime`,
    `          FROM yara(files=OSPath, rules=${s}.Rules, number=1) })`,
  ].join("\n");
  const meta = (field: string) => `get(item=get(item=cfg.RuleMeta, field=Rule), field="${field}")`;
  const hits = [
    `SELECT ${MARK}, "hit" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime, "yara" AS Family,`,
    `  Rule AS RuleName, ${meta("File")} AS RuleFile, ${meta("Author")} AS RuleAuthor,`,
    `  ${meta("Atlas")} AS RuleAtlas, ${meta("Grade")} AS Grade, ${s}.Id AS Scope,`,
    `  HitPath AS FilePath, HitSize AS FileSize, HitMtime AS FileMtime, HitBtime AS FileBtime,`,
    `  hash(path=HitPath).SHA256 AS FileSha256,`,
    `  format(format="%.200s", args=[String.Data]) AS MatchedText,`,
    `  if(condition=NOT ${s}.Upload, then="kept by the AICodingAgents preservation collection",`,
    `     else=if(condition=HitSize > cfg.UploadMaxBytes, then="match observed; file not preserved (over the upload cap)",`,
    `     else=format(format="uploaded (%v bytes)", args=[upload(file=HitPath).Size]))) AS Preserved`,
    `FROM scan_${key} WHERE NOT Rule IN cfg.Disabled`,
  ].join("\n");
  const coverage = [
    `SELECT ${MARK}, "coverage" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime,`,
    `  format(format="YARA %v", args=[${s}.Id]) AS Source, "scanned" AS Status,`,
    `  format(format="%v file(s) scanned; %v skipped over the %v-byte scan cap",`,
    `    args=[len(list={ SELECT * FROM files_${key} WHERE Size <= cfg.ScanMaxBytes }),`,
    `          len(list={ SELECT * FROM files_${key} WHERE Size > cfg.ScanMaxBytes }), cfg.ScanMaxBytes]) AS Detail`,
    `FROM scope()`,
  ].join("\n");
  return { lets, hits, coverage };
}

/** The YARA source: every selected scope, chained. */
export function yaraSourceVql(preamble: string, keys: string[]): string {
  const parts = keys.map(yaraScopeVql);
  const chain = keys.flatMap((k, i) => [`  h${i}={ ${parts[i].hits} }`, `  c${i}={ ${parts[i].coverage} }`]);
  return [preamble, ...parts.map((p) => p.lets), `SELECT * FROM chain(`, chain.join(",\n"), ")"].join("\n");
}

/**
 * Inventory: tools present, configured MCP servers (name + executable only — the first token of the
 * command, arguments counted, `env` never read out), credential stores (path/size/time/hash only).
 */
export function inventorySourceVql(preamble: string): string {
  const head = `${MARK}, cfg.RuleSet AS RuleSet, scan_time AS ScanTime`;
  const server = (doc: string) =>
    [
      `SELECT ${head}, "inventory" AS Kind, tool AS Tool, _key AS McpServer,`,
      `  split(string=str(str=get(item=_value, field="command") || get(item=_value, field="url") || ""), sep=" ")[0] AS McpCommand,`,
      `  len(list=get(item=_value, field="args") || []) AS McpArgCount, OSPath AS ConfigPath`,
      `FROM items(item=${doc})`,
    ].join("\n");
  return [
    preamble,
    `LET mcp_doc(p) = parse_json(data=read_file(filename=p, length=cfg.ScanMaxBytes))`,
    `LET mcp_files <= SELECT * FROM foreach(row=cfg.McpConfigs,`,
    `  query={ SELECT tool, OSPath FROM glob(globs=glob) WHERE NOT IsDir AND Size <= cfg.ScanMaxBytes })`,
    `SELECT * FROM chain(`,
    `  tools={ SELECT ${head}, "inventory" AS Kind, name AS Tool FROM foreach(row=cfg.Tools,`,
    `    query={ SELECT name FROM glob(globs=globs) LIMIT 1 }) },`,
    `  mcp={ SELECT * FROM foreach(row=mcp_files, query={`,
    `    ${server('get(item=mcp_doc(p=OSPath), field="mcpServers") || get(item=mcp_doc(p=OSPath), field="servers") || dict()')} }) },`,
    `  projects={ SELECT * FROM foreach(row=mcp_files, query={`,
    `    SELECT * FROM foreach(row={ SELECT _value AS P, tool, OSPath FROM items(item=get(item=mcp_doc(p=OSPath), field="projects") || dict()) },`,
    `      query={ ${server('get(item=P, field="mcpServers") || dict()')} }) }) },`,
    `  creds={ SELECT ${head}, "credential" AS Kind, OSPath AS FilePath, Size AS FileSize, Mtime AS FileMtime,`,
    `    hash(path=OSPath).SHA256 AS FileSha256 FROM glob(globs=cfg.CredentialGlobs) WHERE NOT IsDir }`,
    ")",
  ].join("\n");
}

/**
 * A compiled Sigma rule (sigmaToVql.ts block: LET stages + one final SELECT), wrapped so its rows
 * keep their native columns and gain the marker columns. The rule's title etc. come from cfg.
 */
export function compiledSigmaSourceVql(preamble: string, block: string, key: string): string {
  const lines = block.split(/\r?\n/);
  let last = -1;
  lines.forEach((l, i) => {
    if (/^SELECT\b/i.test(l)) last = i;
  });
  if (last < 0) throw new Error(`compiled Sigma block for ${key} has no final SELECT`);
  const stages = lines.slice(0, last).join("\n");
  const select = lines.slice(last).join("\n");
  return [
    preamble,
    stages,
    `LET sigma_rows = ${select}`,
    `SELECT *, ${MARK}, "hit" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime, "sigma" AS Family,`,
    `  cfg.${key}.Title AS RuleName, cfg.${key}.File AS RuleFile, cfg.${key}.Author AS RuleAuthor,`,
    `  cfg.${key}.Tags AS RuleTags, cfg.${key}.Grade AS Grade, cfg.${key}.Coverage AS Scope`,
    `FROM sigma_rows`,
  ].join("\n");
}

/**
 * The Sigma rules the compiler refuses but Sysmon can answer (§14.4), through Velociraptor's own
 * sigma() engine over the Sysmon event log. No Sysmon → one coverage row "not run: no Sysmon".
 */
export function sysmonSigmaSourceVql(preamble: string): string {
  const evtx = (eid: number) =>
    `{ SELECT * FROM parse_evtx(filename=cfg.SysmonLog) WHERE System.EventID.Value = ${eid} }`;
  return [
    preamble,
    `LET has_sysmon <= stat(filename=cfg.SysmonLog)`,
    "LET log_sources <= sigma_log_sources(",
    `  \`file_event/windows/*\`=${evtx(11)},`,
    `  \`file_event/*/*\`=${evtx(11)},`,
    `  \`dns_query/windows/*\`=${evtx(22)},`,
    `  \`dns_query/*/*\`=${evtx(22)})`,
    `SELECT * FROM if(condition=has_sysmon,`,
    `  then={ SELECT *, ${MARK}, "hit" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime, "sigma" AS Family,`,
    `    _Rule.Title AS RuleName, get(item=get(item=cfg.SysmonMeta, field=_Rule.Title), field="File") AS RuleFile,`,
    `    get(item=get(item=cfg.SysmonMeta, field=_Rule.Title), field="Grade") AS Grade,`,
    `    get(item=get(item=cfg.SysmonMeta, field=_Rule.Title), field="Tags") AS RuleTags,`,
    `    "Sysmon event history" AS Scope, System.TimeCreated.SystemTime AS EventTime`,
    `    FROM sigma(rules=cfg.SysmonRules, log_sources=log_sources,`,
    `               field_mapping=cfg.SysmonFieldMapping) },`,
    `  else={ SELECT ${MARK}, "coverage" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime,`,
    `    "Sigma on Sysmon" AS Source, "not run: no Sysmon" AS Status,`,
    `    format(format="%v rule(s) need the Sysmon log", args=[cfg.SysmonCount]) AS Detail FROM scope() })`,
  ].join("\n");
}
