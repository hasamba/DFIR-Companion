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

/**
 * One YARA scope: list its files once, scan them, emit hit rows and one coverage row. A hit carries the
 * file's hash AND, when the run uploaded the file, the hash of that upload (#2722).
 *
 * yara(), hash() and upload() are three separate reads of the file, and the bytes YARA matched are not
 * hashed: the file hash is taken after the scan, and the order of hash() and upload() inside one row is
 * not guaranteed. Binding all three to one read (read_file into memory, then the "data" accessor) would
 * hold up to the scan cap — gigabytes for model files — in memory per file, so it is not done; the
 * report says instead what an equal pair of hashes does and does not prove (aiAgentHashCheck.ts).
 */
export function yaraScopeVql(key: string): { lets: string; hits: string; coverage: string } {
  const s = `cfg.${key}`;
  const lets = [
    `LET files_${key} <= SELECT OSPath, Size, Mtime, Btime FROM glob(globs=${s}.Globs)`,
    `  WHERE NOT IsDir AND NOT OSPath =~ cfg.CredentialRegex AND NOT (${s}.SkipRegex AND OSPath =~ ${s}.SkipRegex)`,
    `LET scan_${key} = SELECT * FROM foreach(`,
    `  row={ SELECT * FROM files_${key} WHERE Size <= cfg.ScanMaxBytes },`,
    `  query={ SELECT Rule, String, OSPath AS HitPath, Size AS HitSize, Mtime AS HitMtime, Btime AS HitBtime`,
    `          FROM yara(files=OSPath, rules=${s}.Rules, number=1) })`,
    // The ONE upload() per hit (#2722): its result is read twice below — size and hash — so the
    // preserved copy's hash is the hash of the very upload that preserved it.
    `LET kept_${key} = SELECT *, if(condition=${s}.Upload AND HitSize <= cfg.UploadMaxBytes,`,
    `    then=upload(file=HitPath)) AS Up`,
    `  FROM scan_${key} WHERE NOT Rule IN cfg.Disabled`,
  ].join("\n");
  const meta = (field: string) => `get(item=get(item=cfg.RuleMeta, field=Rule), field="${field}")`;
  const hits = [
    `SELECT ${MARK}, "hit" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime, "yara" AS Family,`,
    `  Rule AS RuleName, ${meta("File")} AS RuleFile, ${meta("Author")} AS RuleAuthor,`,
    `  ${meta("Atlas")} AS RuleAtlas, ${meta("Grade")} AS Grade, ${s}.Id AS Scope,`,
    `  HitPath AS FilePath, HitSize AS FileSize, HitMtime AS FileMtime, HitBtime AS FileBtime,`,
    `  hash(path=HitPath).SHA256 AS FileSha256, Up.Sha256 AS PreservedSha256,`,
    `  format(format="%.200s", args=[String.Data]) AS MatchedText,`,
    `  if(condition=NOT ${s}.Upload, then="kept by the AICodingAgents preservation collection",`,
    `     else=if(condition=HitSize > cfg.UploadMaxBytes, then="match observed; file not preserved (over the upload cap)",`,
    `     else=if(condition=Up, then=format(format="uploaded (%v bytes)", args=[Up.Size]),`,
    `     else="match observed; upload result not recorded"))) AS Preserved`,
    `FROM kept_${key}`,
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
 * The first of the expressions that is set (not null, empty or false), else the last one, as nested
 * `if()` calls. Velociraptor's parser refuses `x || []` (v0.75: unexpected token "||"), which refused
 * the whole artifact at upload; `if()` parses in every form, so the sources use it and never `||`.
 */
export function vqlFirst(...exprs: string[]): string {
  const last = exprs[exprs.length - 1];
  return exprs.slice(0, -1).reduceRight((acc, e) => `if(condition=${e}, then=${e}, else=${acc})`, last);
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
      `  split(string=str(str=${vqlFirst('get(item=_value, field="command")', 'get(item=_value, field="url")', '""')}), sep=" ")[0] AS McpCommand,`,
      `  len(list=${vqlFirst('get(item=_value, field="args")', "[]")}) AS McpArgCount, OSPath AS ConfigPath`,
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
    `    ${server(vqlFirst('get(item=mcp_doc(p=OSPath), field="mcpServers")', 'get(item=mcp_doc(p=OSPath), field="servers")', "dict()"))} }) },`,
    `  projects={ SELECT * FROM foreach(row=mcp_files, query={`,
    `    SELECT * FROM foreach(row={ SELECT _value AS P, tool, OSPath FROM items(item=${vqlFirst('get(item=mcp_doc(p=OSPath), field="projects")', "dict()")}) },`,
    `      query={ ${server(vqlFirst('get(item=P, field="mcpServers")', "dict()"))} }) }) },`,
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
    `SELECT * FROM chain(`,
    `  h={ SELECT *, ${MARK}, "hit" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime, "sigma" AS Family,`,
    `    cfg.${key}.Title AS RuleName, cfg.${key}.File AS RuleFile, cfg.${key}.Author AS RuleAuthor,`,
    `    cfg.${key}.Tags AS RuleTags, cfg.${key}.Grade AS Grade, cfg.${key}.Coverage AS Scope`,
    `    FROM sigma_rows },`,
    // One coverage row per rule per endpoint (#2722), after its hits: the rule ran here, on this basis.
    `  c={ SELECT ${MARK}, "coverage" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime,`,
    `    "Sigma" AS Source, cfg.${key}.Title AS RuleName,`,
    `    format(format="ran (%v)", args=[cfg.${key}.Basis]) AS Status, cfg.${key}.Sentence AS Detail`,
    `    FROM scope() })`,
  ].join("\n");
}

/**
 * The Sigma rules the compiler refuses but Sysmon can answer (§14.4), through Velociraptor's own
 * sigma() engine over the Sysmon event log. Every rule gets one coverage row per endpoint: "ran" when
 * the Sysmon log is there, "not run: no Sysmon" when it is not (#2722).
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
    `  then={ SELECT * FROM chain(`,
    `    h={ SELECT *, ${MARK}, "hit" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime, "sigma" AS Family,`,
    `      _Rule.Title AS RuleName, get(item=get(item=cfg.SysmonMeta, field=_Rule.Title), field="File") AS RuleFile,`,
    `      get(item=get(item=cfg.SysmonMeta, field=_Rule.Title), field="Grade") AS Grade,`,
    `      get(item=get(item=cfg.SysmonMeta, field=_Rule.Title), field="Tags") AS RuleTags,`,
    `      "Sysmon event history" AS Scope, System.TimeCreated.SystemTime AS EventTime`,
    `      FROM sigma(rules=cfg.SysmonRules, log_sources=log_sources,`,
    `                 field_mapping=cfg.SysmonFieldMapping) },`,
    // One coverage row per Sysmon rule per endpoint (#2722); the titles come from cfg, never the VQL.
    `    c={ SELECT ${MARK}, "coverage" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime,`,
    `      "Sigma on Sysmon" AS Source, Title AS RuleName, "ran (Sysmon event history)" AS Status,`,
    `      "Velociraptor sigma() over the Sysmon event log" AS Detail FROM foreach(row=cfg.SysmonTitles) }) },`,
    `  else={ SELECT ${MARK}, "coverage" AS Kind, cfg.RuleSet AS RuleSet, scan_time AS ScanTime,`,
    `    "Sigma on Sysmon" AS Source, Title AS RuleName, "not run: no Sysmon" AS Status,`,
    `    "the Sysmon event log is not on this endpoint" AS Detail FROM foreach(row=cfg.SysmonTitles) })`,
  ].join("\n");
}
