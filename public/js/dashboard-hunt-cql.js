// CrowdStrike Falcon hunt card for the 🔍 hunt modal (#2558): LogScale / Next-Gen SIEM CQL.
//
// Same contract as the KQL / SPL / ES|QL builders: deterministic templating off ONE entity's
// indicators (huntContextFor's typed buckets), no AI, no server round-trip. One query block per
// indicator type, each runnable on its own in Falcon's Advanced Event Search / NG-SIEM search.
// Not legacy FQL (the Falcon API filter language) and not the pre-2023 Splunk-based Event Search.
//
// ESCAPING IS THE CORRECTNESS CORE. Every value here is attacker-controlled (process names, paths,
// domains pulled from evidence). In a CQL quoted string only `\"`, `\\` and `\n` are escapes, and a
// quoted string cannot span lines. Worse, `*` inside a quoted filter value (and inside in()'s
// values) is a wildcard that CANNOT be escaped — an IOC like `*.com` would silently match every
// .com domain in the fleet. So any value with `*` or a control character never reaches a quoted
// form: the whole list goes to an anchored regex with every metacharacter escaped instead.
//
// The entity label and host are NOT written into the query, not even as comments: a newline in
// either would break out of a `//` comment line and become query text.
//
// Pure helper, holds no state. Reads baseName / cleanWinPath / pushUniq from
// js/dashboard-bulk-findings.js at call time, like the sigma-hunt module does.
(function () {
  const MAX_VALUES = 20; // keep the in() lists pasteable, same order of size as the Sigma draft caps

  // A CQL quoted string: escape backslash first, then the quote.
  const cqlString = (v) =>
    `"${String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

  // A value for inside a CQL /regex/ literal: escape every regex metacharacter plus the `/`
  // delimiter, and write control characters as \xHH so nothing can span a line.
  const cqlRegexLiteral = (v) =>
    String(v)
      .replace(/[\\^$.*+?()[\]{}|/]/g, "\\$&")
      .replace(
        /[\x00-\x1f\x7f]/g,
        (ch) => "\\x" + ch.charCodeAt(0).toString(16).padStart(2, "0"),
      );

  // Values that cannot be written as an exact quoted CQL value: an unescapable `*` wildcard, or a
  // control character a quoted string cannot hold.
  const needsRegex = (v) => /[*\x00-\x1f\x7f]/.test(v);

  // One filter matching any of `values` exactly (case-insensitive). in() when every value is safe
  // as a quoted literal; otherwise one anchored regex over the whole list.
  function cqlMatch(field, values) {
    if (values.some(needsRegex)) {
      return `${field}=/^(?:${values.map(cqlRegexLiteral).join("|")})$/i`;
    }
    return `in(field=${field}, values=[${values.map(cqlString).join(", ")}], ignoreCase=true)`;
  }

  // A suffix match on a Falcon full-path field (ImageFileName / TargetFileName are device-style,
  // e.g. \Device\HarddiskVolume3\Windows\x.exe, so an exact match on a case path never hits).
  const cqlPathEnds = (field, names) =>
    `${field}=/\\\\(?:${names.map(cqlRegexLiteral).join("|")})$/i`;

  // Trim, drop empties (an empty value would match everything), dedupe, cap.
  function cleanVals(arr, fn) {
    const out = [];
    for (const v of arr) {
      if (out.length >= MAX_VALUES) break;
      const t = String(fn ? fn(v) : v).trim();
      if (t) pushUniq(out, t);
    }
    return out;
  }

  const urlHost = (u) => {
    try {
      return new URL(u).hostname;
    } catch (_) {
      return "";
    }
  };

  const block = (comment, lines) => [`// ${comment}`, ...lines].join("\n");

  function processBlocks(c, out) {
    const procs = cleanVals(c.processes, baseName);
    if (procs.length)
      out.push(
        block("Process executions by image name", [
          "#event_simpleName=ProcessRollup2",
          `| ${cqlPathEnds("ImageFileName", procs)}`,
          "| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData])",
        ]),
      );
    const parent = cleanVals(c.parent ? [c.parent] : [], baseName);
    if (parent.length)
      out.push(
        block("Children of the parent process", [
          "#event_simpleName=ProcessRollup2",
          `| ${cqlMatch("ParentBaseFileName", parent)}`,
          "| table([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine])",
        ]),
      );
  }

  function hashBlocks(c, out) {
    const hashes = cleanVals(c.hashes, (h) => String(h).toLowerCase());
    const sha256 = hashes.filter((h) => h.length === 64);
    const md5 = hashes.filter((h) => h.length === 32);
    const tail =
      "| table([@timestamp, #event_simpleName, ComputerName, ImageFileName, TargetFileName, SHA256HashData, MD5HashData])";
    if (sha256.length)
      out.push(
        block("Any event carrying the SHA256", [
          cqlMatch("SHA256HashData", sha256),
          tail,
        ]),
      );
    if (md5.length)
      out.push(
        block("Any event carrying the MD5", [cqlMatch("MD5HashData", md5), tail]),
      );
  }

  function networkBlocks(c, out) {
    const ips = cleanVals(c.ips);
    if (ips.length)
      out.push(
        block("Outbound connections to the IP", [
          "#event_simpleName=NetworkConnectIP4",
          `| ${cqlMatch("RemoteAddressIP4", ips)}`,
          "| table([@timestamp, ComputerName, ContextProcessId, LocalAddressIP4, RemoteAddressIP4, RemotePort])",
        ]),
      );
    const domains = cleanVals([...c.domains, ...c.urls.map(urlHost)]);
    if (domains.length)
      out.push(
        block("DNS lookups of the domain", [
          "#event_simpleName=DnsRequest",
          `| ${cqlMatch("DomainName", domains)}`,
          "| table([@timestamp, ComputerName, ContextProcessId, DomainName])",
        ]),
      );
  }

  function fileBlocks(c, out) {
    const names = cleanVals(c.paths, baseName);
    if (names.length)
      out.push(
        block("Files written with this name (PeFileWritten, NewExecutableWritten, …)", [
          "#event_simpleName=/Written$/",
          `| ${cqlPathEnds("TargetFileName", names)}`,
          "| table([@timestamp, #event_simpleName, ComputerName, TargetFileName, SHA256HashData])",
        ]),
      );
  }

  // The card's query text, or "" when the entity carries nothing these templates key on.
  function huntCql(c) {
    const out = [];
    processBlocks(c, out);
    hashBlocks(c, out);
    networkBlocks(c, out);
    fileBlocks(c, out);
    return out.join("\n\n");
  }

  window.huntCql = huntCql;
  window.cqlString = cqlString;
  window.cqlRegexLiteral = cqlRegexLiteral;
  window.cqlMatch = cqlMatch;
})();
