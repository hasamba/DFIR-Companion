// Wildcard patterns and CIDR ranges in the Anonymization panel's custom-entity list (#2946).
// Classic script, like its dashboard-*.js siblings (see dashboard-escape.js for why). The server
// is the authority on what a valid pattern is; the checks here only give the analyst the reason
// before they press Save, and a save the server refuses still shows its reason.
(function () {
  const IP_CATS = new Set(["IP", "EXTIP"]);
  const MIN_LITERAL = 3;
  const MAX_PATTERN = 1024; // anonPatterns.ts MAX_PATTERN_LENGTH (#3009)
  let reports = []; // [{ value, category, count, sample, invalid? }] from GET /anon-entities

  function anonPatternShape(value, category) {
    return value.includes("*") || (IP_CATS.has(category) && value.includes("/"));
  }

  function rangeProblem(value) {
    if (value.includes("*")) return "Addresses take a CIDR range instead of *, for example 10.20.0.0/16.";
    const m = /^([^/\s]+)\/(\d{1,3})$/.exec(value);
    if (!m) return "Write the range as address/prefix, for example 10.20.0.0/16.";
    const v6 = m[1].includes(":");
    const prefix = Number(m[2]);
    if (prefix > (v6 ? 128 : 32)) return `/${prefix} is not a valid prefix for an IPv${v6 ? 6 : 4} address.`;
    if (prefix < (v6 ? 16 : 8))
      return `A /${prefix} range is too wide. The widest allowed is /${v6 ? 16 : 8} for IPv${v6 ? 6 : 4}.`;
    return null;
  }

  function wildcardProblem(value) {
    if (value.length > MAX_PATTERN) return `A pattern can be at most ${MAX_PATTERN} characters long.`;
    if (value.includes("**")) return "Two * in a row mean nothing more than one. Use a single *.";
    const literal = value.replace(/\*/g, "");
    if (literal.trim().length < MIN_LITERAL)
      return `A pattern needs at least ${MIN_LITERAL} characters besides *, or it would hide almost everything.`;
    if (!/[\p{L}\p{N}]/u.test(literal)) return "A pattern needs at least one letter or digit besides *.";
    if (/anon_/i.test(literal)) return "A pattern cannot contain ANON_: that is what masking tokens look like.";
    if (value.slice(1, -1).split("*").length > 2)
      return "Use at most one * in the middle of a pattern (one more at each end is fine).";
    return null;
  }

  /** The entry to add for a typed value: an exact value, a pattern entry, or a reason it is refused. */
  function anonCustomEntry(value, category) {
    if (!anonPatternShape(value, category)) return { value, category };
    const problem = IP_CATS.has(category) ? rangeProblem(value) : wildcardProblem(value);
    return problem || { value, category, match: "pattern" };
  }

  function setAnonPatternReports(list) {
    reports = Array.isArray(list) ? list : [];
  }

  /** The tag and match count shown beside a pattern row; empty for an exact value. */
  function anonPatternTag(e) {
    if (e.match !== "pattern") return "";
    const kind = IP_CATS.has(e.category) ? "range" : "pattern";
    const r = reports.find((x) => x.category === e.category && x.value.toLowerCase() === e.value.toLowerCase());
    const tag = `<span class="anon-pat-tag">${kind}</span>`;
    if (!r) return `${tag}<span class="anon-pat-count">matches shown after Save</span>`;
    if (r.invalid)
      return `<span class="anon-pat-tag anon-pat-bad">${kind} not applied: ${esc(r.invalid)} Until fixed, only this exact text is hidden.</span>`;
    const more = r.count > r.sample.length ? ` … and ${r.count - r.sample.length} more` : "";
    const list = r.sample.length ? r.sample.map(esc).join(", ") + more : "<em>none yet</em>";
    const tip = `Values this case has already listed or masked that the ${kind} covers. New matching values are hidden as they appear.`;
    return `${tag}<details class="anon-pat-count"><summary title="${escAttr(tip)}">matches ${r.count} known value${r.count === 1 ? "" : "s"}</summary>${list}</details>`;
  }

  window.anonPatternShape = anonPatternShape;
  window.anonCustomEntry = anonCustomEntry;
  window.setAnonPatternReports = setAnonPatternReports;
  window.anonPatternTag = anonPatternTag;
})();
