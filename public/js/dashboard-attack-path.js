// The Attack Path panel: the model's kill-chain path as a step list (with a host-hop line above it)
// or as host swimlanes, switched by two tabs. Data in, escaped markup string out.
//
// NOT AN ES MODULE, like js/dashboard-fragments.js: esc/escAttr, proseHtml, proseSentences and
// narrativeEventAt resolve as globals at CALL time. No module-level constants either — a top-level
// `const` in a classic script joins the page's global lexical scope (see js/dashboard-text.js).
//
// The model writes the path in one of two shapes: a numbered Markdown list
// ("1. **Initial Access (T1566.001)** — May 15 09:14: …") or one paragraph of clauses joined by
// semicolons ("Initial access at 09:14 via …; then execution of …"). Both become steps. Text in
// neither shape keeps the plain prose layout, so nothing is lost when the model writes something else.
//
// Times are read as UTC, the zone the forensic timeline uses, and each one links to the most severe
// event of that minute. The Hosts view places a step on a host from evidence first (the linked
// event's host), then from a case host its text names, and only then from the step before it — and
// that last placement is drawn dashed with a tooltip, so a guess never reads as a finding.

function attackSteps(text) {
  const src = String(text == null ? "" : text).trim();
  const listed = apListItems(src);
  const chunks = listed.length >= 2 ? listed : apClauses(src);
  const steps = chunks.map((c) => apStep(c, listed.length >= 2)).filter(Boolean);
  return steps.length >= 2 ? steps : [];
}

// "1. …" / "2) …" items; a line that starts no item continues the one before it.
function apListItems(src) {
  const items = [];
  for (const line of src.split(/\r?\n/)) {
    const m = /^\s*\d{1,3}[.)]\s+(.*)$/.exec(line);
    if (m) items.push(m[1]);
    else if (items.length && line.trim()) items[items.length - 1] += " " + line.trim();
  }
  return items;
}

function apClauses(src) {
  const parts = src.split(/;\s*/).map((p) => p.trim().replace(/^(?:and\s+)?then\s+/i, "")).filter(Boolean);
  return parts.length >= 2 ? parts : [];
}

function apStep(chunk, listed) {
  const s = chunk.replace(/\*\*|__/g, "").trim();
  const techniques = s.match(/\bT\d{4}(?:\.\d{3})?\b/g) || [];
  let title = "";
  let desc = s;
  if (listed) {
    const head = /^(.+?)\s*\(\s*T\d{4}[^)]*\)\s*(?:[—–:-]\s*)?/.exec(s) || /^(.+?)\s+[—–]\s+/.exec(s);
    if (head) {
      title = head[1].trim();
      desc = s.slice(head[0].length);
    }
  }
  const when = apWhen(desc);
  if (listed && when && when.index === 0) desc = desc.slice(when.length).replace(/^\s*[:—–-]\s*/, "");
  const tactic = apTactic(title || s);
  if (!title && tactic) title = tactic.label;
  if (!title && !when) return null;
  desc = desc.trim();
  return {
    title,
    label: title || apLabel(desc, listed ? null : when),
    techniques,
    group: tactic ? tactic.group : "",
    year: when ? when.year : null,
    month: when ? when.month : null,
    day: when ? when.day : null,
    time: when ? when.time : null,
    timeEnd: when ? when.timeEnd : null,
    desc: desc.charAt(0).toUpperCase() + desc.slice(1),
  };
}

// A short name for a step that names no tactic: its own words with the time taken out, cut at a
// word near 60 characters — so no card and no heading is ever drawn empty.
function apLabel(desc, when) {
  let text = desc;
  if (when) {
    const before = text.slice(0, when.index).replace(/\b(?:at|on|by|around)\s*$/i, "");
    text = `${before} ${text.slice(when.index + when.length)}`;
  }
  text = text.replace(/\s+/g, " ").replace(/^[\s,;:—–-]+/, "").replace(/[\s.,;:]+$/, "");
  if (text.length > 60) {
    let cut = text.slice(0, 60);
    if (text[60] !== " ") cut = cut.slice(0, cut.lastIndexOf(" "));
    text = cut.trimEnd() + "…";
  }
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// The first date/time in the text. A time never matches inside an address ("203.0.113.47:443").
function apWhen(s) {
  const T = "(\\d{1,2}:\\d{2}(?::\\d{2})?)(?!\\d|:\\d)";
  const R = `(?:\\s*[–-]\\s*${T})?`;
  const MON = "(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\.?";
  const forms = [
    [new RegExp(`(\\d{4})-(\\d{2})-(\\d{2})[ T]${T}${R}`, "i"), (m) => [+m[1], +m[2], +m[3], m[4], m[5]]],
    [new RegExp(`\\b${MON}\\s+(\\d{1,2})(?:,?\\s+(\\d{4}))?,?\\s+(?:at\\s+)?${T}${R}`, "i"), (m) => [m[3] ? +m[3] : null, apMonth(m[1]), +m[2], m[4], m[5]]],
    [new RegExp(`\\b(\\d{1,2})\\s+${MON}(?:\\s+(\\d{4}))?,?\\s+(?:at\\s+)?${T}${R}`, "i"), (m) => [m[3] ? +m[3] : null, apMonth(m[2]), +m[1], m[4], m[5]]],
    [new RegExp(`(?<![\\d.:])${T}${R}`), (m) => [null, null, null, m[1], m[2]]],
  ];
  let best = null;
  for (const [re, pick] of forms) {
    const m = re.exec(s);
    if (!m || (best && m.index >= best.index)) continue;
    const [year, month, day, time, timeEnd] = pick(m);
    if (Number(time.split(":")[0]) > 23) continue;
    best = { index: m.index, length: m[0].length, year, month, day, time, timeEnd: timeEnd || null };
  }
  return best;
}

function apMonth(name) {
  return ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"].indexOf(name.slice(0, 3).toLowerCase()) + 1;
}

// The tactic a step names, most specific first. `group` sets the step's color: entry, movement
// between hosts, and harm (credentials, data, impact); c2 only marks where the C2 address comes from.
function apTactic(text) {
  const table = [
    [/initial access|phish/i, "Initial Access", "entry"],
    [/lateral/i, "Lateral Movement", "move"],
    [/credential|mimikatz|lsass/i, "Credential Access", "harm"],
    [/exfiltrat/i, "Exfiltration", "harm"],
    [/impact|ransom|encrypt|wiper/i, "Impact", "harm"],
    [/privilege|priv-?esc/i, "Privilege Escalation", ""],
    [/persist/i, "Persistence", ""],
    [/evasion/i, "Defense Evasion", ""],
    [/discover|enumerat|recon/i, "Discovery", ""],
    [/collect|staging|archiv/i, "Collection", ""],
    [/command and control|\bc2\b|beacon/i, "Command and Control", "c2"],
    [/execut/i, "Execution", ""],
  ];
  const hit = table.find(([re]) => re.test(text));
  return hit ? { label: hit[1], group: hit[2] } : null;
}

function attackPathHtml(text, events, view) {
  const steps = attackSteps(text);
  if (steps.length < 2) return proseHtml(text);
  const shown = view === "hosts" ? "hosts" : "steps";
  const placed = apPlace(steps, apContext(events));
  return (
    `<div class="ap" data-ap-view="${shown}">` +
    apTabsHtml(shown) +
    `<div class="ap-steps">${apHopsHtml(placed)}${apStepsHtml(placed)}</div>` +
    `<div class="ap-hosts">${apLanesHtml(placed)}</div></div>`
  );
}

function apContext(events) {
  const timed = [];
  for (const e of Array.isArray(events) ? events : []) {
    const ms = Date.parse((e && e.timestamp) || "");
    if (Number.isFinite(ms)) timed.push({ ms, e });
  }
  timed.sort((a, b) => a.ms - b.ms);
  const caseDates = [...new Set(timed.map((t) => new Date(t.ms).toISOString().slice(0, 10)))];
  const hosts = [...new Set(timed.map((t) => String(t.e.asset || "").trim()).filter(Boolean))];
  return { timed, caseDates, hosts, years: [...new Set(caseDates.map((d) => Number(d.slice(0, 4))))] };
}

// Each step with its day, its linked event and its host. See the file header for the host order;
// a lateral move names where it went, so its named host comes before its event's host.
function apPlace(steps, ctx) {
  let day = null;
  let host = "";
  return steps.map((step) => {
    const own = apStepDate(step, ctx);
    if (own) day = own;
    const dates = day ? [day, ...ctx.caseDates.filter((d) => d > day)] : ctx.caseDates;
    const hit = step.time ? narrativeEventAt(ctx.timed, dates, step.time) : null;
    if (hit) day = hit.at.slice(0, 10);
    const named = apNamedHost(step, ctx.hosts);
    const found = step.group === "move" ? named || (hit && hit.asset) : (hit && hit.asset) || named;
    const assumed = !found && !!host;
    if (found) host = found;
    return { step, day, hit, host: found || host, assumed };
  });
}

function apStepDate(step, ctx) {
  if (!step.month || !step.day) return null;
  const md = `${String(step.month).padStart(2, "0")}-${String(step.day).padStart(2, "0")}`;
  if (step.year) return `${step.year}-${md}`;
  const year = ctx.years.find((y) => ctx.caseDates.includes(`${y}-${md}`)) || ctx.years[0];
  return year ? `${year}-${md}` : null;
}

// A case host the step's text names, by its short name. A move keeps the LAST one it names
// ("from WKSTN to DC01" went to DC01); any other step keeps the first.
function apNamedHost(step, hosts) {
  const text = `${step.title} ${step.desc}`;
  let best = null;
  for (const h of hosts) {
    const short = h.split(".")[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`(?<![\\w-])${short}(?![\\w-])`, "gi");
    let m;
    while ((m = re.exec(text))) {
      const later = step.group === "move" ? m.index > best?.at : m.index < (best ? best.at : Infinity);
      if (!best || later) best = { host: h, at: m.index };
    }
  }
  return best ? best.host : "";
}

function apTabsHtml(shown) {
  const tab = (view, label) =>
    `<button type="button" class="ap-tab" role="tab" data-act="attackPathView" data-view="${view}" aria-selected="${shown === view}">${label}</button>`;
  return `<div class="ap-tabs" role="tablist" aria-label="Attack Path layout">${tab("steps", "Steps")}${tab("hosts", "Hosts")}</div>`;
}

// "203.0.113.47 ⇄ WKSTN-JSMITH → DC01 → FS01": the C2 addresses, then each host in the order the
// attacker first reached it. Only placed hosts count; an assumed placement never adds a hop.
function apHopsHtml(placed) {
  const hosts = [];
  for (const p of placed) if (p.host && !p.assumed && !hosts.includes(p.host)) hosts.push(p.host);
  if (!hosts.length) return "";
  const ips = [];
  for (const p of placed) {
    if (p.step.group !== "c2" && p.step.title !== "Exfiltration") continue;
    for (const ip of `${p.step.title} ${p.step.desc}`.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []) if (!ips.includes(ip)) ips.push(ip);
  }
  const ext = ips.map((ip) => `<span class="ap-ext" title="External address from a C2 or exfiltration step">${esc(ip)}</span>`).join("");
  return (
    `<div class="ap-hops">${ext}${ext ? '<span class="ap-arrow" title="Command and control">⇄</span>' : ""}` +
    hosts.map((h) => `<span class="ap-host">${esc(h)}</span>`).join('<span class="ap-arrow">→</span>') +
    `</div>`
  );
}

function apStepsHtml(placed) {
  let lastDay = null;
  const rows = placed.map((p, i) => {
    const header = p.day && p.day !== lastDay ? `<li class="ap-day">${esc(apDayLabel(p.day))}</li>` : "";
    if (p.day) lastDay = p.day;
    const s = p.step;
    const target = s.group === "move" && p.host ? `<span class="ap-host">→ ${esc(p.host)}</span>` : "";
    const tags = s.techniques.map((t) => `<span class="ap-tt">${esc(t)}</span>`).join("");
    return (
      header +
      `<li class="ap-step">${apNumHtml(s, i + 1)}<span class="ap-when">${apTimeHtml(p)}</span>` +
      `<div class="ap-what">` +
      (s.title || target || tags ? `<div class="ap-head">${s.title ? `<b>${esc(s.title)}</b>` : ""}${target}${tags}</div>` : "") +
      (s.desc ? `<div class="ap-desc">${esc(s.desc)}</div>` : "") +
      `</div></li>`
    );
  });
  return `<ol class="ap-list">${rows.join("")}</ol>`;
}

function apNumHtml(step, n) {
  const tips = {
    entry: "Entry into the environment",
    move: "Movement between hosts",
    harm: "Credential theft, data theft or impact",
  };
  const tip = tips[step.group] || "Other ATT&CK tactic";
  const cls = tips[step.group] ? ` ap-g-${step.group}` : "";
  return `<span class="ap-n${cls}" title="${escAttr(tip)}">${n}</span>`;
}

function apTimeHtml(p) {
  const s = p.step;
  if (!s.time) return "";
  const end = s.timeEnd ? `–${esc(s.timeEnd)}` : "";
  if (!p.hit) return `${esc(s.time)}${end}`;
  return (
    `<button type="button" class="ap-jump" data-act="attackPathJumpToEvent" data-id="${escAttr(p.hit.id)}" title="Open the Forensic Timeline at ${escAttr(p.hit.at)} UTC">${esc(s.time)}</button>${end}`
  );
}

function apDayLabel(iso) {
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][Number(iso.slice(5, 7)) - 1];
  return `${Number(iso.slice(8, 10))} ${mon} ${iso.slice(0, 4)}`;
}

// One row per host in the order the attacker reached it, one column per day. A step with no host
// at all (none named, no event, nothing before it) goes in a "Host not named" row.
function apLanesHtml(placed) {
  const hosts = [];
  for (const p of placed) if (!hosts.includes(p.host)) hosts.push(p.host);
  hosts.sort((a, b) => (a === "") - (b === ""));
  const days = [];
  for (const p of placed) if (!days.includes(p.day)) days.push(p.day);
  days.sort((a, b) => (a === null) - (b === null) || String(a).localeCompare(String(b)));
  const head = days.map((d) => `<th scope="col">${esc(d ? apDayLabel(d) : "No date")}</th>`).join("");
  const rows = hosts.map((h) => {
    const name = h ? `<span class="ap-host">${esc(h)}</span>` : `<span class="ap-nohost">Host not named</span>`;
    const cells = days.map((d) => `<td>${placed.filter((p) => p.host === h && p.day === d).map(apCardHtml).join("")}</td>`);
    return `<tr><th scope="row">${name}</th>${cells.join("")}</tr>`;
  });
  return `<div class="ap-lanes-wrap"><table class="ap-lanes"><thead><tr><th></th>${head}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function apCardHtml(p) {
  const s = p.step;
  const cls = ["entry", "move", "harm"].includes(s.group) ? ` ap-g-${s.group}` : "";
  const tip = p.assumed
    ? ` title="${escAttr(`Host assumed: this step names no host and has no matching event, so it stays on ${p.host} with the step before it`)}"`
    : "";
  return `<div class="ap-card${cls}${p.assumed ? " ap-assumed" : ""}"${tip}><span class="ap-ct">${apTimeHtml(p)}</span><b>${esc(s.label)}</b></div>`;
}

// The tab the analyst last picked, per browser. Storage can throw or be empty (private window,
// blocked site data); either way the panel opens on Steps.
function attackPathStoredView() {
  try {
    return localStorage.getItem("dfir.attackPathView") === "hosts" ? "hosts" : "steps";
  } catch {
    return "steps";
  }
}

// Published for the render path and the tests. EVERY function this file defines is listed, as in
// js/dashboard-fragments.js.
window.DfirAttackPath = {
  attackSteps,
  apListItems,
  apClauses,
  apStep,
  apLabel,
  apWhen,
  apMonth,
  apTactic,
  attackPathHtml,
  apContext,
  apPlace,
  apStepDate,
  apNamedHost,
  apTabsHtml,
  apHopsHtml,
  apStepsHtml,
  apNumHtml,
  apTimeHtml,
  apDayLabel,
  apLanesHtml,
  apCardHtml,
  attackPathStoredView,
};
