// Sigma draft export (#89) and the hunt-query modal (#415 tier 3).
//
// TWO FEATURES, ONE MODULE, because they are one flow: a finding becomes a Sigma rule, and the same
// context becomes an ES|QL / YARA / Suricata hunt you can launch and collect from the same overlay.
// The banner in the inline block named only the first of them.
//
// SHOWTOAST DID NOT COME WITH IT. It sits under the same banner and is a page-wide helper — three
// callers, one of them js/dashboard-tickets.js — so moving it here would make an unrelated module
// depend on the Sigma feature for a toast. It stays in the inline script and this file calls it
// bare, as eleven other modules already call page functions.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the parsed hunt list the modal renders from.
//
// ITS WIRING IS AN INITIALIZER even though the block itself runs nothing at load: the modal's Close
// button and backdrop were bound in the page's shared modal-wiring block, so moving the functions
// out would leave two bare references to this file evaluated as the page parses.
(function () {
  // Moved here from dashboard.html (#415). This module is the only thing that writes it and the
  // only thing that reads it — it sat under the "Bulk finding operations" banner purely because
  // that is where it happened to be typed.
  let huntLabel = "";

  // --- Per-finding "Export as Sigma draft" (#89) -----------------------------------
  // Unlike huntSigma() above (a single-indicator skeleton off ONE entity), this seeds a fuller
  // Sigma DRAFT from a whole finding: every related event's + related IOC's structured indicators
  // (merged, deduped) plus the finding's own MITRE techniques. Still deterministic templating —
  // no AI, no server round-trip — consistent with the pivot generator's "post-detection" philosophy;
  // it's a convenience export, not a certified rule, so it's explicitly `status: experimental` and
  // the analyst is expected to review/tighten it before deploying.
  // A YAML single-quoted scalar: '' escapes an embedded quote (per the YAML 1.1/1.2 spec) — the
  // only *character* escaping single-quoted style needs. But quoting alone is not enough: a
  // quoted scalar must stay on ONE line. An embedded newline continues the scalar onto the next
  // line at column 0, which YAML then reads as a new mapping key — the string breaks out of its
  // quotes and the whole rule fails to parse (or silently parses as something else). Finding
  // titles and IOC values are attacker-influenced free text, so collapse every whitespace run
  // (newlines, CRs, tabs) to a single space before quoting.
  const yqNorm = (s) => String(s).replace(/\s+/g, " ").trim();
  const yq = (s) => `'${yqNorm(s).replace(/'/g, "''")}'`;
  // Normalize + dedupe a list of indicator values, dropping any that reduce to nothing. An empty
  // selector value (`TargetFilename|contains: ''`, or a bare `Image|endswith: '\'`) matches every
  // event, which would turn the draft into a false-positive cannon rather than a detection.
  const sigmaVals = (arr, limit, fn) => {
    const out = [];
    for (const v of arr) {
      if (out.length >= limit) break;
      const t = yqNorm(fn ? fn(v) : v);
      if (t) pushUniq(out, t);
    }
    return out;
  };
  // Merge one entity's huntContextFor() output into the accumulating finding-level context.
  function mergeSigmaCtx(c, ec) {
    if (!c.host && ec.host) c.host = ec.host;
    if (!c.parent && ec.parent) c.parent = ec.parent;
    ec.hashes.forEach((v) => pushUniq(c.hashes, v));
    ec.ips.forEach((v) => pushUniq(c.ips, v));
    ec.domains.forEach((v) => pushUniq(c.domains, v));
    ec.urls.forEach((v) => pushUniq(c.urls, v));
    ec.paths.forEach((v) => pushUniq(c.paths, v));
    ec.processes.forEach((v) => pushUniq(c.processes, v));
  }
  // Gather the finding's structured indicators from its related events + related IOCs. Mirrors the
  // citeIds fallback in render(): prefer the finding's own relatedEventIds, else fall back to the
  // events that back-link to it via relatedFindingIds (findings persisted before relatedEventIds existed).
  function findingSigmaContext(f) {
    const c = {
      hashes: [],
      ips: [],
      domains: [],
      urls: [],
      paths: [],
      processes: [],
      parent: "",
      host: "",
    };
    const wantIds =
      f.relatedEventIds && f.relatedEventIds.length
        ? new Set(f.relatedEventIds)
        : null;
    const events = (DfirState.lastFt() || []).filter((e) =>
      wantIds ? wantIds.has(e.id) : (e.relatedFindingIds || []).includes(f.id),
    );
    for (const e of events) mergeSigmaCtx(c, huntContextFor("event", e));
    const iocsById = new Map(
      ((DfirState.lastState() && DfirState.lastState().iocs) || []).map((i) => [
        i.id,
        i,
      ]),
    );
    for (const id of f.relatedIocs || []) {
      const ioc = iocsById.get(id);
      if (ioc) mergeSigmaCtx(c, huntContextFor("ioc", ioc));
    }
    return c;
  }
  // Build the Sigma detection-rule draft YAML. Each indicator TYPE becomes its own selection block
  // (matching Sigma field conventions per platform hint in queryTranslate.ts) so the analyst can see
  // — and prune — exactly which signal each one contributes; condition ORs them ("1 of sel_*") since
  // these are independent pivots gathered from possibly-unrelated events, not a single AND'd pattern.
  // Returns "" when the finding carries no indicator the deterministic templates understand.
  function findingSigmaYaml(f, c) {
    const sel = [];
    // Normalize every indicator list up front, so both the selection blocks below and the
    // logsource-category choice see the same post-filter view of what the finding actually has.
    const procs = sigmaVals(c.processes, 10, baseName);
    const parentBase = yqNorm(baseName(c.parent || ""));
    const hashes = sigmaVals(c.hashes, 10);
    const ips = sigmaVals(c.ips, 20);
    const netNames = sigmaVals([...c.domains, ...c.urls], 20);
    const paths = sigmaVals(c.paths, 10, baseName);
    if (procs.length || parentBase) {
      const lines = [];
      if (procs.length) {
        lines.push(`    Image|endswith:`);
        procs.forEach((p) => lines.push(`      - ${yq("\\" + p)}`));
      }
      if (parentBase)
        lines.push(`    ParentImage|endswith: ${yq("\\" + parentBase)}`);
      sel.push({ name: "sel_process", lines });
    }
    if (hashes.length) {
      sel.push({
        name: "sel_hash",
        lines: [
          `    Hashes|contains:`,
          ...hashes.map((h) => `      - ${yq(h)}`),
        ],
      });
    }
    if (ips.length) {
      sel.push({
        name: "sel_network_ip",
        lines: [`    DestinationIp:`, ...ips.map((ip) => `      - ${yq(ip)}`)],
      });
    }
    if (netNames.length) {
      sel.push({
        name: "sel_network_domain",
        lines: [
          `    DestinationHostname|contains:`,
          ...netNames.map((v) => `      - ${yq(v)}`),
        ],
      });
    }
    if (paths.length) {
      sel.push({
        name: "sel_file_path",
        lines: [
          `    TargetFilename|contains:`,
          ...paths.map((p) => `      - ${yq(p)}`),
        ],
      });
    }
    if (!sel.length) return "";
    const hasProcessSel = procs.length || hashes.length || parentBase;
    const hasNetSel = ips.length || netNames.length;
    const category = hasProcessSel
      ? "process_creation"
      : hasNetSel
        ? "network_connection"
        : "file_event";
    const level =
      f.severity === "Critical"
        ? "critical"
        : f.severity === "High"
          ? "high"
          : f.severity === "Medium"
            ? "medium"
            : f.severity === "Low"
              ? "low"
              : "informational";
    const tags = (f.mitreTechniques || [])
      .map((t) => `  - attack.${String(t).toLowerCase()}`)
      .join("\n");
    const detection = sel
      .map((s) => `  ${s.name}:\n${s.lines.join("\n")}`)
      .join("\n");
    const condition = sel.length > 1 ? "1 of sel_*" : sel[0].name;
    const desc = String(f.description || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 400);
    return (
      [
        `title: ${yq(String(f.title || "Untitled finding").slice(0, 120))}`,
        `status: experimental`,
        desc ? `description: ${yq(desc)}` : null,
        `references:`,
        `  - ${yq(`DFIR Companion finding ${f.id}`)}`,
        `logsource:`,
        `  category: ${category}`,
        `  product: windows`,
        `detection:`,
        detection,
        `  condition: ${condition}`,
        `falsepositives:`,
        `  - Unknown`,
        `level: ${level}`,
        tags ? `tags:\n${tags}` : null,
      ]
        .filter((l) => l !== null)
        .join("\n") + "\n"
    );
  }
  // Per-finding action-row button: exports a Sigma draft, or leaves a status message when the
  // finding carries no structured indicator (nothing for the deterministic templates to seed from).
  function sigmaExportChip(id) {
    return `<button class="sigma-export-btn" data-sigma-fid="${escAttr(String(id))}" title="Export this finding as a Sigma detection-rule draft (.yml)">${ICON_DOWNLOAD}</button>`;
  }
  // Transient viewport-anchored message. The #status line lives in the toolbar, so for anything
  // triggered from a row further down the page it is scrolled out of sight — a refusal then reads
  // as a dead button. Still writes #status too, so the last action stays inspectable there.

  function exportFindingSigma(findingId) {
    const f = (
      (DfirState.lastState() && DfirState.lastState().findings) ||
      []
    ).find((x) => x.id === findingId);
    if (!f) return;
    const yaml = findingSigmaYaml(f, findingSigmaContext(f));
    if (!yaml) {
      showToast(
        "No Sigma draft: this finding has no hash / IP / domain / path / process indicators on its related events or IOCs to key a rule on.",
        "warn",
      );
      return;
    }
    const blob = new Blob([yaml], { type: "application/x-yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sigma-draft-${String(f.id).replace(/[^A-Za-z0-9_-]+/g, "_")}.yml`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(
      "Sigma draft downloaded — review before deploying (status: experimental)",
    );
  }

  // Elastic ES|QL — one piped query over ECS fields, runnable in Kibana Discover / Security.
  // Distinct from the Microsoft KQL card above (that's Kusto). Process names are lowercased
  // (TO_LOWER) to match the VQL card's case-insensitive behavior.
  function huntEsql(c) {
    const terms = [];
    if (c.hashes.length) {
      const hs = c.hashes.map((h) => hq(h.toLowerCase())).join(", ");
      terms.push(
        `process.hash.sha256 IN (${hs}) OR process.hash.md5 IN (${hs}) OR file.hash.sha256 IN (${hs}) OR file.hash.md5 IN (${hs})`,
      );
    }
    if (c.processes.length)
      terms.push(
        `TO_LOWER(process.name) IN (${c.processes.map((p) => hq(baseName(p).toLowerCase())).join(", ")})`,
      );
    if (c.parent)
      terms.push(
        `TO_LOWER(process.parent.name) == ${hq(baseName(c.parent).toLowerCase())}`,
      );
    if (c.ips.length) {
      const ips = c.ips.map(hq).join(", ");
      terms.push(`source.ip IN (${ips}) OR destination.ip IN (${ips})`);
    }
    if (c.domains.length || c.urls.length) {
      const ds = [...c.domains, ...c.urls].map(hq).join(", ");
      terms.push(
        `dns.question.name IN (${ds}) OR url.domain IN (${ds}) OR url.full IN (${ds})`,
      );
    }
    if (c.paths.length) {
      const ps = c.paths.map((p) => hq(cleanWinPath(p))).join(", ");
      terms.push(`file.path IN (${ps}) OR process.executable IN (${ps})`);
    }
    if (!terms.length) return "";
    return (
      `FROM logs-*\n${c.host ? `| WHERE host.name == ${hq(c.host)}\n` : ""}| WHERE ${terms.join("\n   OR ")}\n` +
      `| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, source.ip, destination.ip, dns.question.name, url.full, file.path\n| SORT @timestamp DESC\n| LIMIT 100`
    );
  }
  // Fingerprint length → YARA hash-module function.
  const yaraHashFn = (h) =>
    h.length === 32
      ? "hash.md5"
      : h.length === 40
        ? "hash.sha1"
        : "hash.sha256";
  // YARA rule — retro-hunt the confirmed sample across a fleet (Velociraptor yara(), THOR, etc.).
  // Hash-gated: we hold the file's fingerprint, not its bytes, so the rule keys on the hash module;
  // the analyst adds a strings: block with real patterns from the sample for variant coverage.
  function huntYara(c) {
    if (!c.hashes.length) return "";
    const name =
      (
        "Hunt_" +
        String(c.label)
          .replace(/[^A-Za-z0-9]+/g, "_")
          .replace(/^_+|_+$/g, "")
      ).slice(0, 60) || "Hunt_indicator";
    const conds = c.hashes
      .map((h) => `${yaraHashFn(h)}(0, filesize) == ${hq(h.toLowerCase())}`)
      .join(" or\n            ");
    const desc = String(c.label).replace(/"/g, "'").slice(0, 80);
    return (
      `import "hash"\n\nrule ${name}\n{\n    meta:\n        description = "Retro-hunt for confirmed indicator: ${desc}"\n        author = "DFIR Companion"\n` +
      `    // Keys on the sample's hash (its fingerprint, not its bytes). For variant coverage add a\n` +
      `    // strings: block with real byte/string patterns from the sample and OR them into the condition.\n` +
      `    condition:\n        filesize < 50MB and (\n            ${conds}\n        )\n}`
    );
  }
  // Suricata content escaping — the four content metacharacters must be hex-escaped (|HH|).
  const suriContent = (s) =>
    String(s)
      .replace(/\|/g, "|7C|")
      .replace(/\\/g, "|5C|")
      .replace(/"/g, "|22|")
      .replace(/;/g, "|3B|");
  const suriMsg = (s) => String(s).replace(/[";]/g, ""); // keep the msg string well-formed
  // Suricata/Snort-style rules — hunt the confirmed NETWORK indicator across sensors (IP/domain/URL).
  // Local sid range (9000001+); reassign to your allocated block before deploying.
  function huntSuricata(c) {
    if (!c.ips.length && !c.domains.length && !c.urls.length) return "";
    const out = [];
    let sid = 9000001;
    for (const ip of c.ips) {
      out.push(
        `alert ip $HOME_NET any -> ${ip} any (msg:"DFIR hunt - traffic to confirmed IP ${suriMsg(ip)}"; flow:to_server; sid:${sid++}; rev:1;)`,
      );
    }
    for (const d of c.domains) {
      const dd = suriContent(d),
        dm = suriMsg(d);
      out.push(
        `alert dns $HOME_NET any -> any any (msg:"DFIR hunt - DNS query for ${dm}"; dns.query; content:"${dd}"; nocase; sid:${sid++}; rev:1;)`,
      );
      out.push(
        `alert tls $HOME_NET any -> any any (msg:"DFIR hunt - TLS SNI ${dm}"; tls.sni; content:"${dd}"; nocase; sid:${sid++}; rev:1;)`,
      );
      out.push(
        `alert http $HOME_NET any -> any any (msg:"DFIR hunt - HTTP host ${dm}"; http.host; content:"${dd}"; nocase; sid:${sid++}; rev:1;)`,
      );
    }
    for (const u of c.urls) {
      let host = "",
        path = "";
      try {
        const url = new URL(u);
        host = url.hostname;
        path = (url.pathname || "") + (url.search || "");
      } catch (_) {
        host = u;
      }
      if (host)
        out.push(
          `alert tls $HOME_NET any -> any any (msg:"DFIR hunt - TLS SNI ${suriMsg(host)}"; tls.sni; content:"${suriContent(host)}"; nocase; sid:${sid++}; rev:1;)`,
        );
      if (path && path !== "/")
        out.push(
          `alert http $HOME_NET any -> any any (msg:"DFIR hunt - HTTP URI ${suriMsg(path)}"; http.uri; content:"${suriContent(path)}"; nocase; sid:${sid++}; rev:1;)`,
        );
      if (host)
        out.push(
          `alert http $HOME_NET any -> any any (msg:"DFIR hunt - HTTP host ${suriMsg(host)}"; http.host; content:"${suriContent(host)}"; nocase; sid:${sid++}; rev:1;)`,
        );
    }
    return out.join("\n");
  }

  function openHuntModal(kind, id) {
    let entity =
      kind === "ioc"
        ? ((DfirState.lastState() && DfirState.lastState().iocs) || []).find(
            (i) => String(i.id) === String(id),
          )
        : (DfirState.lastFt() || []).find((e) => String(e.id) === String(id));
    // Super-timeline rows may reference a RAW super event that was never promoted into the
    // forensic state, so it's absent from DfirState.lastFt() — fall back to the cached super page data.
    if (!entity && kind === "event") {
      entity = (
        (DfirState.lastSuperData() && DfirState.lastSuperData().events) ||
        []
      ).find((e) => String(e.id) === String(id));
    }
    if (!entity) return;
    const c = huntContextFor(kind, entity);
    if (kind === "event" && entity.mitreTechniques)
      c._mitre = entity.mitreTechniques;
    huntLabel = c.label;
    document.getElementById("huntTitle").textContent = "Hunt queries";
    document.getElementById("huntSub").textContent = c.label;
    // [platformKey, label, query]. The key gates the card against the server's enabled-platforms
    // allowlist (DFIR_HUNT_PLATFORMS, delivered via /health) — keys must match huntPlatforms.ts.
    const cards = [
      ["velociraptor", "Velociraptor — hunt (all clients)", huntVql(c)],
      [
        "velociraptor",
        "Velociraptor — notebook (one client)",
        huntVqlNotebook(c),
      ],
      ["defender", "Microsoft Defender / Sentinel (KQL)", huntKql(c)],
      ["elastic", "Elastic / Kibana (ES|QL)", huntEsql(c)],
      ["splunk", "Splunk (SPL)", huntSpl(c)],
      ["sigma", "Sigma rule skeleton (YAML)", huntSigma(c)],
      ["yara", "YARA rule (retro-hunt the sample)", huntYara(c)],
      ["suricata", "Suricata rules (network)", huntSuricata(c)],
    ].filter(([key, , q]) => q && q.trim() && enabledHuntPlatforms.has(key));
    const body = document.getElementById("huntBody");
    body.innerHTML = !hasAny(c)
      ? "<div data-safe-style='color:var(--text-muted);font-size:12px'>This entity carries no hash / IP / domain / path / process to pivot on. Add structured fields (or tag it) to enable hunt queries.</div>"
      : !cards.length
        ? "<div data-safe-style='color:var(--text-muted);font-size:12px'>No hunt platforms are enabled for this entity. Platforms are limited by <code>DFIR_HUNT_PLATFORMS</code> in the server environment — clear or widen it to show more.</div>"
        : cards
            .map(([, tool, query], idx) => {
              // The Velociraptor HUNT card is runnable when the API is configured: editable VQL + a Run
              // button that launches it across all clients. The notebook card is copy-only (it runs in a
              // Velociraptor notebook, not via this server-side hunt path).
              const runnable =
                tool.startsWith("Velociraptor — hunt") && veloEnabled;
              const head =
                `<div class="hunt-card-head"><span>${esc(tool)}</span><div>` +
                (runnable
                  ? `<button class="hunt-run" data-idx="${idx}" title="Launch a hunt that runs this VQL on ALL enrolled Velociraptor clients">▶ Run hunt (all clients)</button>`
                  : "") +
                `<button class="hunt-copy" data-idx="${idx}">Copy</button></div></div>`;
              const content = runnable
                ? `<textarea class="hunt-vql-edit" id="huntQ${idx}" spellcheck="false">${esc(query)}</textarea>`
                : `<pre id="huntQ${idx}">${esc(query)}</pre>`;
              return `<div class="hunt-card">${head}${content}${runnable ? `<div class="hunt-run-res" id="huntRunRes${idx}"></div>` : ""}</div>`;
            })
            .join("");
    body.innerHTML += sigmaCompileCardHtml();
    bindSigmaCard();
    body.querySelectorAll(".hunt-copy").forEach(
      (b) =>
        (b.onclick = () => {
          navigator.clipboard
            .writeText(huntText(b.dataset.idx))
            .then(() => {
              b.textContent = "Copied ✓";
              b.classList.add("copied");
              setTimeout(() => {
                b.textContent = "Copy";
                b.classList.remove("copied");
              }, 1500);
            })
            .catch(() => {
              b.textContent = "copy failed";
            });
        }),
    );
    body
      .querySelectorAll(".hunt-run")
      .forEach((b) => (b.onclick = () => runHunt(b.dataset.idx)));
    document.getElementById("huntOverlay").classList.add("open");
  }
  function closeHuntModal() {
    document.getElementById("huntOverlay").classList.remove("open");
  }
  // Read a hunt card's query text (textarea when runnable/editable, else the <pre>).
  function huntText(idx) {
    const el = document.getElementById("huntQ" + idx);
    return el.tagName === "TEXTAREA" ? el.value : el.textContent;
  }
  // Launch a HUNT that runs the card's VQL on ALL enrolled Velociraptor clients, then poll for the
  // rows endpoints return (results arrive asynchronously as clients check in).
  function runHunt(idx) {
    launchHuntInto(
      huntText(idx),
      huntLabel,
      document.getElementById("huntRunRes" + idx),
      document.querySelector('.hunt-run[data-idx="' + idx + '"]'),
    );
  }
  // `pollHuntResults` was `poll`. The "leaves nothing behind" census compares bindings at ANY depth
  // on both sides, and the page has its own unrelated `const poll` inside another function, so the
  // plain name read as a leftover here. Second time this session — see wireToolRules. The gate's
  // false positive is real: a duplicate that matters is one that can shadow.
  //
  // Shared launch+poll for any VQL hunt (the per-entity hunt modal AND the AI-suggested fleet
  // hunts both deploy through the same launchHunt path). `res` is the element to render status into;
  // `btn` (optional) is disabled while in flight. When `ctx` ({caseId,title,source,mitre}) is given
  // — i.e. deploying an AI SUGGESTION — it routes through the case-scoped /deploy-hunt so the hunt is
  // recorded in the feedback loop (#157); the bare per-entity hunt uses the global /velociraptor/hunt.
  function launchHuntInto(vql, description, res, btn, ctx) {
    if (!res) return;
    res.innerHTML =
      "<div data-safe-style='color:var(--text-muted);font-size:12px'>launching hunt on all clients…</div>";
    if (btn) btn.disabled = true;
    const recorded = ctx && ctx.caseId;
    const url = recorded
      ? `/cases/${encodeURIComponent(ctx.caseId)}/velociraptor/deploy-hunt`
      : "/velociraptor/hunt";
    // #14: link this hunt to a hypothesis — either the caller set it on ctx, or the analyst armed the
    // "🎯 test via hunt" button (consumed once here). An empty result then exhausts that hypothesis.
    // #803: a live-snapshot hunt (a compiled Sigma rule) is never linked to a hypothesis — its
    // empty result is not negative evidence — so the armed "test via hunt" is left for a real one.
    const snapshot = !!(ctx && ctx.coverage === "snapshot");
    const relatedHypothesisId = snapshot
      ? undefined
      : (ctx && ctx.relatedHypothesisId) ||
        (recorded ? consumePendingHuntHypothesis() : undefined);
    const body = recorded
      ? {
          vql,
          title: ctx.title || description || "DFIR fleet hunt",
          description: description || "DFIR hunt",
          source: ctx.source || "fleet",
          mitreTechniques: ctx.mitre || [],
          ...(relatedHypothesisId ? { relatedHypothesisId } : {}),
          ...(snapshot ? { coverage: "snapshot" } : {}),
        }
      : { vql, description: description || "DFIR hunt" };
    fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          res.innerHTML = `<div data-safe-style="color:var(--sev-high);font-size:12px">error: ${esc(j.error || "hunt failed")}</div>`;
          return;
        }
        const link = j.guiUrl
          ? ` · <a href="${escAttr(j.guiUrl)}" target="_blank" rel="noopener" data-safe-style="color:var(--accent)">open in Velociraptor ↗</a>`
          : "";
        const snapNote = snapshot
          ? ` · <span data-safe-style="color:var(--text-muted)">live snapshot — an empty result is not a miss and is not linked to a hypothesis</span>`
          : "";
        res.innerHTML =
          `<div data-safe-style="font-size:12px;margin-bottom:6px">🎯 Hunt <strong>${esc(j.huntId)}</strong> launched on all clients · ${esc(j.state)}${link}${snapNote} ` +
          `<button class="hunt-refresh" data-hid="${escAttr(j.huntId)}" data-art="${escAttr(j.artifact)}" data-src="${escAttr((j.sources || []).join(","))}">↻ Refresh results</button></div>` +
          `<div class="hunt-results-rows" data-safe-style="color:var(--text-muted);font-size:12px">waiting for endpoints to respond…</div>`;
        const rb = res.querySelector(".hunt-refresh");
        const target = res.querySelector(".hunt-results-rows");
        rb.onclick = () => fetchHuntResults(rb, target);
        // Auto-poll a few times since hunt results trickle in as clients check in.
        let tries = 0;
        const pollHuntResults = () => {
          tries++;
          fetchHuntResults(rb, target).then((n) => {
            if (!n && tries < 6) setTimeout(pollHuntResults, 5000);
          });
        };
        setTimeout(pollHuntResults, 3000);
      })
      .catch(
        (e) =>
          (res.innerHTML = `<div data-safe-style="color:var(--sev-high);font-size:12px">error: ${esc(e.message)} — restart the companion server if this 404s</div>`),
      )
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  // Fetch a launched hunt's collected results into `target`; resolves to the row count.
  function fetchHuntResults(rb, target) {
    const huntId = rb.dataset.hid,
      artifact = rb.dataset.art;
    const sources = (rb.dataset.src || "").split(",").filter(Boolean);
    target.innerHTML =
      "<span data-safe-style='color:var(--text-muted)'>fetching results…</span>";
    return fetch("/velociraptor/hunt-results", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ huntId, artifact, sources }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          target.innerHTML = `<div data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "failed")}</div>`;
          return 0;
        }
        const n = (j.rows || []).length;
        target.innerHTML = n
          ? renderVqlRows(j)
          : "<span data-safe-style='color:var(--text-muted)'>no results yet — endpoints report on their next poll. Click ↻ to refresh.</span>";
        return n;
      })
      .catch((e) => {
        target.innerHTML = `<div data-safe-style="color:var(--sev-high)">error: ${esc(e.message)}</div>`;
        return 0;
      });
  }

  // ── Sigma rule → VQL (#798) ─────────────────────────────────────────────────────────────────
  // The paste card lives in the hunt modal. Compile is offline (POST /cases/:id/sigma/compile) and
  // deterministic — no AI. Only Run needs the Velociraptor API, and it goes through launchHuntInto
  // with the case context so the hunt is recorded in the hunting profile like any other fleet
  // hunt. The card is gated on the `velociraptor` hunt platform, not on `sigma`: it consumes a
  // Sigma rule and produces VQL, so it is a Velociraptor surface.
  function sigmaCompileEnabled() {
    return enabledHuntPlatforms.has("velociraptor");
  }
  function sigmaCompileCardHtml(prefill) {
    if (!sigmaCompileEnabled()) return "";
    return (
      `<div class="hunt-card sigma-compile-card">` +
      `<div class="hunt-card-head"><span>Sigma rule → Velociraptor hunt</span><div>` +
      `<button class="sigma-compile-go" id="sigmaCompileBtn" title="Compile this Sigma rule to VQL — deterministic, no AI">Compile</button></div></div>` +
      `<textarea class="hunt-vql-edit" id="sigmaYamlIn" spellcheck="false" placeholder="Paste a Sigma rule (YAML). Supported logsource categories: process_creation, network_connection, file_event, registry_*">${esc(prefill || "")}</textarea>` +
      `<div class="hunt-run-res" id="sigmaCompileRes"></div></div>`
    );
  }
  // What the analyst sees under the paste box: the VQL card, the refusal list, or one error line.
  // Refusal lines are written by the parser and the compiler for the analyst and rendered as text.
  function sigmaCompileResultHtml(result) {
    if (!result || result.error)
      return `<div data-safe-style="color:var(--sev-high);font-size:12px">error: ${esc((result && result.error) || "compile failed")}</div>`;
    if (!result.ok) {
      const items = (result.refusals || [])
        .map((r) => `<li><code>${esc(r.path)}</code> — ${esc(r.message)}</li>`)
        .join("");
      return (
        `<div class="sigma-refusals"><div data-safe-style="font-size:12px;margin-bottom:4px">The Companion cannot express this rule as VQL. Nothing was compiled.</div>` +
        `<ul>${items}</ul></div>`
      );
    }
    const run = veloEnabled
      ? `<button class="hunt-run" id="sigmaRunBtn" title="Launch a hunt that runs this VQL on ALL enrolled Velociraptor clients">▶ Run hunt (all clients)</button>`
      : `<span data-safe-style="color:var(--text-muted);font-size:11px">Velociraptor API not configured — copy the VQL, or set the API config path in Settings → Integrations</span>`;
    return (
      `<div class="sigma-coverage" data-safe-style="font-size:12px;margin:6px 0">Compiled <strong>${esc(result.title || "rule")}</strong> → ${esc(result.coverage || "")}</div>` +
      `<textarea class="hunt-vql-edit" id="sigmaVqlOut" spellcheck="false">${esc(result.vql)}</textarea>` +
      `<div data-safe-style="display:flex;gap:6px;align-items:center;margin-top:6px"><button class="sigma-compile-go" id="sigmaCopyBtn">Copy</button>${run}</div>` +
      `<div class="hunt-run-res" id="sigmaRunRes"></div>`
    );
  }
  function bindSigmaResult(res, j, caseId) {
    if (!j || !j.ok) return;
    const copy = res.querySelector("#sigmaCopyBtn");
    const out = res.querySelector("#sigmaVqlOut");
    if (copy && out)
      copy.onclick = () =>
        navigator.clipboard
          .writeText(out.value)
          .then(() => {
            copy.textContent = "Copied ✓";
            copy.classList.add("copied");
            setTimeout(() => {
              copy.textContent = "Copy";
              copy.classList.remove("copied");
            }, 1500);
          })
          .catch(() => {
            copy.textContent = "copy failed";
          });
    const run = res.querySelector("#sigmaRunBtn");
    if (run && out)
      run.onclick = () =>
        launchHuntInto(out.value, `Sigma: ${j.title || "rule"}`, res.querySelector("#sigmaRunRes"), run, {
          caseId,
          title: j.title || "Sigma rule",
          source: "fleet",
          mitre: j.mitreTechniques || [],
          ...(j.snapshot ? { coverage: "snapshot" } : {}),
        });
  }
  function compileSigmaRule() {
    const box = document.getElementById("sigmaYamlIn");
    const res = document.getElementById("sigmaCompileRes");
    const btn = document.getElementById("sigmaCompileBtn");
    if (!box || !res) return;
    const caseEl = document.getElementById("caseId");
    const caseId = ((caseEl && caseEl.value) || "").trim();
    const yaml = box.value;
    if (!caseId) {
      res.innerHTML = sigmaCompileResultHtml({ error: "connect to a case first" });
      return;
    }
    if (!yaml.trim()) {
      res.innerHTML = sigmaCompileResultHtml({ error: "paste a Sigma rule first" });
      return;
    }
    if (btn) btn.disabled = true;
    fetch(`/cases/${encodeURIComponent(caseId)}/sigma/compile`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ yaml }),
    })
      .then((r) => r.json())
      .then((j) => {
        res.innerHTML = sigmaCompileResultHtml(j);
        bindSigmaResult(res, j, caseId);
      })
      .catch((e) => {
        res.innerHTML = sigmaCompileResultHtml({ error: e.message });
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  function bindSigmaCard() {
    const btn = document.getElementById("sigmaCompileBtn");
    if (btn) btn.onclick = compileSigmaRule;
  }
  // Open the modal on the Sigma card alone, prefilled with a rule, and compile it at once. The two
  // shortcuts — the per-finding chip and the query translator's Sigma card — both land here.
  function openSigmaCompileWith(yaml, label) {
    huntLabel = label || "Sigma rule";
    document.getElementById("huntTitle").textContent = "Sigma rule → Velociraptor hunt";
    document.getElementById("huntSub").textContent = huntLabel;
    document.getElementById("huntBody").innerHTML =
      sigmaCompileCardHtml(yaml) ||
      "<div data-safe-style='color:var(--text-muted);font-size:12px'>Velociraptor is not an enabled hunt platform (<code>DFIR_HUNT_PLATFORMS</code>), so there is nothing to compile to.</div>";
    bindSigmaCard();
    document.getElementById("huntOverlay").classList.add("open");
    if (yaml && sigmaCompileEnabled()) compileSigmaRule();
  }
  // Per-finding action-row chip, next to "Export as Sigma draft": the same draft, compiled.
  function sigmaCompileChip(id) {
    if (!sigmaCompileEnabled()) return "";
    return `<button class="sigma-compile-btn" data-sigma-cid="${escAttr(String(id))}" title="Compile this finding's Sigma draft to Velociraptor VQL and open it in the hunt modal">${ICON_HUNT}</button>`;
  }
  function compileFindingSigma(findingId) {
    const f = ((DfirState.lastState() && DfirState.lastState().findings) || []).find(
      (x) => x.id === findingId,
    );
    if (!f) return;
    const yaml = findingSigmaYaml(f, findingSigmaContext(f));
    if (!yaml) {
      showToast(
        "No Sigma draft: this finding has no hash / IP / domain / path / process indicators on its related events or IOCs to key a rule on.",
        "warn",
      );
      return;
    }
    openSigmaCompileWith(yaml, f.title || String(f.id));
  }

  // The two controls the page's shared modal-wiring block used to bind.
  function initHuntModal() {
    document.getElementById("huntClose").onclick = closeHuntModal;
    document.getElementById("huntOverlay").addEventListener("click", (e) => {
      if (e.target.id === "huntOverlay") closeHuntModal();
    });
      // Capture phase, so the chip wins over the finding row's own click handlers and the row does
    // not toggle under the analyst's cursor.
    document.addEventListener(
      "click",
      (e) => {
        const chip = e.target.closest && e.target.closest(".sigma-compile-btn");
        if (!chip) return;
        e.stopPropagation();
        e.preventDefault();
        compileFindingSigma(chip.getAttribute("data-sigma-cid"));
      },
      true,
    );
  }

  window.exportFindingSigma = exportFindingSigma;
  // Published for the Sigma → VQL round-trip test (#797): the compiler must accept the draft
  // this function writes, and the only honest way to prove that is to run the real function.
  window.findingSigmaYaml = findingSigmaYaml;
  window.sigmaExportChip = sigmaExportChip;
  window.openHuntModal = openHuntModal;
  window.closeHuntModal = closeHuntModal;
  window.launchHuntInto = launchHuntInto;
  window.initHuntModal = initHuntModal;
  window.sigmaCompileCardHtml = sigmaCompileCardHtml;
  window.sigmaCompileResultHtml = sigmaCompileResultHtml;
  window.compileSigmaRule = compileSigmaRule;
  window.openSigmaCompileWith = openSigmaCompileWith;
  window.sigmaCompileChip = sigmaCompileChip;
  window.compileFindingSigma = compileFindingSigma;
})();
