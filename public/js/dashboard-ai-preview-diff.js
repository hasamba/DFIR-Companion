// Preview what the AI will see — the GitHub-style diff (#2531).
//
// The server lines the masking up from the real anonymizer's own value→token map
// (companion/src/analysis/ai/previewDiff.ts) and sends offsets: which clear span became which token,
// and which masked text only LOOKS unmasked. This file draws that: clear (left) and masked (right)
// aligned row by row in one grid, a changed row red on the left and green on the right, the value
// bold red and its token bold green, hover linking the two, amber for a possible leak, and a
// "Show only changed lines" view. Nothing here guesses a pair.
//
// Every value is case text — adversary-controlled — so every piece goes through esc()/escAttr()
// before it joins the HTML. IIFE-wrapped; publishes aiPreviewDiffHtml and aiPreviewDiffWire.
(function () {
  const NOUNS = {
    HOST: ["host", "hosts"],
    USER: ["user", "users"],
    IP: ["IP address", "IP addresses"],
    EXTIP: ["public IP address", "public IP addresses"],
    EMAIL: ["email address", "email addresses"],
    DOMAIN: ["domain", "domains"],
    PATH: ["path", "paths"],
    CMD: ["encoded command", "encoded commands"],
    REG: ["account SID", "account SIDs"],
    CARD: ["card number", "card numbers"],
    PHONE: ["phone number", "phone numbers"],
    NATID: ["ID number", "ID numbers"],
    PERSON: ["name", "names"],
    OTHER: ["custom term", "custom terms"],
    SECRET: ["secret", "secrets"],
  };
  const LOOKS_LIKE = {
    ip: "an IP address",
    email: "an email address",
    domain: "a domain",
    host: "a host name",
  };
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  /** "14 values replaced in 9 lines: 4 hosts, 3 users …" plus the unaligned and amber counts. */
  function summary(d) {
    const parts = [];
    const total = d.marks.length;
    if (total) {
      const kinds = Object.entries(d.counts)
        .sort((a, b) => b[1] - a[1])
        .map(([cat, n]) => plural(n, ...(NOUNS[cat] || [cat.toLowerCase(), cat.toLowerCase()])));
      const lines = d.changedLines - d.unalignedLines.length;
      parts.push(`${plural(total, "value", "values")} replaced in ${plural(lines, "line", "lines")}: ${kinds.join(", ")}.`);
    } else if (!d.unalignedLines.length) {
      parts.push("Nothing in this request was replaced.");
    }
    if (d.unalignedLines.length)
      parts.push(
        `${plural(d.unalignedLines.length, "more line changed", "more lines changed")} but could not be lined up value by value (shown with no inline marks).`,
      );
    if (d.warnings.length)
      parts.push(
        `${plural(d.warnings.length, "place looks", "places look")} unmasked (amber) — a guess from the text's shape; check them.`,
      );
    return parts.join(" ");
  }

  /** Escaped HTML for text[s, e) with the given spans (sorted, non-overlapping) wrapped in <mark>. */
  function paint(text, s, e, spans) {
    let out = "";
    let at = s;
    for (const sp of spans) {
      const a = Math.max(sp.s, s);
      const b = Math.min(sp.e, e);
      if (b < a) continue;
      out += esc(text.slice(at, a));
      out += `<mark class="${sp.cls}"${sp.attrs}>${esc(text.slice(a, b))}</mark>`;
      at = b;
    }
    return out + esc(text.slice(at, e));
  }

  function pairAttrs(d, m) {
    if (m.pair < 0) return ` title="${escAttr("a secret — removed one-way, never restored")}"`;
    const p = d.pairs[m.pair];
    return ` data-pair="${Number(m.pair)}" title="${escAttr(`${p.value} → ${p.token}`)}"`;
  }

  function warnSpan(w) {
    const tip = `looks like ${LOOKS_LIKE[w.looksLike] || "a value"} — not masked (a guess: check it)`;
    return { s: w.m[0], e: w.m[1], cls: "aip-warn", attrs: ` title="${escAttr(tip)}"` };
  }

  // Line starts of a text, as offsets: [0, after-first-\n, …].
  function lineStarts(text) {
    const out = [0];
    for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) out.push(i + 1);
    return out;
  }

  /** The rows, one per masked line. Each row knows its clear range and its marks. */
  function buildRows(call) {
    const d = call.diff;
    const C = call.clearPrompt;
    const M = call.maskedPrompt;
    const mStarts = lineStarts(M);
    const cStarts = d.mode === "lines" ? lineStarts(C) : null;
    const unaligned = new Set(d.unalignedLines);
    const rows = [];
    let j = 0; // next mark
    let w = 0; // next warning
    let delta = 0; // clear offset − masked offset, before mark j (text mode)
    let cLine = 1;
    for (let i = 0; i < mStarts.length; i++) {
      const ms = mStarts[i];
      const me = i + 1 < mStarts.length ? mStarts[i + 1] - 1 : M.length;
      const marks = [];
      while (j < d.marks.length && d.marks[j].m[0] < me) marks.push(d.marks[j++]);
      const warns = [];
      while (w < d.warnings.length && d.warnings[w].m[0] < me) warns.push(d.warnings[w++]);
      let cs;
      let ce;
      if (cStarts) {
        cs = cStarts[i];
        ce = i + 1 < cStarts.length ? cStarts[i + 1] - 1 : C.length;
      } else {
        cs = ms + delta;
        for (const m of marks) delta += m.c[1] - m.c[0] - (m.m[1] - m.m[0]);
        ce = me + delta;
      }
      const inner = (C.slice(cs, ce).match(/\n/g) || []).length;
      rows.push({
        cNo: inner ? `${cLine}–${cLine + inner}` : String(cLine),
        mNo: i + 1,
        left: paint(C, cs, ce, marks.map((m) => ({ s: m.c[0], e: m.c[1], cls: "aip-del", attrs: pairAttrs(d, m) }))),
        right: paint(
          M,
          ms,
          me,
          marks
            .map((m) => ({ s: m.m[0], e: m.m[1], cls: "aip-add", attrs: pairAttrs(d, m) }))
            .concat(warns.map(warnSpan))
            .sort((a, b) => a.s - b.s),
        ),
        changed: marks.length > 0 || unaligned.has(i),
        unaligned: unaligned.has(i),
        warned: warns.length > 0,
      });
      cLine += inner + 1;
    }
    return rows;
  }

  function rowHtml(r) {
    const cls = ["aip-row"];
    if (r.changed) cls.push("aip-chg");
    if (r.warned) cls.push("aip-warned");
    const tip = r.unaligned
      ? ` title="${escAttr("This line changed but could not be lined up value by value (it was cut to a length limit after masking).")}"`
      : "";
    return (
      `<div class="${cls.join(" ")}"${tip}><span class="aip-ln">${esc(r.cNo)}</span>` +
      `<span class="aip-cell aip-left">${r.left}</span><span class="aip-ln">${r.mNo}</span>` +
      `<span class="aip-cell aip-right">${r.right}</span></div>`
    );
  }

  const gap = (n) => `<div class="aip-gap">${esc(plural(n, "unchanged line", "unchanged lines"))} hidden</div>`;

  /** The grid. Only-changed: changed or amber rows, with a marker counting each hidden run. */
  function gridHtml(rows, onlyChanged) {
    if (!onlyChanged) return rows.map(rowHtml).join("");
    let out = "";
    let hidden = 0;
    for (const r of rows) {
      if (!r.changed && !r.warned) {
        hidden++;
        continue;
      }
      if (hidden) out += gap(hidden);
      hidden = 0;
      out += rowHtml(r);
    }
    if (hidden) out += gap(hidden);
    return out || `<div class="aip-gap">No line changed.</div>`;
  }

  function head(title) {
    return `<div class="aip-row aip-head"><span class="aip-ln"></span><span class="aip-cell">${esc(title[0])}</span><span class="aip-ln"></span><span class="aip-cell">${esc(title[1])}</span></div>`;
  }

  const HEAD = ["Clear text (never sent when masking is on)", "Masked text — sent to the provider"];

  /** The fallback: the texts side by side, tokens and amber marks on the masked side only. */
  function fallbackHtml(call) {
    const d = call.diff;
    const right = paint(
      call.maskedPrompt,
      0,
      call.maskedPrompt.length,
      d ? d.warnings.map(warnSpan) : [],
    ).replace(/ANON_[A-Z]+_\d+/g, (t) => `<mark class="aip-add">${t}</mark>`);
    return (
      `<div class="ai-preview-note">The changes could not be lined up value by value, so the two texts are shown side by side.</div>` +
      `<div class="ai-preview-panes"><div class="ai-preview-pane"><div class="asset-subhead">${esc(HEAD[0])}</div><pre>${esc(call.clearPrompt)}</pre></div>` +
      `<div class="ai-preview-pane"><div class="asset-subhead">${esc(HEAD[1])}</div><pre>${right}</pre></div></div>`
    );
  }

  /** The whole diff block for a captured call (masking on). */
  function aiPreviewDiffHtml(call, onlyChanged) {
    const d = call.diff;
    if (!d || d.mode === "none") return (d ? `<div class="aip-summary">${esc(summary(d))}</div>` : "") + fallbackHtml(call);
    return (
      `<div class="aip-bar"><div class="aip-summary">${esc(summary(d))}</div>` +
      `<label class="aip-only"><input type="checkbox" id="aiPreviewOnlyChanged"${onlyChanged ? " checked" : ""} /> Show only changed lines</label></div>` +
      `<div class="aip-diff" id="aiPreviewDiff">${head(HEAD)}${gridHtml(buildRows(call), onlyChanged)}</div>`
    );
  }

  /** Binds hover-linking and the checkbox inside `root` for the call just rendered. */
  function aiPreviewDiffWire(root, call) {
    const box = root.querySelector("#aiPreviewOnlyChanged");
    const grid = root.querySelector("#aiPreviewDiff");
    if (!box || !grid) return;
    const rows = buildRows(call);
    box.addEventListener("change", () => {
      grid.innerHTML = head(HEAD) + gridHtml(rows, box.checked);
    });
    let hot = [];
    const clear = () => {
      for (const el of hot) el.classList.remove("aip-hot");
      hot = [];
    };
    grid.addEventListener("mouseover", (e) => {
      const mark = e.target.closest && e.target.closest("mark[data-pair]");
      clear();
      if (!mark) return;
      hot = Array.from(grid.querySelectorAll(`mark[data-pair="${Number(mark.dataset.pair)}"]`));
      for (const el of hot) el.classList.add("aip-hot");
    });
    grid.addEventListener("mouseleave", clear);
  }

  window.aiPreviewDiffHtml = aiPreviewDiffHtml;
  window.aiPreviewDiffWire = aiPreviewDiffWire;
  window.aiPreviewDiffSummary = summary;
})();
