// Memory Next Steps (#101) — what to look at next in a memory image, ranked by severity
// (#415 tier 3).
//
// NO INITIALIZER: the only load-time statement in its banner range was the host-ranking guard an
// earlier extraction left there, and that stays in the page.
(function () {
  // ── Memory Next Steps (#101) ──────────────────────────────────────────────────────────
  // AI-proposed next Volatility 3 commands for an iterative memory investigation. The section is
  // shown only when the case has imported Volatility/Rekall evidence (toggled from render()). On
  // demand (an AI call): the analyst clicks "Suggest next steps", reviews each anomaly + command,
  // and copies the command to run in their own Volatility. Ephemeral — not persisted.
  const MNS_SEV_COLOR = {
    Critical: "#ff5c5c",
    High: "#ff9f43",
    Medium: "#ffd93b",
    Low: "#6bcb77",
    Info: "#6aa9ff",
  };
  const MNS_SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

  // Show the section iff the (in-scope, non-FP) timeline has any Volatility/Rekall events.
  function toggleMemNextSteps(ft) {
    const sec = document.getElementById("sec-mem-nextsteps");
    if (!sec) return;
    const hasMem = (ft || []).some((e) =>
      (e.sources || []).some((s) => s === "Volatility" || s === "Rekall"),
    );
    // Open/close this section's data gate, then let applySectionsVis() own the actual display so
    // the user's Settings choice is respected too — it hides the section when EITHER the analyst
    // switched it off or the case has no memory evidence.
    sec.dataset.gateOpen = hasMem ? "1" : "";
    applySectionsVis();
  }

  function resetMemNextSteps() {
    const el = document.getElementById("memNextSteps");
    if (el) el.innerHTML = "";
    const msg = document.getElementById("memNextStepsMsg");
    if (msg) msg.textContent = "";
  }

  function doMemNextSteps() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const btn = document.getElementById("memNextStepsBtn");
    const msg = document.getElementById("memNextStepsMsg");
    const el = document.getElementById("memNextSteps");
    if (!el) return;
    if (btn) btn.disabled = true;
    if (msg)
      msg.textContent = "thinking… (one AI call over the memory evidence)";
    el.innerHTML = "";
    fetch(`/cases/${caseId}/memory/next-steps`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) msg.textContent = "";
          el.innerHTML = `<div class="mns-empty" data-safe-style="color:var(--sev-high)">error: ${esc(j.error || "could not generate next steps")} — restart the companion server if this 404s</div>`;
          return;
        }
        renderMemNextSteps(j.suggestions || []);
        const n = (j.suggestions || []).length;
        if (msg) msg.textContent = n ? `${n} next step(s) proposed` : "";
      })
      .catch((e) => {
        if (msg) msg.textContent = "";
        el.innerHTML = `<div class="mns-empty" data-safe-style="color:var(--sev-high)">error: ${esc(e.message)}</div>`;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }

  function renderMemNextSteps(suggestions) {
    const el = document.getElementById("memNextSteps");
    if (!el) return;
    if (!suggestions.length) {
      el.innerHTML = `<div class="mns-empty">No next steps proposed — the AI found nothing anomalous in the imported memory evidence to dig into. Import more Volatility 3 / Rekall plugin output (pstree, netscan, malfind, cmdline) and try again.</div>`;
      return;
    }
    const ordered = [...suggestions].sort(
      (a, b) =>
        (MNS_SEV_RANK[a.severity] ?? 9) - (MNS_SEV_RANK[b.severity] ?? 9),
    );
    const caveat = `<div class="mns-caveat">⚠ AI-suggested commands — review before running. Substitute <code>&lt;image&gt;</code> with your memory image path. Most steps print a table you can paste/Import back here; a <code>--dump</code> / <code>dumpfiles</code> step writes a raw <code>.dmp</code> for offline analysis (YARA / capa / sandbox) — import those results, not the binary.</div>`;
    const cards = ordered
      .map((s, idx) => {
        const sev = s.severity || "Medium";
        const sevColor = MNS_SEV_COLOR[sev] || "#9aa4b2";
        const sevBadge = `<span class="mns-sev" data-safe-style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55">${esc(sev)}</span>`;
        const pid = s.pid
          ? `<span class="mns-pid">PID ${esc(s.pid)}</span>`
          : "";
        const techs = (s.mitreTechniques || [])
          .map((t) => {
            const u = attackUrl(t);
            return u
              ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="mns-tech">${esc(t)}</a>`
              : `<span class="mns-tech">${esc(t)}</span>`;
          })
          .join("");
        const rationale = s.rationale
          ? `<div class="mns-rationale">${esc(s.rationale)}</div>`
          : "";
        return (
          `<div class="mns-card">` +
          `<div class="mns-head"><span class="mns-anomaly">${esc(s.anomaly)}</span>${sevBadge}${pid}</div>` +
          rationale +
          (techs ? `<div class="mns-techs">${techs}</div>` : "") +
          `<textarea class="mns-cmd" id="mnsC${idx}" spellcheck="false" rows="1">${esc(s.command)}</textarea>` +
          `<div class="mns-actions"><button class="mns-copy" data-idx="${idx}">Copy command</button></div>` +
          `</div>`
        );
      })
      .join("");
    el.innerHTML = caveat + `<div class="mns-list">${cards}</div>`;
    el.querySelectorAll(".mns-copy").forEach(
      (b) =>
        (b.onclick = () => {
          const q = document.getElementById("mnsC" + b.dataset.idx);
          navigator.clipboard
            .writeText(q ? q.value : "")
            .then(() => {
              b.textContent = "Copied ✓";
              b.classList.add("copied");
              setTimeout(() => {
                b.textContent = "Copy command";
                b.classList.remove("copied");
              }, 1500);
            })
            .catch(() => {
              b.textContent = "copy failed";
            });
        }),
    );
  }

  window.toggleMemNextSteps = toggleMemNextSteps;
  window.resetMemNextSteps = resetMemNextSteps;
  window.doMemNextSteps = doMemNextSteps;
})();
