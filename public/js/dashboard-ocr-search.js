// Screenshot OCR full-text search — extracted from dashboard.html (issue #415, tier 3).
//
// This section reported five state escapes until the Kill Chain code that had been filed under its
// banner was reunited with renderKillChain, and KC_SEV_COLOR was moved beside SEV where the page's
// severity vocabulary lives. Neither was OCR. With both gone the block has none.
//
// It was already a self-calling IIFE, so it was always initializer work — it just called itself at
// the point in the page where it was written. In a <head> module that point is before the markup
// exists, so the page calls initOcrSearch() instead.
(function () {
  "use strict";

  function initOcrSearch() {
    const input = document.getElementById("ocrSearch");
    const clearBtn = document.getElementById("ocrSearchClear");
    const results = document.getElementById("ocrSearchResults");
    const info = document.getElementById("ocrSearchInfo");
    if (!input || !results) return;

    function highlight(snippet, query) {
      const safe = esc(snippet);
      const q = query.trim();
      if (!q) return safe;
      const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      // snippet is escaped first, so wrapping matches in <mark> can't inject markup.
      return safe.replace(rx, (m) => `<mark>${m}</mark>`);
    }

    function clear() {
      input.value = "";
      results.hidden = true;
      results.innerHTML = "";
      info.textContent = "";
      clearBtn.hidden = true;
    }

    async function run() {
      const caseId = document.getElementById("caseId").value.trim();
      const q = input.value.trim();
      clearBtn.hidden = q.length === 0;
      if (!caseId || q.length === 0) {
        results.hidden = true;
        results.innerHTML = "";
        info.textContent = "";
        return;
      }
      try {
        const r = await fetch(
          `/cases/${encodeURIComponent(caseId)}/ocr-search?q=${encodeURIComponent(q)}`,
        );
        if (r.status === 404) {
          info.textContent = "no such case";
          results.hidden = true;
          return;
        }
        if (!r.ok) {
          // Endpoint missing → server is stale (see CLAUDE.md #1 gotcha).
          info.textContent =
            r.status === 400
              ? ""
              : "search failed — restart the companion server";
          results.hidden = true;
          return;
        }
        const data = await r.json();
        const hits = data.hits || [];
        info.textContent = `${hits.length} hit(s) · ${data.indexed || 0} screenshot(s) indexed${data.enabled === false ? " · OCR search OFF" : ""}`;
        if (hits.length === 0) {
          results.innerHTML = `<div class="ocr-empty">No screenshot text matches "${esc(q)}".</div>`;
        } else {
          results.innerHTML = hits
            .map(
              (h) =>
                `<a class="ocr-hit" href="/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(h.screenshotFile)}" target="_blank" rel="noopener">` +
                `<span class="ocr-file">📎 ${esc(h.screenshotFile)}${h.matchCount > 1 ? ` · ${h.matchCount}×` : ""}</span>` +
                `<div class="ocr-snippet">${highlight(h.snippet || "", q)}</div></a>`,
            )
            .join("");
        }
        results.hidden = false;
      } catch (e) {
        info.textContent = "search failed";
        results.hidden = true;
      }
    }

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        run();
      } else if (e.key === "Escape") {
        clear();
      }
    });
    clearBtn.addEventListener("click", clear);
  }

  window.initOcrSearch = initOcrSearch;
})();
