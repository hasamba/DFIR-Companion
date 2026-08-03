// The CISA KEV catalog panel (#99), lifted whole out of the inline script (#415, tier 3).
//
// The SECOND of the two features measured as wholly movable, and the last one until tier 2 lands.
// Of fourteen features surveyed, eleven would have split across two files because part of each is
// entangled with the shared timeline-filter state; the tagger and this are the two that are not.
// See js/dashboard-tagger.js for why half a feature in a module is worse than none.
//
// Four functions, no shared dashboard state: each reads the DOM, calls a /kev route, and writes a
// status line back. The catalog itself is global and lives on the server, which is precisely why
// this panel never touched the per-case state everything else here is tangled with.
//
// A CLASSIC SCRIPT, like every js/dashboard-*.js file. These four are wired with
// `addEventListener("click", kevImportUrl)` — a function REFERENCE resolved when the listener is
// registered — and loadKev() is called by name when the Settings KEV tab opens. Both need the name
// to be a real global by the time the inline script runs, which is what a synchronous classic
// script in <head> guarantees. See js/dashboard-escape.js for the full argument.

// --- CISA KEV catalog (#99) — global CVE cross-reference, Settings → KEV ---------------------
function loadKev() {
  const status = document.getElementById("kevStatus");
  const cnt = document.getElementById("kevCount");
  fetch("/kev").then(r => r.json()).then(j => {
    if (j.count > 0) {
      const ver = j.catalogVersion ? ` · version ${j.catalogVersion}` : "";
      const rel = j.dateReleased ? ` · released ${j.dateReleased.slice(0, 10)}` : "";
      cnt.textContent = `(${j.count.toLocaleString()} CVEs)`;
      status.textContent = `Catalog loaded${ver}${rel}.`;
    } else {
      cnt.textContent = "";
      status.textContent = "No catalog loaded yet — click \"Load from CISA feed\" or point to a local file.";
    }
  }).catch(() => { if (status) status.textContent = "Could not fetch KEV status — restart the server if this 404s."; });
}

function kevImportUrl() {
  const msg = document.getElementById("kevUrlMsg");
  msg.textContent = "fetching from CISA…";
  fetch("/kev/import-url", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })
    .then(async r => { if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "HTTP " + r.status); return r.json(); })
    .then(j => { msg.textContent = `loaded ${j.total.toLocaleString()} CVEs`; loadKev(); })
    .catch(e => { msg.textContent = "failed: " + e.message + " — check server outbound connectivity or use a local file."; });
}

function kevImportFile() {
  const path = document.getElementById("kevFilePath").value.trim();
  const msg = document.getElementById("kevFileMsg");
  if (!path) { msg.textContent = "enter a file path first"; return; }
  msg.textContent = "loading…";
  fetch("/kev/import-file", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ path }) })
    .then(async r => { if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "HTTP " + r.status); return r.json(); })
    .then(j => { msg.textContent = `loaded ${j.total.toLocaleString()} CVEs`; document.getElementById("kevFilePath").value = ""; loadKev(); })
    .catch(e => { msg.textContent = "failed: " + e.message; });
}

function kevClear() {
  if (!confirm("Clear the CISA KEV catalog? This is global (affects all cases).")) return;
  const msg = document.getElementById("kevClearMsg");
  msg.textContent = "clearing…";
  fetch("/kev", { method: "DELETE" })
    .then(async r => { if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "HTTP " + r.status); return r.json(); })
    .then(() => { msg.textContent = "cleared"; loadKev(); })
    .catch(e => { msg.textContent = "failed: " + e.message; });
}

// Published for the inline script, which registers the listeners and calls loadKev() on tab open.
window.DfirKev = {
  loadKev,
  kevImportUrl,
  kevImportFile,
  kevClear,
};
