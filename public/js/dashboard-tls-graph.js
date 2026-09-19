// TLS Relationships (#997, the cross-upload half).
//
// The case's TLS-graph rows — one per (sensor, identity) per upload — merged by identity at read
// time on the server (GET /cases/:id/tls-graph): a certificate, a name, a client certificate, a
// JA3 or a JA3S, with the union of what every sensor saw beside it and, per observation, which
// sensor and upload saw it and when. Drawn as a graph (the shared Cytoscape chrome the Asset graph
// uses) and listed as a table. A cluster is a lead, never a conclusion; a fingerprint is never an
// operator; a JA3/JA3S is a library signature. Nothing here contacts observed infrastructure.
//
// An IIFE for the same reason as js/dashboard-campaign-scope.js: this feature owns state.
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  let graph = { nodes: [], notShown: 0, rowsRead: 0, folded: 0 };
  let currentCaseId = "";
  let loadGen = 0;
  let status = "loading"; // "loading" | "loaded" | "error": a failed request is never an empty case
  let gv = null;
  const kindsEnabled = new Set(["certificate", "name", "client-certificate", "ja3", "ja3s", "server"]);

  /** The drawn graph is bounded; the table below lists every node the route returned. */
  const DRAWN_NODES_MAX = 400;
  const DRAWN_EDGES_MAX = 1200;
  const KIND_LABEL = {
    certificate: "certificate",
    name: "name",
    "client-certificate": "client certificate",
    ja3: "JA3",
    ja3s: "JA3S",
    server: "server",
  };
  const KIND_COLOR = {
    certificate: "#e0b45c",
    name: "#6cb6ff",
    "client-certificate": "#c98bff",
    ja3: "#7fd18c",
    ja3s: "#4fb3a8",
    server: "#9aa6b8",
  };

  const ends = (h) => (h && h.length > 12 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h || "");
  const shortId = (n) => (n.kind === "name" ? n.id : ends(n.id));
  const day = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") : "?");
  const num = (v) => Number(v || 0).toLocaleString("en-US");
  const edgeWords = (e, one, many) =>
    !e || !e.count
      ? "—"
      : `${num(e.count)}${e.atLeast ? "+" : ""} ${e.count === 1 && !e.atLeast ? one : many}` +
        (e.listed && e.listed.length ? ` — ${e.listed.slice(0, 3).map(esc).join(", ")}${e.count > 3 ? " …" : ""}` : "");

  function glyph(kind) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 22 22"><circle cx="11" cy="11" r="7" fill="${KIND_COLOR[kind] || "#888"}" stroke="#0f1115" stroke-width="1.5"/></svg>`;
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
  }

  function buildElements() {
    const els = [];
    const ids = new Set();
    let edges = 0;
    const addNode = (id, kind, label, full, extra) => {
      if (ids.has(id) || ids.size >= DRAWN_NODES_MAX) return ids.has(id);
      ids.add(id);
      els.push({ data: { id, name: label, full, kind, glyph: glyph(kind), ...(extra || {}) } });
      return true;
    };
    const addEdge = (a, b, label) => {
      if (edges >= DRAWN_EDGES_MAX || !ids.has(a) || !ids.has(b)) return;
      edges += 1;
      els.push({ data: { id: `te:${a}|${b}|${label}`, source: a, target: b, label } });
    };
    // Nodes the route returned first, so a drawn name is the merged name node when one exists.
    for (const n of graph.nodes) {
      if (!kindsEnabled.has(n.kind)) continue;
      addNode(`${n.kind}:${n.id}`, n.kind, shortId(n), `${KIND_LABEL[n.kind]} ${n.id}`, { node: n });
    }
    for (const n of graph.nodes) {
      if (!kindsEnabled.has(n.kind)) continue;
      const me = `${n.kind}:${n.id}`;
      if (!ids.has(me)) continue;
      if (n.kind !== "name" && kindsEnabled.has("name"))
        for (const name of n.names.listed) {
          addNode(`name:${name}`, "name", name, `name ${name}`);
          addEdge(me, `name:${name}`, n.kind === "certificate" ? "presented under" : "under");
        }
      if (kindsEnabled.has("server"))
        for (const s of n.servers.listed) {
          addNode(`server:${s}`, "server", s, `server ${s}`);
          addEdge(me, `server:${s}`, n.kind === "ja3s" ? "presented by" : n.kind === "client-certificate" ? "presented to" : "at");
        }
      if (n.kind === "name" && kindsEnabled.has("certificate"))
        for (const c of n.certificates.listed) {
          addNode(`certificate:${c}`, "certificate", ends(c), `certificate ${c}`);
          addEdge(`certificate:${c}`, me, "presented under");
        }
    }
    return els;
  }

  const TLS_STYLE = [
    {
      selector: "node",
      style: {
        "background-image": "data(glyph)",
        "background-color": "#0f1115",
        "background-opacity": 0,
        "background-fit": "none",
        "background-clip": "none",
        width: 24,
        height: 24,
        label: "data(name)",
        color: "#cbd3df",
        "font-size": "10px",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 3,
      },
    },
    { selector: "edge", style: { width: 1, "line-color": "#3a4456", "curve-style": "bezier", "target-arrow-shape": "none" } },
    { selector: ".gv-dim", style: { opacity: 0.1 } },
  ];

  function observationRows(n) {
    return n.observations
      .map(
        (o) =>
          `<tr><td>${esc(o.sensor)}</td><td>${o.upload ? esc(o.upload.id.slice(0, 12)) + (o.upload.importedAt ? ` <span data-safe-style="color:var(--text-muted)">(${esc(day(o.upload.importedAt))})</span>` : "") : "<span data-safe-style='color:var(--text-muted)'>not recorded</span>"}</td><td>${esc(day(o.first))} → ${esc(day(o.last))}</td><td>${num(o.sessions)}</td><td>${edgeWords(o.names, "name", "names")}</td><td>${edgeWords(o.servers, "server", "servers")}</td><td>${edgeWords(o.clientAddresses, "client address", "client addresses")}</td><td>${o.leads.map((l) => esc(l.words)).join("<br>") || "—"}</td></tr>`,
      )
      .join("");
  }

  function nodeDetails(n) {
    const facts = n.crossFacts.map((f) => `<li>${esc(f)}</li>`).join("");
    const leads = n.leads.map((l) => `<li><b>${esc(l.sensor)}</b>: ${esc(l.words)}</li>`).join("");
    const cert = n.certificate
      ? `<div data-safe-style="font-size:12px">Certificate record: ${n.certificate.subject ? `subject ${esc(n.certificate.subject)}; ` : ""}${n.certificate.issuer ? `issuer ${esc(n.certificate.issuer)}; ` : ""}${n.certificate.notBefore || n.certificate.notAfter ? `valid ${esc(day(n.certificate.notBefore))} – ${esc(day(n.certificate.notAfter))}` : ""}</div>`
      : "";
    return `<div data-safe-style="font-size:12px;margin:4px 0">${num(n.sessions)} session record(s) on ${num(n.sensors)} sensor(s), ${num(n.uploads)} upload(s); observed ${esc(day(n.first))} → ${esc(day(n.last))}</div>
      ${cert}
      ${facts ? `<div data-safe-style="font-size:12px">Between sensors:<ul>${facts}</ul></div>` : ""}
      ${leads ? `<div data-safe-style="font-size:12px">Leads (a cluster proves nothing on its own):<ul>${leads}</ul></div>` : ""}
      <table data-safe-style="margin-top:4px;font-size:12px"><thead><tr><th>Sensor</th><th>Upload</th><th>Observed</th><th>Sessions</th><th>Names</th><th>Servers</th><th>Client addresses</th><th>Leads</th></tr></thead><tbody>${observationRows(n)}${n.observationsNotShown ? `<tr><td colspan="8">+${num(n.observationsNotShown)} observation(s) not shown</td></tr>` : ""}</tbody></table>`;
  }

  function showNodePanel(node) {
    const p = document.getElementById("tlsGraphSidePanel");
    if (!p) return;
    const n = node.data("node");
    p.innerHTML = `<div><b>${esc(node.data("full"))}</b></div>${n ? nodeDetails(n) : `<div data-safe-style="font-size:12px;color:var(--text-muted)">Drawn from another node's edge list; it has no merged row of its own (seen with one identity only).</div>`}<button type="button" class="lg-close" id="tlsGraphSideClose">✕ Close</button>`;
    p.style.display = "block";
    const close = document.getElementById("tlsGraphSideClose");
    if (close)
      close.onclick = () => {
        p.style.display = "none";
        if (gv) gv.dimExcept(null);
      };
  }

  function ensureGV() {
    if (gv) return gv;
    if (!window.DfirGraphView) return null;
    gv = window.DfirGraphView.createGraphView({
      graphId: "tls",
      container: document.getElementById("tlsGraph"),
      wrap: document.getElementById("tlsGraphWrap"),
      caseIdEl: document.getElementById("caseId"),
      exportName: "tls-relationships.png",
      defaults: { layout: "spread", edgeStyle: "bezier", dim: 85 },
      style: TLS_STYLE,
      buildElements,
      onNodeTap: (node) => showNodePanel(node),
      onBackgroundTap: () => {
        const p = document.getElementById("tlsGraphSidePanel");
        if (p) p.style.display = "none";
      },
      onRefresh: () => {
        if (currentCaseId) loadTlsGraph(currentCaseId);
      },
      controls: {
        layoutRadios: document.querySelectorAll('input[name="tlsLayoutRadio"]'),
        edgeStyleRadios: document.querySelectorAll('input[name="tlsEdgeStyle"]'),
        dimSlider: document.getElementById("tlsDim"),
        filterInput: document.getElementById("tlsFilter"),
        fitBtn: document.getElementById("tlsFit"),
        fullscreenBtn: document.getElementById("tlsFullscreenBtn"),
        exportBtn: document.getElementById("tlsExport"),
        refreshBtn: document.getElementById("tlsRefresh"),
        optionsBtn: document.getElementById("tlsOptions"),
        optionsPanel: document.getElementById("tlsOptionsPanel"),
        toggles: [],
      },
    });
    return gv;
  }

  function renderTable() {
    const el = document.getElementById("tlsGraphTable");
    if (!el) return;
    const rows = graph.nodes
      .map(
        (n, i) =>
          `<tr><td>${esc(KIND_LABEL[n.kind] || n.kind)}</td><td><code title="${esc(n.id)}">${esc(shortId(n))}</code></td><td>${num(n.sensors)}</td><td>${num(n.uploads)}</td><td>${num(n.sessions)}</td><td>${esc(day(n.first))} → ${esc(day(n.last))}</td><td>${edgeWords(n.names, "name", "names")}</td><td>${edgeWords(n.servers, "server", "servers")}</td><td>${n.leads.length ? `${num(n.leads.length)} lead(s)` : "—"}${n.crossFacts.length ? `; ${num(n.crossFacts.length)} sensor difference(s)` : ""}</td><td><details><summary>details</summary>${nodeDetails(n)}</details></td></tr>`,
      )
      .join("");
    el.innerHTML = `<table data-safe-style="font-size:12px"><thead><tr><th>Kind</th><th>Identity</th><th>Sensors</th><th>Uploads</th><th>Sessions</th><th>Observed</th><th>Names</th><th>Servers</th><th>Leads</th><th></th></tr></thead><tbody>${rows}</tbody></table>
      <div data-safe-style="font-size:11px;color:var(--text-muted);margin-top:4px">${num(graph.rowsRead)} graph row(s) read across every upload${graph.notShown ? `; ${num(graph.notShown)} node(s) past the bound not shown` : ""}${graph.folded ? `; ${num(graph.folded)} node(s) an upload folded past its own bound — nothing known about them` : ""}. A JA3/JA3S is a library signature; a certificate shared across names is shared hosting, a CDN, an inspection proxy or one operator — the records do not say which; nothing here contacts observed infrastructure.</div>`;
  }

  function renderTlsGraph() {
    const el = document.getElementById("tlsGraph");
    const table = document.getElementById("tlsGraphTable");
    if (!el || !table) return;
    if (status === "loading") {
      table.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>Loading…</div>`;
      return;
    }
    if (status === "error") {
      table.innerHTML = `<div data-safe-style='color:var(--danger, #b00);font-size:12px'>The TLS relationships could not be loaded (${esc(graph.error || "request failed")}). Nothing here says the case holds no TLS records.</div>`;
      if (gv) gv.destroy();
      return;
    }
    if (!graph.nodes.length) {
      table.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>No TLS relationship rows. Import Zeek ssl.log / x509.log or Suricata tls records; a node needs two or more session records to exist.</div>`;
      if (gv) gv.destroy();
      return;
    }
    renderTable();
    const g = ensureGV();
    if (!g) {
      el.textContent = "Graph library not loaded — restart the companion server.";
      return;
    }
    g.render();
  }

  function loadTlsGraph(caseId) {
    currentCaseId = caseId;
    graph = { nodes: [], notShown: 0, rowsRead: 0, folded: 0 };
    status = "loading";
    renderTlsGraph();
    const gen = ++loadGen;
    // A late answer for a case the user has left, or an older load, never overwrites the panel.
    fetch(`/cases/${encodeURIComponent(caseId)}/tls-graph`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        graph = d && Array.isArray(d.nodes) ? d : { nodes: [], notShown: 0, rowsRead: 0, folded: 0 };
        status = "loaded";
        renderTlsGraph();
      })
      .catch((err) => {
        if (currentCaseId !== caseId || loadGen !== gen) return;
        graph = { nodes: [], notShown: 0, rowsRead: 0, folded: 0, error: String((err && err.message) || err) };
        status = "error";
        renderTlsGraph();
      });
  }

  function initTlsGraph() {
    document.querySelectorAll(".tls-kind-toggle").forEach((cb) =>
      cb.addEventListener("change", () => {
        if (cb.checked) kindsEnabled.add(cb.value);
        else kindsEnabled.delete(cb.value);
        if (gv && status === "loaded" && graph.nodes.length) gv.render();
      }),
    );
    document.querySelectorAll(".tls-legend-slot").forEach((s) => {
      s.innerHTML = `<img alt="" width="12" height="12" src="${glyph(s.dataset.ltype)}">`;
    });
    const h2 = document.querySelector("#sec-tls-graph h2");
    if (h2)
      h2.addEventListener("click", () => {
        setTimeout(() => {
          if (gv) gv.onExpand();
        }, 0);
      });
    // A view switch can reveal the section without a click on its header (the panel loaded while
    // the "Now" view hid it, so the graph's first render was deferred). Re-render when the
    // container gains a width, not only on the header click.
    const container = document.getElementById("tlsGraph");
    if (container && typeof ResizeObserver === "function") {
      let hadWidth = container.offsetWidth > 0;
      new ResizeObserver(() => {
        const has = container.offsetWidth > 0;
        if (has && !hadWidth && gv) gv.onExpand();
        hadWidth = has;
      }).observe(container);
    }
  }

  window.loadTlsGraph = loadTlsGraph;
  window.initTlsGraph = initTlsGraph;
})();
