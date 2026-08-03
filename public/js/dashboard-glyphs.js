// SVG glyph builders and the severity colour ramps that feed them (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED. See js/dashboard-escape.js for the whole argument; the
// short form is that dashboard.html's inline script calls these by bare name at 427 sites, one of
// them while the page is still parsing, so the declarations have to be real globals that exist
// before <script nonce> at line 6538 runs.
//
// These return SVG SOURCE as a string, never DOM. legendIcon() in particular is called from a
// top-level statement in dashboard.html while the page is still parsing, which is the concrete
// reason the whole set is loaded as a synchronous classic script rather than a module.

// A gear/cog outline with flat-topped (trapezoidal) teeth for the "service" asset icon —
// each tooth = a raised flat top (R) then a flat valley (r), so it reads as a cog, not a star.
function gearPath(cx, cy, R, r, teeth) {
  const step = (Math.PI * 2) / teeth;
  const pt = (rad, a) => (cx + rad * Math.cos(a)).toFixed(1) + "," + (cy + rad * Math.sin(a)).toFixed(1);
  let d = "";
  for (let i = 0; i < teeth; i++) {
    const a0 = i * step - Math.PI / 2;   // tooth-top start
    const a1 = a0 + step * 0.5;          // tooth-top end (raised flat)
    const a2 = a0 + step;                // valley end (next tooth start)
    d += (i === 0 ? "M" : "L") + pt(R, a0) + "L" + pt(R, a1) + "L" + pt(r, a1) + "L" + pt(r, a2);
  }
  return d + "Z";
}

// Type glyph for an asset node: monitor=host, person=account, gear=service (anything else → a
// plain dot). Filled in the node's compromise color (red=compromised, blue=clean) with a dark
// edge for contrast on the dark canvas. A transparent hit-circle keeps the click target generous.
function assetIcon(type, cx, cy, color) {
  const bg = "#0f1115";
  const f = (n) => n.toFixed(1);
  const hit = `<circle cx="${f(cx)}" cy="${f(cy)}" r="11" fill="transparent"/>`;
  if (type === "host") {                       // monitor: screen + stand
    return hit
      + `<rect x="${f(cx - 8)}" y="${f(cy - 7)}" width="16" height="11" rx="1.5" fill="${color}" stroke="${bg}" stroke-width="1"/>`
      + `<rect x="${f(cx - 1)}" y="${f(cy + 4)}" width="2" height="3" fill="${color}"/>`
      + `<rect x="${f(cx - 4.5)}" y="${f(cy + 7)}" width="9" height="2.2" rx="1" fill="${color}" stroke="${bg}" stroke-width="0.5"/>`;
  }
  if (type === "account") {                    // person: head + shoulders
    return hit
      + `<circle cx="${f(cx)}" cy="${f(cy - 4)}" r="4" fill="${color}" stroke="${bg}" stroke-width="1"/>`
      + `<path d="M ${f(cx - 7)},${f(cy + 8)} C ${f(cx - 7)},${f(cy - 1)} ${f(cx + 7)},${f(cy - 1)} ${f(cx + 7)},${f(cy + 8)} Z" fill="${color}" stroke="${bg}" stroke-width="1"/>`;
  }
  if (type === "service") {                    // gear: cog + hub hole
    return hit
      + `<path d="${gearPath(cx, cy, 9, 6.3, 8)}" fill="${color}" stroke="${bg}" stroke-width="0.6" stroke-linejoin="round"/>`
      + `<circle cx="${f(cx)}" cy="${f(cy)}" r="2.9" fill="${bg}"/>`;
  }
  return hit + `<circle cx="${f(cx)}" cy="${f(cy)}" r="6" fill="${color}" stroke="${bg}" stroke-width="1.5"/>`;
}

// Small standalone SVG of an asset-type icon, for the Show-toggle legend (neutral gray).
function legendIcon(type) {
  return `<svg class="legend-ico" width="16" height="16" viewBox="0 0 22 22">${assetIcon(type, 11, 11, "#cbd3df")}</svg>`;
}

// Wrap centered glyph markup (as produced by assetIcon(type,11,11,color) / evNodeGlyph(n,11,11))
// into a standalone SVG data URI usable as a cytoscape node background-image. The 22×22 viewBox
// matches the icon coordinates (center 11,11); size is the rendered pixel box.
function glyphDataUri(innerSvg, size) {
  const px = size || 26;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 22 22">${innerSvg}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}

function evSevColor(sev) { return (sev === "Critical" || sev === "High") ? "#ff5c5c" : sev === "Medium" ? "#ff9f43" : "#6aa9ff"; }

// Node glyph: hosts/accounts reuse the asset-graph icons; a process is a small rounded box.
function evNodeGlyph(n, x, y, color) {
  const c = color || evSevColor(n.maxSeverity), f = (v) => v.toFixed(1);
  if (n.kind === "host" || n.kind === "account") return assetIcon(n.kind, x, y, c);
  if (n.kind === "file") {
    // Diamond shape representing a file artifact.
    return `<circle cx="${f(x)}" cy="${f(y)}" r="11" fill="transparent"/>`
      + `<polygon points="${f(x)},${f(y - 10)} ${f(x + 10)},${f(y)} ${f(x)},${f(y + 10)} ${f(x - 10)},${f(y)}" fill="${c}" stroke="#0f1115" stroke-width="1"/>`;
  }
  if (n.kind === "network") {
    // Filled circle representing an IP endpoint.
    return `<circle cx="${f(x)}" cy="${f(y)}" r="10" fill="${c}" stroke="#0f1115" stroke-width="1"/>`;
  }
  // process: rounded rectangle
  return `<circle cx="${f(x)}" cy="${f(y)}" r="11" fill="transparent"/>`
    + `<rect x="${f(x - 9)}" y="${f(y - 6)}" width="18" height="12" rx="2.5" fill="${c}" stroke="#0f1115" stroke-width="1"/>`;
}

// Colour a label by triage meaning: threat=red, benign=green, review=yellow, evidence=blue.
function tagColor(label) {
  const THREAT = ["confirmed-malicious","c2-comms","exfil","credential-access","initial-access","lateral-movement","persistence"];
  const BENIGN = ["false-positive","benign-admin"];
  if (THREAT.includes(label)) return "#ff6b6b";
  if (BENIGN.includes(label)) return "#6bcB77";
  if (label === "needs-review") return "#ffd93b";
  if (label === "key-evidence" || label === "pivot-point") return "#6aa9ff";
  return "#9aa4b2";
}

function geoSevColor(sev) {
  return sev === "Critical" || sev === "High" ? "red" : sev === "Medium" ? "orange" : sev === "Low" ? "yellow" : "gray";
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirGlyphs = {
  gearPath,
  assetIcon,
  legendIcon,
  glyphDataUri,
  evSevColor,
  evNodeGlyph,
  geoSevColor,
  tagColor,
};
