// Theme (#53) — the palette picker and its menu — extracted from dashboard.html (issue #415,
// tier 3).
//
// Reported three escapes (DFIR_THEMES, THEME_GROUP_LABELS, THEME_GROUP_ORDER) that were read by
// renderThemeMenu and the menu's four handlers — 78 lines of theme code sitting on the far side of
// the "Theme picker" banner, which is the page's state hub. The banner was in the wrong place, not
// the code: moving it past the menu block left this section with no escapes at all.
//
// "Theme picker" is a misleading name for what is left there. It holds ws, SEV, aiEnabled, the
// pagination cursors and thirty more of the page's central bindings, and is flagged a state hub.
(function () {
  "use strict";

  // The effective theme lives in <html data-theme>. It is set FOUC-free by the <head> bootstrap;
  // here we wire the picker, persist the choice, follow OS changes (until the user overrides),
  // and give canvas/SVG code a way to read the active token values (canvas can't use CSS vars).
  //
  // Colours are addressed by ROLE (--bg-primary, --sev-high), never by hex. A theme supplies
  // the 25 "tier A" roles; everything else derives from those. See companion/scripts/theme/.
  /* >>> dfir-theme registry (generated) */
  // Theme palettes are third-party, MIT, (c) 2026 Security Onion Solutions, LLC;
  // see companion/scripts/theme/vendor/themePalettes.ts for the full notice.
  const DFIR_THEMES = {
    dark: { label: "Dark", group: "dark", polarity: "dark" },
    light: { label: "Light", group: "light", polarity: "light" },
    catppuccin: { label: "Catppuccin", group: "dark", polarity: "dark" },
    "catppuccin-latte": {
      label: "Catppuccin Latte",
      group: "light",
      polarity: "light",
    },
    cga: { label: "CGA", group: "fun", polarity: "dark" },
    ethereal: { label: "Ethereal", group: "dark", polarity: "dark" },
    everforest: { label: "Everforest", group: "dark", polarity: "dark" },
    gruvbox: { label: "Gruvbox", group: "dark", polarity: "dark" },
    hacker: { label: "Hacker", group: "fun", polarity: "dark" },
    hackerman: { label: "Hackerman", group: "dark", polarity: "dark" },
    kanagawa: { label: "Kanagawa", group: "dark", polarity: "dark" },
    lumon: { label: "Lumon", group: "dark", polarity: "dark" },
    "matte-black": { label: "Matte Black", group: "dark", polarity: "dark" },
    miasma: { label: "Miasma", group: "dark", polarity: "dark" },
    nord: { label: "Nord", group: "dark", polarity: "dark" },
    "osaka-jade": { label: "Osaka Jade", group: "dark", polarity: "dark" },
    "retro-82": { label: "Retro 82", group: "dark", polarity: "dark" },
    ristretto: { label: "Ristretto", group: "dark", polarity: "dark" },
    "rose-pine": { label: "Rose Pine", group: "light", polarity: "light" },
    sguil: { label: "Sguil", group: "fun", polarity: "light" },
    "tokyo-night": { label: "Tokyo Night", group: "dark", polarity: "dark" },
    vantablack: { label: "Vantablack", group: "dark", polarity: "dark" },
    vaporwave: { label: "Vaporwave", group: "fun", polarity: "dark" },
    white: { label: "White", group: "light", polarity: "light" },
  };
  /* <<< dfir-theme registry */
  const THEME_GROUP_LABELS = { dark: "Dark", light: "Light", fun: "Fun" };
  const THEME_GROUP_ORDER = ["dark", "light", "fun"];

  let _themeColorCache = {};
  function themeColor(token, fallback) {
    if (token in _themeColorCache) return _themeColorCache[token];
    let v = "";
    try {
      v = getComputedStyle(document.documentElement)
        .getPropertyValue(token)
        .trim();
    } catch (e) {}
    return (_themeColorCache[token] = v || fallback || "#000");
  }
  // A stored value is untrusted input: it reaches us from localStorage, which any script that
  // ever ran on this origin could have written. Without this check it would be interpolated
  // straight into a DOM attribute. Membership in the generated registry is the only accepted
  // proof that a name is real, so an unknown value falls back rather than being applied.
  function isKnownTheme(name) {
    return (
      typeof name === "string" &&
      Object.prototype.hasOwnProperty.call(DFIR_THEMES, name)
    );
  }
  function systemTheme() {
    try {
      return window.matchMedia &&
        window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark";
    } catch (e) {
      return "dark";
    }
  }
  function storedTheme() {
    try {
      const s = localStorage.getItem("dfir-theme");
      return isKnownTheme(s) ? s : null;
    } catch (e) {
      return null;
    }
  }
  function currentTheme() {
    const t = document.documentElement.getAttribute("data-theme");
    return isKnownTheme(t) ? t : "dark";
  }
  function applyTheme(theme) {
    const name = isKnownTheme(theme) ? theme : "dark";
    document.documentElement.setAttribute("data-theme", name);
    const btn = document.getElementById("themeToggle");
    if (btn) {
      const label = DFIR_THEMES[name].label;
      btn.title = "Theme: " + label + " — click to change";
      btn.setAttribute("aria-label", "Change theme (currently " + label + ")");
    }
    _themeColorCache = {}; // token values changed — drop the cache
    rethemeCanvases(); // redraw anything that bakes colors (the swimlane canvas)
    renderThemeMenu(); // keep the checkmark on the active entry
  }
  function setTheme(theme) {
    if (!isKnownTheme(theme)) return;
    try {
      localStorage.setItem("dfir-theme", theme);
    } catch (e) {}
    applyTheme(theme);
  }
  // Redraw canvas-based views whose colors are baked (CSS vars can't reach a <canvas>).
  function rethemeCanvases() {
    // The `typeof swLanes` half of this guard had to go when the feature moved (#415 tier 3):
    // the lane array is private to js/dashboard-swimlane.js now, so that test is permanently
    // "undefined" here and would have silently stopped the canvas re-theming forever. Dropping
    // it is safe because swRenderCanvas paints its empty-state placeholder and returns when
    // there are no lanes, so calling it with none is a no-op rather than a throw.
    try {
      if (typeof swRenderCanvas === "function") swRenderCanvas();
    } catch (e) {}
  }

  // Entries are built with createElement and textContent rather than innerHTML: the labels come
  // from a generated file today, but this menu is the one place a theme name reaches the DOM and
  // it should not become an injection sink if that file ever takes a less trusted source.
  function renderThemeMenu() {
    const menu = document.getElementById("themeMenu");
    if (!menu) return;
    const active = currentTheme();
    menu.replaceChildren();
    for (const group of THEME_GROUP_ORDER) {
      const names = Object.keys(DFIR_THEMES)
        .filter((k) => DFIR_THEMES[k].group === group)
        .sort((a, b) =>
          DFIR_THEMES[a].label.localeCompare(DFIR_THEMES[b].label),
        );
      if (!names.length) continue;
      const h = document.createElement("h3");
      h.textContent = THEME_GROUP_LABELS[group] || group;
      menu.appendChild(h);
      for (const name of names) {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "theme-item" + (name === active ? " active" : "");
        item.dataset.theme = name;
        item.setAttribute("role", "menuitemradio");
        item.setAttribute("aria-checked", String(name === active));
        const sw = document.createElement("span");
        sw.className = "theme-swatch";
        sw.dataset.for = name; // coloured by CSS, so no inline style is needed
        const txt = document.createElement("span");
        txt.textContent = DFIR_THEMES[name].label;
        item.append(sw, txt);
        menu.appendChild(item);
      }
    }
  }
  function themeMenuOpen() {
    const m = document.getElementById("themeMenu");
    return !!m && m.style.display !== "none";
  }
  function closeThemeMenu() {
    const m = document.getElementById("themeMenu");
    if (m) m.style.display = "none";
    const b = document.getElementById("themeToggle");
    if (b) b.setAttribute("aria-expanded", "false");
  }
  function openThemeMenu() {
    const m = document.getElementById("themeMenu");
    if (!m) return;
    renderThemeMenu();
    m.style.display = "block";
    const b = document.getElementById("themeToggle");
    if (b) b.setAttribute("aria-expanded", "true");
    const first =
      m.querySelector(".theme-item.active") || m.querySelector(".theme-item");
    if (first) first.focus();
  }

  // The toggle, the menu, the outside-click close and the keyboard nav. All bind to markup.
  function initTheme() {
    // The bootstrap: apply before first paint so there is no flash, follow the OS only while the
    // analyst has not chosen explicitly, and enable the colour transition only afterwards. This ran
    // as bare top-level statements in the page, which the facade gate flagged the moment the
    // functions moved out — an unguarded read at load, thrown before anything could report it.
    applyTheme(storedTheme() || systemTheme());
    // Follow the OS only while the user hasn't picked an explicit theme.
    try {
      window
        .matchMedia("(prefers-color-scheme: light)")
        .addEventListener("change", (e) => {
          if (!storedTheme()) applyTheme(e.matches ? "light" : "dark");
        });
    } catch (e) {}
    // Enable the colour transition only after the first paint, so the initial theme doesn't animate.
    requestAnimationFrame(() =>
      document.documentElement.classList.add("theme-anim"),
    );

    document.getElementById("themeToggle").addEventListener("click", (e) => {
      e.stopPropagation();
      themeMenuOpen() ? closeThemeMenu() : openThemeMenu();
    });
    document.getElementById("themeMenu").addEventListener("click", (e) => {
      const item = e.target.closest(".theme-item");
      if (!item) return;
      setTheme(item.dataset.theme);
      closeThemeMenu();
      document.getElementById("themeToggle").focus();
    });
    document.addEventListener("click", (e) => {
      if (!themeMenuOpen()) return;
      if (e.target.closest("#themeMenu") || e.target.closest("#themeToggle"))
        return;
      closeThemeMenu();
    });
    document.addEventListener("keydown", (e) => {
      if (!themeMenuOpen()) return;
      if (e.key === "Escape") {
        closeThemeMenu();
        document.getElementById("themeToggle").focus();
        return;
      }
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      const items = [...document.querySelectorAll("#themeMenu .theme-item")];
      const at = items.indexOf(document.activeElement);
      const next = e.key === "ArrowDown" ? at + 1 : at - 1;
      if (items[(next + items.length) % items.length]) {
        e.preventDefault();
        items[(next + items.length) % items.length].focus();
      }
    });
  }

  window.initTheme = initTheme;
  window.applyTheme = applyTheme;
  window.storedTheme = storedTheme;
  window.systemTheme = systemTheme;
  window.themeColor = themeColor;
})();
