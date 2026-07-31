/*
 * Central browser rendering policy.
 *
 * Evidence strings are adversary controlled. Every HTML sink is therefore routed through the
 * sanitizer below. Chromium additionally enforces that routing with Trusted Types; the patched
 * setters provide the same protection in Firefox, where Trusted Types is not implemented.
 *
 * Inline styles are governed here too. Markup uses data-safe-style and JavaScript may continue to
 * use element.style, but both paths become validated rules in one nonce-approved stylesheet. No
 * style attribute is written to the live document.
 */
(function installSafeDom(root) {
  "use strict";

  var BLOCKED_ELEMENTS = new Set([
    "BASE", "EMBED", "FOREIGNOBJECT", "IFRAME", "LINK", "MATH", "META", "NOSCRIPT",
    "OBJECT", "SCRIPT", "STYLE", "TEMPLATE",
  ]);
  var HTML_ELEMENTS = new Set([
    "A", "ABBR", "ARTICLE", "ASIDE", "B", "BLOCKQUOTE", "BR", "BUTTON", "CANVAS",
    "CAPTION", "CODE", "COL", "COLGROUP", "DATA", "DD", "DEL", "DETAILS", "DFN",
    "DIV", "DL", "DT", "EM", "FIELDSET", "FIGCAPTION", "FIGURE", "FOOTER", "FORM",
    "H1", "H2", "H3", "H4", "H5", "H6", "HEADER", "HR", "I", "IMG", "INPUT",
    "KBD", "LABEL", "LEGEND", "LI", "MAIN", "MARK", "NAV", "OL", "OPTGROUP", "OPTION",
    "OUTPUT", "P", "PICTURE", "PRE", "PROGRESS", "Q", "S", "SAMP", "SECTION", "SELECT",
    "SMALL", "SOURCE", "SPAN", "STRONG", "SUB", "SUMMARY", "SUP", "TABLE", "TBODY", "TD",
    "TEXTAREA", "TFOOT", "TH", "THEAD", "TIME", "TR", "U", "UL", "VAR", "VIDEO", "WBR",
  ]);
  var SVG_ELEMENTS = new Set([
    "CIRCLE", "CLIPPATH", "DEFS", "ELLIPSE", "G", "LINE", "LINEARGRADIENT", "PATH",
    "POLYGON", "POLYLINE", "RADIALGRADIENT", "RECT", "STOP", "SVG", "TEXT", "TSPAN",
  ]);
  var SAFE_ATTRIBUTES = new Set([
    "abbr", "accept", "accept-charset", "alt", "aria-atomic", "aria-busy", "aria-checked",
    "aria-controls", "aria-current", "aria-describedby", "aria-disabled", "aria-expanded",
    "aria-haspopup", "aria-hidden", "aria-label", "aria-labelledby", "aria-live", "aria-modal",
    "aria-multiselectable", "aria-pressed", "aria-required", "aria-selected", "aria-valuemax",
    "aria-valuemin", "aria-valuenow", "aria-valuetext", "autocomplete", "autofocus", "capture",
    "cellpadding", "cellspacing", "checked", "class", "cols", "colspan", "contenteditable",
    "controls", "datetime", "decoding", "dir", "disabled", "download", "draggable", "for",
    "headers", "height", "hidden", "high", "id", "inputmode", "kind", "label", "lang", "list",
    "loading", "loop", "low", "max", "maxlength", "media", "method", "min", "minlength",
    "multiple", "muted", "name", "open", "optimum", "pattern", "placeholder", "playsinline",
    "poster", "preload", "readonly", "rel", "required", "reversed", "role", "rows", "rowspan",
    "scope", "selected", "size", "sizes", "slot", "span", "spellcheck", "src", "step",
    "tabindex", "target", "title", "translate", "type", "value", "width", "wrap",
  ]);
  var SAFE_SVG_ATTRIBUTES = new Set([
    "class", "clip-path", "cx", "cy", "d", "fill", "fill-opacity", "height", "id", "offset",
    "opacity", "points", "preserveaspectratio", "r", "rx", "ry", "stop-color", "stop-opacity",
    "stroke", "stroke-dasharray", "stroke-linecap", "stroke-linejoin", "stroke-opacity",
    "stroke-width", "transform", "viewbox", "width", "x", "x1", "x2", "xmlns", "y", "y1", "y2",
  ]);
  var URL_ATTRIBUTES = new Set(["href", "poster", "src"]);
  var DANGEROUS_CSS = /(?:url\s*\(|expression\s*\(|@import|javascript\s*:|vbscript\s*:|behavior\s*:|-moz-binding|[{}<>\\])/i;

  function isSafeUrl(value, attribute, tagName) {
    var raw = String(value == null ? "" : value).trim();
    var compact = raw.replace(/[\u0000-\u0020\u007f]+/g, "").toLowerCase();
    var attr = String(attribute || "").toLowerCase();
    var tag = String(tagName || "").toLowerCase();
    if (!compact) return true;
    if (compact[0] === "#" || compact[0] === "?" || compact.indexOf("./") === 0 || compact.indexOf("../") === 0) return true;
    if (compact[0] === "/" && compact.indexOf("//") !== 0) return true;
    if (attr === "src" && tag === "img" && /^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i.test(compact)) return true;
    if (compact.indexOf("//") === 0) return false;
    if (attr === "href" && /^(?:https?|mailto):/i.test(compact)) return true;

    var base = root.location && root.location.origin ? root.location.origin : "https://dfir-companion.invalid";
    try {
      var parsed = new root.URL(raw, base);
      return (parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.origin === base;
    } catch (_error) {
      return false;
    }
  }

  function sanitizeCssText(value) {
    var clean = [];
    String(value == null ? "" : value).split(";").forEach(function (part) {
      var colon = part.indexOf(":");
      if (colon < 1) return;
      var property = part.slice(0, colon).trim().toLowerCase();
      var cssValue = part.slice(colon + 1).trim().replace(/\s*!important\s*$/i, "");
      if (!/^(?:--[a-z0-9-]+|[a-z-]+)$/.test(property) || !cssValue || DANGEROUS_CSS.test(property + ":" + cssValue)) return;
      clean.push(property + ":" + cssValue);
    });
    return clean.join(";");
  }

  // This is a first, browser-independent pass. The DOM walk below remains authoritative: regex is
  // useful for reducing what reaches the inert parser, but it is never treated as an HTML parser.
  function precleanHtml(value) {
    var html = String(value == null ? "" : value);
    html = html.replace(/<\/?(?:script|iframe|object|embed|style|template|base|meta|link|math)\b[^>]*>/gi, "");
    html = html.replace(/\s(?:on[a-z0-9_-]+|srcdoc)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");
    html = html.replace(/\sstyle\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi, function (_all, _quoted, doubleValue, singleValue, bareValue) {
      var css = sanitizeCssText(doubleValue || singleValue || bareValue || "");
      return css ? ' data-safe-style="' + css.replace(/&/g, "&amp;").replace(/"/g, "&quot;") + '"' : "";
    });
    return html;
  }

  var api = {
    isSafeUrl: isSafeUrl,
    precleanHtml: precleanHtml,
    sanitizeCssText: sanitizeCssText,
  };
  root.DFIRSafeDOM = api;
  if (!root.document || !root.Element) return;

  var document = root.document;
  var innerDescriptor = Object.getOwnPropertyDescriptor(root.Element.prototype, "innerHTML");
  var outerDescriptor = Object.getOwnPropertyDescriptor(root.Element.prototype, "outerHTML");
  var nativeInsertAdjacentHtml = root.Element.prototype.insertAdjacentHTML;
  var nativeSetAttribute = root.Element.prototype.setAttribute;
  if (!innerDescriptor || !innerDescriptor.get || !innerDescriptor.set) throw new Error("DOM HTML setters unavailable");

  var trustedTypes = root.trustedTypes;
  var parserPolicy = trustedTypes ? trustedTypes.createPolicy("dfir-parser", { createHTML: function (input) { return input; } }) : null;

  function isAllowedAttribute(element, name) {
    var lower = name.toLowerCase();
    if (lower.indexOf("on") === 0 || lower === "srcdoc" || lower === "action" || lower === "formaction" || lower === "srcset") return false;
    if (lower.indexOf("data-") === 0 || lower.indexOf("aria-") === 0) return true;
    if (element.namespaceURI === "http://www.w3.org/2000/svg") return SAFE_SVG_ATTRIBUTES.has(lower);
    return SAFE_ATTRIBUTES.has(lower) || lower === "href";
  }

  function sanitizeElement(element) {
    var name = element.tagName.toUpperCase();
    if (BLOCKED_ELEMENTS.has(name)) {
      element.remove();
      return;
    }
    if (!HTML_ELEMENTS.has(name) && !SVG_ELEMENTS.has(name)) {
      element.replaceWith(document.createTextNode(element.textContent || ""));
      return;
    }

    Array.prototype.slice.call(element.attributes).forEach(function (attribute) {
      var attrName = attribute.name.toLowerCase();
      if (attrName === "style") {
        var css = sanitizeCssText(attribute.value);
        element.removeAttribute(attribute.name);
        if (css) element.setAttribute("data-safe-style", css);
        return;
      }
      if (!isAllowedAttribute(element, attrName)) {
        element.removeAttribute(attribute.name);
        return;
      }
      if (URL_ATTRIBUTES.has(attrName) && !isSafeUrl(attribute.value, attrName, name)) {
        element.removeAttribute(attribute.name);
        return;
      }
      if (attrName === "data-safe-style") {
        var safeCss = sanitizeCssText(attribute.value);
        if (safeCss) element.setAttribute(attribute.name, safeCss);
        else element.removeAttribute(attribute.name);
      }
    });

    if (name === "A" && element.getAttribute("target") === "_blank") {
      element.setAttribute("rel", "noopener noreferrer");
    }
  }

  function sanitizeHtml(value) {
    var template = document.createElement("template");
    var prepared = precleanHtml(value);
    var inert = parserPolicy ? parserPolicy.createHTML(prepared) : prepared;
    innerDescriptor.set.call(template, inert);
    Array.prototype.slice.call(template.content.querySelectorAll("*")).forEach(sanitizeElement);
    return innerDescriptor.get.call(template);
  }

  var safePolicy = trustedTypes ? trustedTypes.createPolicy("dfir-safe-html", { createHTML: sanitizeHtml }) : null;
  if (trustedTypes) trustedTypes.createPolicy("default", {
    createHTML: sanitizeHtml,
    createScriptURL: function (value) {
      if (isSafeUrl(value, "src", "script")) return value;
      throw new TypeError("Blocked cross-origin script URL");
    },
  });

  function trustedHtml(value) {
    return safePolicy ? safePolicy.createHTML(String(value == null ? "" : value)) : sanitizeHtml(value);
  }

  var cssByClass = new Map();
  var classByCss = new Map();
  var styleState = new WeakMap();
  var styleClass = new WeakMap();
  var dynamicRule = new WeakMap();
  var styleProxy = new WeakMap();
  var dynamicStyleId = 0;

  function hashCss(value) {
    var hash = 2166136261;
    for (var i = 0; i < value.length; i += 1) {
      hash ^= value.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(36);
  }

  function runtimeSheet() {
    var owner = document.getElementById("dfir-runtime-styles");
    if (!owner) {
      owner = document.createElement("style");
      owner.id = "dfir-runtime-styles";
      var nonceSource = document.querySelector("style[nonce],script[nonce]");
      if (nonceSource && nonceSource.nonce) owner.nonce = nonceSource.nonce;
      (document.head || document.documentElement).appendChild(owner);
    }
    return owner.sheet;
  }

  function importantCss(css) {
    return css.split(";").filter(Boolean).map(function (declaration) { return declaration + " !important"; }).join(";");
  }

  function classForCss(css) {
    if (classByCss.has(css)) return classByCss.get(css);
    var base = "dfir-s-" + hashCss(css);
    var className = base;
    var suffix = 1;
    while (cssByClass.has(className) && cssByClass.get(className) !== css) className = base + "-" + suffix++;
    try {
      runtimeSheet().insertRule("." + className + "{" + importantCss(css) + "}", runtimeSheet().cssRules.length);
    } catch (_error) {
      return "";
    }
    cssByClass.set(className, css);
    classByCss.set(css, className);
    return className;
  }

  function cssMap(value) {
    var state = new Map();
    sanitizeCssText(value).split(";").filter(Boolean).forEach(function (declaration) {
      var colon = declaration.indexOf(":");
      state.set(declaration.slice(0, colon), declaration.slice(colon + 1));
    });
    return state;
  }

  function serializeState(state) {
    return Array.from(state.entries()).map(function (entry) { return entry[0] + ":" + entry[1]; }).join(";");
  }

  function dynamicClassFor(element) {
    var existing = dynamicRule.get(element);
    if (existing) return existing;
    var className = "dfir-d-" + (++dynamicStyleId).toString(36);
    var sheet = runtimeSheet();
    try {
      sheet.insertRule("." + className + "{}", sheet.cssRules.length);
    } catch (_error) {
      return null;
    }
    var entry = { className: className, rule: sheet.cssRules[sheet.cssRules.length - 1] };
    dynamicRule.set(element, entry);
    return entry;
  }

  function applyStyleState(element, state, isDynamic) {
    var previous = styleClass.get(element);
    if (previous) element.classList.remove(previous);
    var css = sanitizeCssText(serializeState(state));
    if (isDynamic) {
      var entry = dynamicClassFor(element);
      if (!entry) return;
      entry.rule.style.cssText = importantCss(css);
      element.classList.add(entry.className);
      styleClass.set(element, entry.className);
      return;
    }
    if (!css) {
      styleClass.delete(element);
      return;
    }
    var className = classForCss(css);
    if (className) {
      element.classList.add(className);
      styleClass.set(element, className);
    }
  }

  function ensureStyleState(element) {
    if (styleState.has(element)) return styleState.get(element);
    var declared = element.getAttribute("data-safe-style") || element.getAttribute("style") || "";
    element.removeAttribute("style");
    element.removeAttribute("data-safe-style");
    var state = cssMap(declared);
    styleState.set(element, state);
    applyStyleState(element, state, false);
    return state;
  }

  function cssPropertyName(property) {
    if (property.indexOf("--") === 0) return property;
    if (property === "cssFloat") return "float";
    return property.replace(/[A-Z]/g, function (letter) { return "-" + letter.toLowerCase(); });
  }

  function setStyleProperty(element, property, value) {
    var state = ensureStyleState(element);
    var name = cssPropertyName(String(property));
    var next = String(value == null ? "" : value).trim();
    if (!next) state.delete(name);
    else {
      var clean = sanitizeCssText(name + ":" + next);
      if (clean) state.set(name, clean.slice(clean.indexOf(":") + 1));
      else state.delete(name);
    }
    applyStyleState(element, state, true);
  }

  function proxyForStyle(element, nativeStyle) {
    if (styleProxy.has(element)) return styleProxy.get(element);
    var proxy = new Proxy(nativeStyle, {
      get: function (_target, property) {
        var state = ensureStyleState(element);
        if (property === "cssText") return serializeState(state);
        if (property === "length") return state.size;
        if (property === "item") return function (index) { return Array.from(state.keys())[index] || ""; };
        if (property === "getPropertyValue") return function (name) { return state.get(String(name).toLowerCase()) || ""; };
        if (property === "getPropertyPriority") return function () { return ""; };
        if (property === "setProperty") return function (name, value) { setStyleProperty(element, String(name), value); };
        if (property === "removeProperty") return function (name) {
          var key = String(name).toLowerCase();
          var previous = state.get(key) || "";
          state.delete(key);
          applyStyleState(element, state, true);
          return previous;
        };
        if (typeof property === "string") {
          var key = cssPropertyName(property);
          if (state.has(key)) return state.get(key);
        }
        var fallback = Reflect.get(nativeStyle, property, nativeStyle);
        return typeof fallback === "function" ? fallback.bind(nativeStyle) : fallback;
      },
      set: function (_target, property, value) {
        if (property === "cssText") {
          var replacement = cssMap(value);
          styleState.set(element, replacement);
          applyStyleState(element, replacement, true);
        } else setStyleProperty(element, String(property), value);
        return true;
      },
    });
    styleProxy.set(element, proxy);
    return proxy;
  }

  function patchStyleGetter(prototype) {
    if (!prototype) return;
    var descriptor = Object.getOwnPropertyDescriptor(prototype, "style");
    if (!descriptor || !descriptor.get || descriptor.configurable === false) return;
    Object.defineProperty(prototype, "style", {
      configurable: true,
      enumerable: descriptor.enumerable,
      get: function () { return proxyForStyle(this, descriptor.get.call(this)); },
    });
  }

  function hydrateStyles(rootNode) {
    if (!rootNode) return;
    if (rootNode.nodeType === 1 && (rootNode.hasAttribute("data-safe-style") || rootNode.hasAttribute("style"))) ensureStyleState(rootNode);
    if (rootNode.querySelectorAll) {
      Array.prototype.slice.call(rootNode.querySelectorAll("[data-safe-style],[style]")).forEach(ensureStyleState);
    }
  }

  function patchHtmlSetter(prototype, property, descriptor) {
    if (!prototype || !descriptor || !descriptor.get || !descriptor.set || descriptor.configurable === false) return;
    Object.defineProperty(prototype, property, {
      configurable: true,
      enumerable: descriptor.enumerable,
      get: descriptor.get,
      set: function (value) {
        descriptor.set.call(this, trustedHtml(value));
        hydrateStyles(property === "outerHTML" ? this.parentNode : this);
      },
    });
  }

  patchHtmlSetter(root.Element.prototype, "innerHTML", innerDescriptor);
  patchHtmlSetter(root.Element.prototype, "outerHTML", outerDescriptor);
  if (root.ShadowRoot) patchHtmlSetter(root.ShadowRoot.prototype, "innerHTML", Object.getOwnPropertyDescriptor(root.ShadowRoot.prototype, "innerHTML"));
  root.Element.prototype.insertAdjacentHTML = function (position, value) {
    nativeInsertAdjacentHtml.call(this, position, trustedHtml(value));
    hydrateStyles(this.parentNode || this);
  };
  root.Element.prototype.setAttribute = function (name, value) {
    var lower = String(name).toLowerCase();
    if (lower.indexOf("on") === 0 || lower === "srcdoc") return;
    if (lower === "style") {
      var css = sanitizeCssText(value);
      var state = cssMap(css);
      styleState.set(this, state);
      this.removeAttribute("data-safe-style");
      applyStyleState(this, state, true);
      return;
    }
    if (URL_ATTRIBUTES.has(lower) && !isSafeUrl(value, lower, this.tagName)) return;
    nativeSetAttribute.call(this, name, value);
  };
  patchStyleGetter(root.HTMLElement && root.HTMLElement.prototype);
  patchStyleGetter(root.SVGElement && root.SVGElement.prototype);

  api.sanitizeHtml = sanitizeHtml;
  api.setHtml = function (element, value) { element.innerHTML = value; };
  api.hydrateStyles = hydrateStyles;

  function finishInitialHydration() {
    try { hydrateStyles(document); }
    finally { document.documentElement.classList.add("dfir-styles-ready"); }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", finishInitialHydration, { once: true });
  else finishInitialHydration();

  if (root.MutationObserver) {
    new root.MutationObserver(function (records) {
      records.forEach(function (record) {
        if (record.type === "attributes") hydrateStyles(record.target);
        else Array.prototype.slice.call(record.addedNodes).forEach(hydrateStyles);
      });
    }).observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-safe-style", "style"] });
  }
})(globalThis);
