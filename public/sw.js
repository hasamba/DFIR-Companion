/*
 * DFIR Companion — mobile PWA service worker (#59).
 *
 * Deliberately minimal and tightly scoped. It is registered with scope "/mobile", so it ONLY
 * sees requests under /mobile — it never intercepts the dashboard, the API (/cases/...), or any
 * other route. Its single job is to make the mobile app-shell launchable offline (and satisfy
 * PWA installability). Live case data is fetched by the page itself, which keeps its own
 * last-good copy in localStorage for offline glances — so the SW never caches forensic evidence.
 */
const SHELL_CACHE = "dfir-mobile-shell-v1";
const SHELL_URL = "/mobile";

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) => cache.add(SHELL_URL)).then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// App-shell strategy: network-first (so a fresh shell is served when online), falling back to the
// cached shell when offline. Only navigations are handled; anything else falls through to the
// network untouched.
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  if (req.mode !== "navigate") return;

  event.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(SHELL_CACHE).then((cache) => cache.put(SHELL_URL, copy)).catch(() => {});
        return res;
      })
      .catch(() => caches.match(SHELL_URL).then((cached) => cached || Response.error())),
  );
});
