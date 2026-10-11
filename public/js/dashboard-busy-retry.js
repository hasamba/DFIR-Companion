// "Server busy" retry for the dashboard's reads (#1915).
//
// Under a burst of heavy whole-case reads the server admits a few at a time and answers the overflow
// with 503 + Retry-After + an X-DFIR-Server-Busy marker (companion/src/composition/heavyReadGate.ts).
// That is not a broken feature, so a panel must not show it as one: this wraps window.fetch once,
// at load, and retries a busy GET/HEAD after the server's Retry-After (longer each time, with
// jitter), a few times, while a small note says "Server busy — retrying…". If the server stays busy, the note says so and offers a
// reload, and the caller gets the 503 to handle as it already does. One dashboard on its own never
// reaches the cap, so in normal use this does nothing at all.
//
// Only a 503 carrying the marker is retried: any other 503 (a feature that is not configured, a
// provider that is down) is a real answer, and retrying it would only delay the error.
(function () {
  const BUSY_HEADER = "X-DFIR-Server-Busy";
  const MAX_RETRIES = 4;
  const DEFAULT_WAIT_S = 2;
  const MAX_WAIT_S = 30;
  const JITTER = 0.5;
  const NOTE_ID = "serverBusyNote";
  const baseFetch = window.fetch;
  let retrying = 0;
  let gaveUp = false;

  function isServerBusy(response) {
    return !!response && response.status === 503 && response.headers.get(BUSY_HEADER) === "1";
  }

  // Doubles per attempt and adds 0-50% at random (#2123): with a fixed wait every refused dashboard
  // came back in the same wave and refilled the queue. Jitter only adds, because Retry-After is the
  // least the server asked for; MAX_WAIT_S stays the ceiling, jitter included.
  function retryAfterMs(response, attempt) {
    const seconds = Number(response.headers.get("Retry-After"));
    const floor = Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, MAX_WAIT_S) : DEFAULT_WAIT_S;
    const grown = floor * 2 ** attempt * (1 + Math.random() * JITTER);
    return Math.round(Math.min(grown, MAX_WAIT_S) * 1000);
  }

  function abortReason(signal) {
    if (signal.reason) return signal.reason;
    const err = new Error("The request was aborted.");
    err.name = "AbortError";
    return err;
  }

  function wait(ms, signal) {
    return new Promise((resolve, reject) => {
      if (signal && signal.aborted) return reject(abortReason(signal));
      const timer = setTimeout(resolve, ms);
      if (signal)
        signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            reject(abortReason(signal));
          },
          { once: true },
        );
    });
  }

  function note() {
    let el = document.getElementById(NOTE_ID);
    if (el) return el;
    el = document.createElement("div");
    el.id = NOTE_ID;
    el.className = "toast warn show";
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
    el.hidden = true;
    document.body.appendChild(el);
    return el;
  }

  function showNote(text, offerReload) {
    if (!document.body) return;
    const el = note();
    if (gaveUp && !offerReload) return; // a retry elsewhere must not replace the reload offer
    el.textContent = text;
    if (offerReload) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "Reload";
      button.addEventListener("click", () => location.reload());
      el.appendChild(document.createTextNode(" "));
      el.appendChild(button);
    }
    el.hidden = false;
  }

  function hideNote() {
    const el = document.getElementById(NOTE_ID);
    if (el) el.hidden = true;
  }

  function methodOf(input, init) {
    const method = (init && init.method) || (input && typeof input === "object" && input.method) || "GET";
    return String(method).toUpperCase();
  }

  async function fetchWithBusyRetry(input, init) {
    let response = await baseFetch(input, init);
    if (!isServerBusy(response)) return response;
    const method = methodOf(input, init);
    if (method !== "GET" && method !== "HEAD") return response;
    const signal = init && init.signal;
    retrying++;
    try {
      for (let attempt = 0; attempt < MAX_RETRIES && isServerBusy(response); attempt++) {
        showNote("Server busy — retrying…", false);
        await wait(retryAfterMs(response, attempt), signal);
        response = await baseFetch(input, init);
      }
    } finally {
      retrying--;
    }
    if (isServerBusy(response)) {
      gaveUp = true; // stays up until the reload: a panel on screen is missing its data
      showNote("Server busy — some panels could not load.", true);
    } else if (retrying === 0 && !gaveUp) {
      hideNote();
    }
    return response;
  }

  // Wraps the page's fetch (already team-auth wrapped in dashboard.html's head); never adds one.
  if (typeof baseFetch === "function") window.fetch = fetchWithBusyRetry;
  window.dfirServerBusy = isServerBusy;
})();
