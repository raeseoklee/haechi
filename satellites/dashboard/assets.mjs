// Static assets for haechi-dashboard, embedded as template-string constants.
//
// Design constraint (acceptance criterion): assets are served from a FIXED
// in-code Map keyed by exact request path. There is NO runtime `fs` read for
// assets and NO URL-derived filesystem path — so path traversal (e.g.
// `/../../etc/passwd`) is structurally impossible: an unknown key just misses
// the Map and 404s.
//
// The client JS builds the DOM with `document.createElement` + `textContent`
// ONLY. It never assigns `innerHTML` with interpolated data, so an audit field
// like `detections[].path` containing `<script>` / `<img onerror>` is rendered
// inert as text. The page's CSP (`require-trusted-types-for 'script'`) makes
// any stray `innerHTML` sink throw in-browser, turning the convention into an
// enforced guarantee. The HTML references only same-origin /assets/app.js and
// /assets/app.css — no inline script/style, no external CDN, no eval.

export const HTML_SHELL = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Haechi Audit Viewer</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header>
<h1>Haechi Audit Viewer</h1>
<p class="subtitle">Read-only audit log + hash-chain status</p>
</header>
<section id="chain-status" aria-live="polite">
<h2>Chain status</h2>
<div id="chain-body">Loading&hellip;</div>
</section>
<section id="summary">
<h2>Summary</h2>
<div id="summary-body">Loading&hellip;</div>
</section>
<section id="events">
<h2>Events</h2>
<div id="events-controls">
<button id="refresh-btn" type="button">Refresh</button>
<span id="window-marker" hidden></span>
</div>
<div id="events-body">Loading&hellip;</div>
</section>
<script src="/assets/app.js"></script>
</body>
</html>
`;

export const APP_CSS = `:root {
  color-scheme: light dark;
  --fg: #1a1a1a;
  --bg: #fafafa;
  --muted: #6a6a6a;
  --danger: #b00020;
  --ok: #1b7f3b;
  --border: #d9d9d9;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  color: var(--fg);
  background: var(--bg);
  line-height: 1.5;
}
header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }
h1 { margin: 0; font-size: 1.4rem; }
.subtitle { margin: 0.25rem 0 0; color: var(--muted); font-size: 0.9rem; }
section { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }
h2 { font-size: 1rem; margin: 0 0 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
.chain-valid { color: var(--ok); font-weight: 600; }
.chain-invalid { color: var(--danger); font-weight: 700; }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 0.15rem 0.75rem; font-size: 0.9rem; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
.detections { margin: 0.25rem 0 0; padding-left: 1rem; font-size: 0.8rem; }
button { font: inherit; padding: 0.3rem 0.75rem; cursor: pointer; }
#window-marker { margin-left: 0.75rem; color: var(--danger); font-size: 0.85rem; }
.error { color: var(--danger); }
`;

export const APP_JS = `"use strict";
// All rendering uses createElement + textContent only. No innerHTML, no eval.
(function () {
  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function getJson(url) {
    return fetch(url, { headers: { accept: "application/json" }, credentials: "same-origin" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      });
  }

  function renderChain(data) {
    var body = document.getElementById("chain-body");
    clear(body);
    if (data.valid === null) {
      body.appendChild(el("p", "Chain too large to verify (size cap exceeded).", "error"));
      return;
    }
    var head = el("p", null, data.valid ? "chain-valid" : "chain-invalid");
    head.textContent = data.valid ? "VALID" : "TAMPER DETECTED (valid:false)";
    body.appendChild(head);
    var dl = el("dl", null, "kv");
    function row(k, v) {
      dl.appendChild(el("dt", k));
      dl.appendChild(el("dd", v === undefined || v === null ? "—" : v));
    }
    row("records", data.records);
    if (data.headHash !== undefined) row("headHash", data.headHash);
    if (data.truncationDetected !== undefined) row("truncationDetected", String(data.truncationDetected));
    if (data.anchored) {
      row("anchored.count", data.anchored.count);
      row("anchored.lastSequence", data.anchored.lastSequence);
    }
    body.appendChild(dl);
  }

  function renderSummary(data) {
    var body = document.getElementById("summary-body");
    clear(body);
    var dl = el("dl", null, "kv");
    dl.appendChild(el("dt", "detectionCount"));
    dl.appendChild(el("dd", data.detectionCount != null ? data.detectionCount : 0));
    function counts(label, obj) {
      dl.appendChild(el("dt", label));
      var dd = el("dd");
      var keys = obj ? Object.keys(obj) : [];
      if (keys.length === 0) { dd.textContent = "—"; }
      else {
        keys.forEach(function (k, i) {
          if (i > 0) dd.appendChild(document.createTextNode(", "));
          dd.appendChild(document.createTextNode(k + ": " + obj[k]));
        });
      }
      dl.appendChild(dd);
    }
    counts("byType", data.byType);
    counts("byAction", data.byAction);
    body.appendChild(dl);
  }

  function renderEvents(data) {
    var body = document.getElementById("events-body");
    clear(body);
    var marker = document.getElementById("window-marker");
    if (data.windowExceeded) {
      marker.hidden = false;
      marker.textContent = "window exceeded — older pages are not retained";
    } else {
      marker.hidden = true;
      marker.textContent = "";
    }
    var events = data.events || [];
    if (events.length === 0) {
      body.appendChild(el("p", "No events in window."));
      return;
    }
    var table = el("table");
    var thead = el("thead");
    var hr = el("tr");
    ["seq", "time", "protocol", "operation", "actor", "mode", "blocked", "detections"].forEach(function (h) {
      hr.appendChild(el("th", h));
    });
    thead.appendChild(hr);
    table.appendChild(thead);
    var tbody = el("tbody");
    events.forEach(function (ev) {
      var tr = el("tr");
      tr.appendChild(el("td", ev.auditIntegrity ? ev.auditIntegrity.sequence : "", "mono"));
      tr.appendChild(el("td", ev.timestamp));
      tr.appendChild(el("td", ev.protocol));
      tr.appendChild(el("td", ev.operation));
      // PII-safe actor: identity.id is provider:subjectHash[:16] (keyed-HMAC),
      // never the raw subject/email; dash when no auth was configured.
      tr.appendChild(el("td", ev.identity && ev.identity.id ? ev.identity.id : "—", "mono"));
      tr.appendChild(el("td", ev.mode));
      tr.appendChild(el("td", String(ev.blocked)));
      var dcell = el("td");
      var dets = ev.detections || [];
      if (dets.length === 0) {
        dcell.textContent = "—";
      } else {
        var ul = el("ul", null, "detections");
        dets.forEach(function (d) {
          // d.path is attacker-influenced (client JSON key). textContent
          // renders it inert; never innerHTML.
          var li = el("li");
          li.textContent = d.type + " @ " + d.path + " -> " + d.action;
          ul.appendChild(li);
        });
        dcell.appendChild(ul);
      }
      tr.appendChild(dcell);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    body.appendChild(table);
  }

  function showError(id, message) {
    var body = document.getElementById(id);
    clear(body);
    body.appendChild(el("p", message, "error"));
  }

  function load() {
    getJson("/api/chain").then(renderChain).catch(function () { showError("chain-body", "Failed to load chain status."); });
    getJson("/api/summary").then(renderSummary).catch(function () { showError("summary-body", "Failed to load summary."); });
    getJson("/api/events?limit=50").then(renderEvents).catch(function () { showError("events-body", "Failed to load events."); });
  }

  document.getElementById("refresh-btn").addEventListener("click", load);
  load();
})();
`;

// Read-only fixed asset map. Keyed by exact request path. Values carry the
// content-type the dashboard serves. A request path not present here is a 404
// (no fs, no traversal).
export const ASSETS = new Map([
  ["/assets/app.js", { contentType: "text/javascript; charset=utf-8", body: APP_JS }],
  ["/assets/app.css", { contentType: "text/css; charset=utf-8", body: APP_CSS }]
]);
