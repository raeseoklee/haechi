// WS4-A telemetry seam (reliability-hardening-track §WS4 "Telemetry").
//
// A minimal, zero-dependency in-memory metrics collector rendering the
// Prometheus text exposition format. It is an INJECTABLE collaborator
// (providers.metrics in createRuntime), mirroring auditSink/rateLimiter; an
// operator who wants a real metrics backend injects their own object exposing
// the same { increment, observe, render } contract.
//
// HARD INVARIANT (the no-plaintext-in-audit invariant, extended to telemetry):
// every metric name AND every label value is a BOUNDED ENUM — a route id, a
// policy mode, or a decision class. It is NEVER an identity id/subject, a token,
// a detected value, or any other unbounded/PII-bearing string. This module does
// not — and structurally cannot — accept a payload value: callers pass only
// pre-classified enum labels, and label values are coerced + length-capped here
// as defence in depth so an accidental high-cardinality value cannot explode
// the series set or leak content.

// Metric catalogue: name -> { type, help }. Counters and one histogram. Keeping
// the catalogue explicit (rather than letting callers invent metric names)
// bounds the metric-name dimension to this fixed set.
const COUNTERS = {
  haechi_requests_total: "Proxy requests by route, mode, and decision class.",
  haechi_blocks_total: "Requests blocked by a policy decision.",
  haechi_auth_denied_total: "Requests denied at authentication.",
  haechi_rate_limited_total: "Requests rejected by the rate limiter.",
  haechi_upstream_timeout_total: "Upstream requests that timed out.",
  haechi_upstream_error_total: "Upstream requests that failed (non-timeout).",
  haechi_response_unprotected_total: "Responses forwarded without protection (size/encoding/parse).",
  haechi_internal_error_total: "Unexpected internal proxy errors.",
  haechi_overloaded_total: "Requests rejected by the max-in-flight backpressure ceiling (503)."
};

const HISTOGRAMS = {
  haechi_request_duration_seconds: "End-to-end proxy request handling duration in seconds."
};

// Default request-duration histogram buckets (seconds). Bounded, fixed set.
const DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

// Defence-in-depth label hygiene: a label value must be a short, bounded token.
// We coerce to string, trim, cap length, and collapse anything outside a safe
// charset to "_". This guarantees that even a caller mistake cannot place a raw
// payload value or a long identity string into a series label.
const MAX_LABEL_LENGTH = 64;

function safeLabelValue(value) {
  if (value === undefined || value === null) {
    return "none";
  }
  const text = String(value).slice(0, MAX_LABEL_LENGTH);
  // Allow a conservative identifier charset only (route ids, modes, decisions
  // are all of this shape). Everything else becomes "_".
  return text.replace(/[^A-Za-z0-9_.:/-]/g, "_") || "none";
}

function seriesKey(name, labels) {
  const parts = Object.keys(labels)
    .sort()
    .map((labelName) => `${labelName}="${escapeLabel(labels[labelName])}"`);
  return parts.length > 0 ? `${name}{${parts.join(",")}}` : name;
}

function escapeLabel(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, "\\\"");
}

export function createMetrics({ buckets = DEFAULT_BUCKETS } = {}) {
  // counterSeries: metricName -> Map(seriesKey -> { labels, value })
  const counterSeries = new Map();
  // histogramSeries: metricName -> Map(seriesKey -> { labels, bucketCounts, sum, count })
  const histogramSeries = new Map();
  const sortedBuckets = [...buckets].sort((a, b) => a - b);

  function normalizeLabels(labels = {}) {
    const out = {};
    for (const [key, value] of Object.entries(labels)) {
      // Label NAMES are caller-fixed identifiers; coerce defensively anyway.
      const labelName = String(key).replace(/[^A-Za-z0-9_]/g, "_");
      out[labelName] = safeLabelValue(value);
    }
    return out;
  }

  return {
    // Increment a known counter by `amount` (default 1), labelled by a bounded
    // enum set. An unknown metric name is ignored (fail-soft for telemetry — a
    // metric typo must never break a request path).
    increment(name, labels = {}, amount = 1) {
      if (!(name in COUNTERS)) {
        return;
      }
      const safe = normalizeLabels(labels);
      const key = seriesKey(name, safe);
      let series = counterSeries.get(name);
      if (!series) {
        series = new Map();
        counterSeries.set(name, series);
      }
      const existing = series.get(key);
      if (existing) {
        existing.value += amount;
      } else {
        series.set(key, { labels: safe, value: amount });
      }
    },

    // Observe a value into a known histogram (request-duration seconds).
    observe(name, value, labels = {}) {
      if (!(name in HISTOGRAMS) || typeof value !== "number" || !Number.isFinite(value)) {
        return;
      }
      const safe = normalizeLabels(labels);
      const key = seriesKey(name, safe);
      let series = histogramSeries.get(name);
      if (!series) {
        series = new Map();
        histogramSeries.set(name, series);
      }
      let entry = series.get(key);
      if (!entry) {
        entry = { labels: safe, bucketCounts: new Array(sortedBuckets.length).fill(0), sum: 0, count: 0 };
        series.set(key, entry);
      }
      entry.sum += value;
      entry.count += 1;
      for (let i = 0; i < sortedBuckets.length; i += 1) {
        if (value <= sortedBuckets[i]) {
          entry.bucketCounts[i] += 1;
        }
      }
    },

    // Render the full Prometheus text exposition. Every declared counter and
    // histogram emits its HELP/TYPE header even with no observations, so the
    // surface is stable for scrapers.
    render() {
      const lines = [];

      for (const [name, help] of Object.entries(COUNTERS)) {
        lines.push(`# HELP ${name} ${help}`);
        lines.push(`# TYPE ${name} counter`);
        const series = counterSeries.get(name);
        if (series) {
          for (const { labels, value } of series.values()) {
            lines.push(`${seriesKey(name, labels)} ${value}`);
          }
        }
      }

      for (const [name, help] of Object.entries(HISTOGRAMS)) {
        lines.push(`# HELP ${name} ${help}`);
        lines.push(`# TYPE ${name} histogram`);
        const series = histogramSeries.get(name);
        if (series) {
          for (const entry of series.values()) {
            // bucketCounts[i] already holds the cumulative count of observations
            // with value <= sortedBuckets[i] (observe() increments every bucket
            // the value falls under), which is exactly the Prometheus le="..."
            // cumulative bucket semantics — emit it directly.
            for (let i = 0; i < sortedBuckets.length; i += 1) {
              const labels = { ...entry.labels, le: String(sortedBuckets[i]) };
              lines.push(`${seriesKey(`${name}_bucket`, labels)} ${entry.bucketCounts[i]}`);
            }
            const infLabels = { ...entry.labels, le: "+Inf" };
            lines.push(`${seriesKey(`${name}_bucket`, infLabels)} ${entry.count}`);
            lines.push(`${seriesKey(`${name}_sum`, entry.labels)} ${entry.sum}`);
            lines.push(`${seriesKey(`${name}_count`, entry.labels)} ${entry.count}`);
          }
        }
      }

      return `${lines.join("\n")}\n`;
    }
  };
}

// Exported for tests / operators who want to assert the bounded metric surface.
export const METRIC_NAMES = Object.freeze({
  counters: Object.keys(COUNTERS),
  histograms: Object.keys(HISTOGRAMS)
});
