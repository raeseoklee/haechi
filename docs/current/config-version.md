# Haechi `configVersion` & Upgrade Notes

- Status: Living document (tracks core 1.7.x)

`configVersion` is a single integer stamped at the top of `haechi.config.json`
(and `haechi.config.example.json`). It is a **versioned anchor** so a future
breaking config-schema change has something concrete to gate on, rather than
silently mis-reading a config written by a different Haechi build.

## Behavior

- **Default / absent:** a config that omits `configVersion` (e.g. a 1.1 file
  written before the stamp existed) is treated as the **current** version. Adding
  the field changed nothing for existing configs.
- **Current version:** `1`.
- **Fail-closed on newer/unknown:** a `configVersion` **greater** than the build
  understands throws at load — a config a *newer* Haechi wrote may rely on
  semantics this build does not implement, so Haechi refuses rather than guessing.
  Upgrade Haechi, or lower the stamp once you have confirmed compatibility.
- **Fail-closed on malformed:** a non-positive or non-integer `configVersion`
  throws (`configVersion must be a positive integer`).

This is the same fail-closed posture as the rest of `normalizeConfig`: an
ambiguous or forward-dated config stops the gateway rather than degrading it.

## Why fail-closed on a newer version

A security gateway that silently runs an unfamiliar config could, for example,
ignore a future enforcement key it does not recognize and run weaker than the
operator intended. Refusing to start surfaces the mismatch immediately and keeps
the "policies only get stronger / fail closed" invariant intact.

## Version map

| `configVersion` | Core line | Notes |
|---|---|---|
| `1` | 1.0 – 1.7.x | Initial stamp. All keys are additive over the 1.0 frozen config surface (`api-stability.md` §2.4). The 1.1.x additive keys (`logging`, `metrics`, the WS4-B `limits.maxInFlight` / `limits.shutdownGraceMs` / `limits.requestTimeoutMs` / `limits.headersTimeoutMs`, `configVersion` itself) and the 1.2.0 Reliability-Hardening keys (`filters.minConfidence` / `filters.allowlist`, `proxy.tls` / `proxy.trustForwardedProto`) all default to prior behavior. The 1.3.0 additions are new *values*, not new keys — `target.type` `anthropic`/`gemini`, additional detection types, and the `asia-pdpa`/`jp-appi` `privacy.profile` values. The 1.4.0 plugin-signing CLI (`plugin-keygen`/`plugin-sign`/`plugin-verify`) is **CLI surface, not config**. The 1.5.0 store seams (`createAuditSink`/`createTokenVault` + the file-store defaults) are an **injected-provider** surface. The 1.6.0 nonce-budget visibility and 1.7.0 v2 crypto-AAD/freshness changes are crypto envelope/API behavior, not config keys. So the config schema (and `configVersion`) is unchanged. No migration needed. |

## Upgrading

When a future minor adds config keys, they remain **additive** (default to prior
behavior) and `configVersion` stays `1` — no action required. `configVersion`
will only be **bumped** alongside a deliberate breaking schema change, which would
also carry a major version bump and a deprecation note per `api-stability.md`
§2.2. At that point this table gains a row describing the migration, and a config
stamped with the older version is migrated (or read under compatibility rules)
explicitly — never silently.

To pin: set `"configVersion": 1` at the top of your config (the example config
already does). To upgrade Haechi past a future schema bump, follow the migration
row for the target version before raising the stamp.
