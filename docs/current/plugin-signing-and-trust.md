# Plugin Signing & Trust-Anchor Curation

- Status: Living document (tracks core 1.5.x)
- Date: 2026-06-17

Haechi's default is **dependency injection** — you pass an `authProvider` to
`createRuntime(config, providers)` and no code is loaded dynamically. The signed-
plugin sandbox (`auth.provider: "plugin"`) is the **opt-in** exception: it loads a
third-party `authProvider` only when the operator has signed it with a key they
control and allowlisted that key as a **trust anchor**. The load-bearing control
is that trust gate (Ed25519 signature + operator allowlist + pin/floor/revocation),
not the sandbox isolation — see [`api-stability.md`](api-stability.md) and the
[threat model](threat-model.md).

This runbook is the end-to-end authoring + curation flow using the `haechi
plugin-*` CLI. For the full `auth.plugin.*` key reference see
[`configuration.md`](configuration.md#authplugin-signed-authprovider-sandbox).

## 1. Generate a signing keypair

```bash
haechi plugin-keygen --key-id acme-signer --out-dir ./keys
```

- Writes `./keys/acme-signer.key` — the **private** signing key (PKCS8 PEM, mode
  `0600`). Keep it offline / in your own secret store; Haechi never reads it at
  runtime and never needs it on the gateway host.
- Writes `./keys/acme-signer.pub` — the **public** key (SPKI PEM). This is the
  **trust anchor** you give operators; it is safe to commit/distribute.
- The JSON output carries only the paths and the public PEM — **never** the
  private key material.

Use a stable, meaningful `keyId` (it labels the anchor in config and the audit
log). One signer key can sign many plugins.

## 2. Sign a plugin

Sign the **exact** entry-file bytes — the signature binds `sha256(entry bytes)`,
so any later edit to the plugin source invalidates it.

```bash
haechi plugin-sign ./acme-auth.mjs \
  --key ./keys/acme-signer.key \
  --signer-key-id acme-signer \
  --plugin-id acme-auth \
  --kind authProvider \
  --plugin-version 1.0.0 \
  --core-range ">=1.0.0 <2.0.0" \
  --capabilities '{"readsCredentials":true}' \
  --out acme-auth.signed.json
```

- An `authProvider` plugin **must** declare `readsCredentials: true` (core rejects
  one that does not). `--capabilities` also accepts `@path` to read a JSON file.
- The private key is read from the `--key` **file**, never the command line (a key
  in argv leaks into shell history and the process table).
- Optional `--not-before` / `--not-after` (epoch ms) bound a signing window.
- Writes the signed envelope `{ payload, signerKeyId, alg, signature }` to
  `--out` (default `<pluginId>.signed.json`).

## 3. Verify before you trust it

`plugin-verify` runs the **same** verification the runtime does at load, so you
can confirm an envelope is good before wiring it in. It **fails closed**: any
refusal exits non-zero with the stable `PluginLoadError` reason (the gate signal);
it never prints `valid:true` on a bad envelope.

```bash
haechi plugin-verify acme-auth.signed.json \
  --entry ./acme-auth.mjs \
  --anchor ./keys/acme-signer.pub \
  --allow-capability readsCredentials \
  --core-version 1.3.3
```

- `--allow-capability <name>` (repeatable) is the verifier's capability allowlist.
  It is **required** to verify an `authProvider` (its mandatory `readsCredentials`
  is not allowlisted by default) — without it you get a fail-closed
  `capability-not-allowlisted`.
- Resolve anchors from an explicit `--anchor <pub.pem>` (with `--anchor-key-id`,
  default the envelope's `signerKeyId`) **or** from a running config with
  `--config haechi.config.json` (reads `auth.plugin.trustAnchors`).
- `--pin <entrySha256>` and `--core-version <v>` exercise the pin / range checks.

Common refusal reasons: `tampered-entry` (entry edited after signing),
`invalid-signature` (wrong key / mutated signature), `unknown-signer` (anchor not
allowlisted), `alg-not-ed25519`, `expired-window`, `below-version-floor`,
`revoked`, `pin-mismatch`, `capability-not-allowlisted`.

## 4. Wire the trust anchor into config

Paste the **public** key as a trust anchor and allowlist exactly the capabilities
the plugin needs (no more):

```jsonc
{
  "auth": {
    "provider": "plugin",
    "plugin": {
      "manifestPath": "acme-auth.signed.json",
      "trustAnchors": [
        { "keyId": "acme-signer", "publicKey": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n" }
      ],
      "allowCapabilities": ["readsCredentials"],
      "isolation": "process"
    }
  }
}
```

- `trustAnchors` accepts the array-of-`{keyId, publicKey}` form above or a
  `{ keyId: publicKey }` map. Key resolution is **trust-anchor-only** — a signer
  key not listed here is `unknown-signer`, fail-closed.
- Prefer `isolation: "process"` (kernel-enforced capability denial; requires a
  Node that enforces `--allow-net`) over the default `worker` where you can.
- `plugins.enabled: false` is a global kill-switch that refuses to construct any
  plugin.

## 5. Rotate, pin, and revoke (curation lifecycle)

The operator owns the trust anchors — curate them deliberately:

- **Rotate a signer key.** `plugin-keygen` a new key, re-sign the plugin with it,
  and **add** the new anchor to `trustAnchors` alongside the old one. Once every
  deployed plugin is re-signed, remove the old anchor. Never silently drop an
  anchor that live envelopes still depend on (that is a fail-closed outage).
- **Pin an exact build.** `auth.plugin.pin: { version?, entrySha256?, manifestSha256? }`
  refuses anything but the pinned build — defense against a malicious update or a
  rollback. Use the `entrySha256` that `plugin-sign` printed.
- **Set a version floor.** `auth.plugin.versionFloor: { "<pluginId>": "<min>" }`
  refuses any version below the floor (anti-rollback) without pinning an exact
  build.
- **Revoke.** `auth.plugin.revoked: { signerKeyIds?: [...], entrySha256?: [...] }`
  denylists a compromised signer key or a specific bad build; revocation is
  fail-closed at load. Revocation takes effect at the **next load** (a restart, or
  the kill-switch to force-drop a live plugin) — a live revocation feed is future
  work (P1-SEC-025 residual).

## 6. Operator checklist

- [ ] Private signing key stored offline / in a secret store, never on the gateway host.
- [ ] Only the public key is in `trustAnchors`; `allowCapabilities` is the minimal set.
- [ ] Envelope verified with `plugin-verify` (matching `--core-version`) before deploy.
- [ ] A rotation plan exists (add-new-then-remove-old) and `pin`/`versionFloor` are set for production.
- [ ] `isolation: "process"` on a `--allow-net`-enforcing Node where possible.

See also: [`configuration.md`](configuration.md#authplugin-signed-authprovider-sandbox),
[`threat-model.md`](threat-model.md), [`api-stability.md`](api-stability.md).
