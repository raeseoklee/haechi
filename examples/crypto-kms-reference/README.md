# `@haechi/crypto-kms` (reference)

A reference KMS-backed `cryptoProvider` for Haechi's `keys.provider: external` path. This is the **shape** of the satellite published as `@haechi/crypto-kms` in 0.8 — it lives here as a dependency-free reference so core stays zero-runtime-dependency.

## How it works

Envelope encryption: each `encrypt` generates a fresh AES-256-GCM **data key**, encrypts the plaintext locally, and **wraps the data key with the KMS**. The KMS master key never leaves the KMS. `decrypt` unwraps the data key via the KMS and decrypts locally. `hmac` derives a per-domain key from the KMS, preserving Haechi's domain-separation discipline (tokens, identity, policy bundles).

The envelope matches Haechi's contract (`v, alg, kid, iv, ct, tag, aadHash`) plus a `wrappedKey`. AAD is canonicalized and bound exactly as the local provider does, so it passes `assertCryptoProviderConformance`.

## The KMS client interface

Inject any client implementing:

```js
{
  keyId: string,
  async wrap(dataKey: Buffer): string,          // KMS-encrypt a data key
  async unwrap(wrapped: string): Buffer,         // KMS-decrypt it
  async deriveHmacKey(domain: string): Buffer    // KMS-derived per-domain key
}
```

`createInMemoryKms()` is a process-local stand-in for examples/tests. A real deployment swaps in an AWS KMS / HashiCorp Vault client (e.g. `@aws-sdk/client-kms` `GenerateDataKey`/`Decrypt`, plus an HKDF for `deriveHmacKey`).

## Usage

In 0.7 this is a repo reference example — import it by relative path
(`./examples/crypto-kms-reference/index.mjs`). From 0.8 it is published as
`@haechi/crypto-kms` and imported by name, as shown below.

```js
import { createRuntime } from "haechi/runtime";
import { createKmsCryptoProvider, createInMemoryKms } from "@haechi/crypto-kms";

const cryptoProvider = createKmsCryptoProvider({ kms: createInMemoryKms() });
const runtime = createRuntime({ keys: { provider: "external" }, /* ... */ }, { cryptoProvider });
```

## Self-test

```js
import { assertCryptoProviderConformance } from "haechi/crypto";
await assertCryptoProviderConformance(cryptoProvider); // throws on any contract violation
```

This reference is **not a production key provider**; `createInMemoryKms` holds a process-local master key. Use a real KMS client for custody.
