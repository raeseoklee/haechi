# `@haechi/crypto-kms`

A KMS-backed `cryptoProvider` for Haechi's `keys.provider: external` path. It lives in the Haechi monorepo under `satellites/` and is published independently as `@haechi/crypto-kms`. Core (`haechi`) stays zero-runtime-dependency; this satellite carries any KMS-client dependency itself.

## How it works

Envelope encryption: each `encrypt` generates a fresh AES-256-GCM **data key**, encrypts the plaintext locally, and **wraps the data key with the KMS**. The KMS master key never leaves the KMS. `decrypt` unwraps the data key via the KMS and decrypts locally. `hmac` derives a per-domain key from the KMS, preserving Haechi's domain-separation discipline (tokens, identity, policy bundles).

The envelope matches Haechi's contract (`v, alg, kid, iv, ct, tag, aadHash`) plus a `wrappedKey`. AAD is canonicalized with `canonicalize` imported directly from `haechi/crypto` (no local copy), so it is byte-for-byte identical to the core provider's AAD and passes `assertCryptoProviderConformance`.

## Install

```sh
npm install @haechi/crypto-kms        # peer: haechi >=0.8.0 <1.0.0
```

The satellite reuses your installed `haechi` instance (declared as a peer dependency), so there is a single crypto/identity surface.

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

`createInMemoryKms()` is a process-local stand-in for examples/tests. A real deployment swaps in an AWS KMS / HashiCorp Vault client. (The real AWS KMS client backed by `@aws-sdk/client-kms` lands as a satellite-only dependency in a follow-up — it never touches core.)

## Usage

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

This satellite is **not a production key provider** on its own; `createInMemoryKms` holds a process-local master key. Use a real KMS client for custody.
