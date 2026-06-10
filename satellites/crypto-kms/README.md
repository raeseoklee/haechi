# `haechi-crypto-kms`

A KMS-backed `cryptoProvider` for Haechi's `keys.provider: external` path. It lives in the Haechi monorepo under `satellites/` and is published independently as `haechi-crypto-kms`. Core (`haechi`) stays zero-runtime-dependency, and so does this satellite by default: a KMS-client SDK (e.g. `@aws-sdk/client-kms`) is an **optional peer dependency**, installed only by consumers who use that backend.

## How it works

Envelope encryption: each `encrypt` generates a fresh AES-256-GCM **data key**, encrypts the plaintext locally, and **wraps the data key with the KMS**. The KMS master key never leaves the KMS. `decrypt` unwraps the data key via the KMS and decrypts locally. `hmac` derives a per-domain key from the KMS, preserving Haechi's domain-separation discipline (tokens, identity, policy bundles).

The envelope matches Haechi's contract (`v, alg, kid, iv, ct, tag, aadHash`) plus a `wrappedKey`. AAD is canonicalized with `canonicalize` imported directly from `haechi/crypto` (no local copy), so it is byte-for-byte identical to the core provider's AAD and passes `assertCryptoProviderConformance`.

## Install

```sh
npm install haechi-crypto-kms        # peer: haechi >=0.8.0 <1.0.0
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

`createInMemoryKms()` is a process-local stand-in for examples/tests. For real custody, use the bundled AWS KMS client (below) or implement the same interface over another KMS / Vault.

## AWS KMS (`haechi-crypto-kms/aws`)

```js
import { createRuntime } from "haechi/runtime";
import { createKmsCryptoProvider } from "haechi-crypto-kms";
import { createAwsKmsClient } from "haechi-crypto-kms/aws";

const kms = createAwsKmsClient({
  keyId: "arn:aws:kms:us-east-1:123456789012:key/abcd…",
  region: "us-east-1",
  // Required ONLY if you tokenize/authenticate (i.e. need hmac): a base64url
  // KMS-encrypted 32-byte root. Omit for encrypt-only use.
  hmacRootCiphertext: process.env.HAECHI_HMAC_ROOT
});
const runtime = createRuntime({ keys: { provider: "external" }, /* ... */ }, {
  cryptoProvider: createKmsCryptoProvider({ kms })
});
```

The AWS client wraps a CSPRNG-generated 32-byte data key with KMS `Encrypt`/`Decrypt` (envelope encryption — the master key never leaves KMS) and derives per-domain HMAC keys with HKDF from a single KMS-decrypted root (deterministic, domain-separated, no per-token network call).

**`@aws-sdk/client-kms` is an optional peer dependency.** Install it only if you use the AWS path:

```sh
npm install haechi-crypto-kms @aws-sdk/client-kms
```

It is imported lazily, so consumers on the in-memory or an injected client never pull the SDK. For tests, inject `createAwsKmsClient({ keyId, client })` with a `{ encrypt, decrypt }` mock — no SDK or network required.

## Usage

```js
import { createRuntime } from "haechi/runtime";
import { createKmsCryptoProvider, createInMemoryKms } from "haechi-crypto-kms";

const cryptoProvider = createKmsCryptoProvider({ kms: createInMemoryKms() });
const runtime = createRuntime({ keys: { provider: "external" }, /* ... */ }, { cryptoProvider });
```

## Self-test

```js
import { assertCryptoProviderConformance } from "haechi/crypto";
await assertCryptoProviderConformance(cryptoProvider); // throws on any contract violation
```

This satellite is **not a production key provider** on its own; `createInMemoryKms` holds a process-local master key. Use a real KMS client for custody.
