# `@haechi/crypto-kms` moved

The KMS-backed `cryptoProvider` reference that used to live here has been **promoted to a published satellite**. It now lives in the monorepo at [`satellites/crypto-kms/`](../../satellites/crypto-kms/) and is published as **`@haechi/crypto-kms`**.

```sh
npm install @haechi/crypto-kms
```

```js
import { createKmsCryptoProvider, createInMemoryKms } from "@haechi/crypto-kms";
```

See [`satellites/crypto-kms/README.md`](../../satellites/crypto-kms/README.md) for usage. Core (`haechi`) stays zero-runtime-dependency; the satellite carries any KMS-client dependency itself.
