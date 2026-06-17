// haechi-store-redis — shared-store (Redis-backed) adapters for the 1.5.0
// audit + token-vault STORE seams.
//
// The Haechi audit hash chain and tokenization vault are file-backed and
// single-writer by default. 1.5.0 added STORE injection seams to core
// (createAuditSink({ store }) and createTokenVault({ store, ... })) so the
// exclusive read-previous+persist (audit) and read-all+mutate+persist (token)
// primitives can sit on a shared store. This satellite is the production
// consumer of those seams: with these adapters the chain and the vault hold
// across REPLICAS, serialized by a Redis distributed lock.
//
// The store/client is INJECTED, so this package adds no runtime dependency to
// core — the optional `redis` peer is installed only by consumers using the
// bundled Redis adapters. Nothing here imports from `haechi` at module top
// level; the stores are injected INTO core by the consumer.
//
// Wire it:
//   import { createAuditSink } from "haechi/audit";
//   import { createTokenVault } from "haechi/token-vault";
//   import { createRedisAuditStore, createRedisTokenStore } from "haechi-store-redis";
//   const auditSink  = createAuditSink({ store: createRedisAuditStore({ client }) });
//   const tokenVault = createTokenVault({ store: createRedisTokenStore({ client }), cryptoProvider, /* ... */ });

export { createRedisAuditStore, readChain } from "./audit.mjs";
export { createRedisTokenStore } from "./token-vault.mjs";
export { createMemoryAuditStore, createMemoryTokenStore } from "./memory.mjs";
export { withRedisLock } from "./lock.mjs";
