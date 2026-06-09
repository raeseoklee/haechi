import test from "node:test";
import assert from "node:assert/strict";
import { validatePluginManifest } from "../packages/plugin/index.mjs";

test("plugin manifest validates required capability contract", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "example-filter",
      version: "0.1.0",
      kind: "filter-engine",
      runtime: "node",
      entrypoint: "./dist/index.js",
      compatibility: {
        haechiCore: ">=0.2.0 <0.3.0"
      },
      capabilities: {
        readsPlaintext: true,
        writesPlaintext: false,
        networkEgress: false,
        fileWrite: false,
        auditWrite: false,
        externalSecrets: false
      },
      dataHandling: {
        retention: "none",
        logsRawPayload: false
      }
    }
  });

  assert.equal(result.valid, true);
});

test("plugin manifest rejects raw payload logging", () => {
  const result = validatePluginManifest({
    haechiPlugin: {
      id: "bad-filter",
      version: "0.1.0",
      kind: "filter-engine",
      runtime: "node",
      entrypoint: "./dist/index.js",
      compatibility: {
        haechiCore: ">=0.2.0 <0.3.0"
      },
      capabilities: {
        readsPlaintext: true,
        writesPlaintext: false,
        networkEgress: false,
        fileWrite: false,
        auditWrite: false,
        externalSecrets: false
      },
      dataHandling: {
        logsRawPayload: true
      }
    }
  });

  assert.equal(result.valid, false);
  assert.match(result.errors.join("\n"), /logsRawPayload/);
});
