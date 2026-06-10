# Release 0.2 Implementation Scope

- Status: Draft 0.1
- Date: 2026-06-09
- Target version: Haechi

## 1. Goals

0.2 reinforces the security trust boundary and replaceability on top of the 0.1 quickstart.

Included scope:

- Local encrypted TokenVault
- Signed policy bundle signing/verification
- Plugin manifest validation
- MCP stdio JSON-RPC line filter skeleton
- Related CLI commands and tests

## 2. New CLI Commands

```bash
node packages/cli/bin/haechi.mjs policy-sign policy.json --out policy.bundle.json
node packages/cli/bin/haechi.mjs policy-verify policy.bundle.json
node packages/cli/bin/haechi.mjs plugin-validate examples/plugins/custom-filter.plugin.json
node packages/cli/bin/haechi.mjs token-reveal <token>
node packages/cli/bin/haechi.mjs token-purge <token>
node packages/cli/bin/haechi.mjs mcp-stdio --config haechi.config.json
```

## 3. Excluded Scope

- Live integration with external Vault/AWS/GCP/Azure KMS
- Dynamic loading of plugin code
- MCP server child process lifecycle management
- Automated generation of signed release artifacts and SBOM
- Python SDK

## 4. Completion Criteria

| Criterion | Done When |
|---|---|
| TokenVault | `tokenize` action stores mappings in an encrypted local vault |
| Signed policy | Runtime load fails when policy bundle signature verification fails |
| Plugin manifest | `capability` and `dataHandling` fields are validated |
| MCP stdio | JSON-RPC `params`/`result` payloads are protected |
| Tests | token vault, policy bundle, plugin manifest, and MCP stdio fixtures pass |
