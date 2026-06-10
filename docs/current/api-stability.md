# Haechi API Stability Policy

- Status: Draft 0.1
- Date: 2026-06-10
- Target version: 0.4.0

## 1. Version Interpretation

0.x releases are developer previews. Public exports are available for use but are not considered stable API.

| Version range | Meaning |
|---|---|
| `0.3.x` | local inference/proxy safety patch line |
| `0.4.x` | token round-trip and adoption line |
| `0.5.x` | streaming hardening target |
| `0.6.x` | auth and operational controls target |
| `1.0.0` | First stable candidate at which an API compatibility contract may be declared |

## 2. Change Policy

| Change type | 0.x handling |
|---|---|
| Strengthening security defaults | Allowed in patch |
| Blocking unsafe config | Allowed in patch |
| Removing or renaming exports | Allowed in minor; migration note required in README |
| Changing policy action semantics | Requires minor or higher |
| Changing audit schema | Requires minor or higher |
| Changing crypto envelope format | Requires minor or higher; backward handling required |

## 3. Experimental exports

The following exports are treated as preview in 0.4.0.

- `haechi/runtime`
- `haechi/proxy`
- `haechi/protocol-adapters`
- `haechi/privacy-profiles`
- `haechi/plugin`
- `haechi/mcp-stdio` `wrapMcpChild`
- `haechi/token-vault` `detokenize`, deterministic tokenization options
- `injection` detection type and its heuristic rules
- `identity` audit field and the `authProvider` contract (reserved in 0.4, implemented in 0.6 — shape may change until then)
- `status` / `audit-verify` CLI output shapes
- `haechi/stream-filter` (`inspectResponseStream`, path helpers) and `createStreamProtector` (streaming inspection internals)

## 4. Migration note criteria

A migration note is added to `docs/current/release-*.md` or the README whenever any of the following changes occur.

- Adding or removing a config key
- Changing default enforcement behavior
- Adding or removing a CLI flag
- Changing an audit event field
- Changing the token format
- Changing the plugin manifest schema
