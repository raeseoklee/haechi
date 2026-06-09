# Security Policy

## Scope

This repository is an experimental self-hosted security toolkit. It is not production-ready and is not a compliance certification, legal opinion, or assurance report.

Release risk tracking is maintained in `docs/current/risk-register-release-gate.md`. npm release checks must pass `npm run release:preflight`; actual npm publication additionally requires `npm run release:preflight:npm` from an authenticated npm account.

## Supported Versions

Only the current `0.3.x` development line is considered in scope.

## Reporting

Report suspected vulnerabilities privately to the repository maintainer. Do not include real secrets, production prompts, customer data, or personal information in reports.

## Security Invariants

- Audit output must not contain raw sensitive payload values.
- Encryption must bind ciphertext to canonical AAD.
- Policy enforcement must prefer blocking over leaking plaintext when configuration is invalid.
- Proxy listeners must stay loopback-only unless remote binding is explicitly enabled and the deployment supplies network access controls.
- Streaming payloads are not inspected in 0.3.x and must fail closed unless the operator explicitly selects pass-through.
- Plugin/provider implementations that read plaintext or use network egress must declare that capability in plugin manifests.

## Local Development Keys

`haechi init` creates `.haechi/dev.keys.json` for local development. Treat this file as a disposable development secret. Do not reuse it for production data, shared environments, compliance evidence, or internet-facing gateways.
