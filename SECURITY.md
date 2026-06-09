# Security Policy

## Scope

This repository is an early self-hosted security toolkit. It is not a compliance certification, legal opinion, or assurance report.

Release risk tracking is maintained in `docs/current/risk-register-release-gate.md`. The current npm release gate is blocked until the P0 release risks in that document are closed.

## Supported Versions

Only the current `0.3.x` development line is considered in scope.

## Reporting

Report suspected vulnerabilities privately to the repository maintainer. Do not include real secrets, production prompts, customer data, or personal information in reports.

## Security Invariants

- Audit output must not contain raw sensitive payload values.
- Encryption must bind ciphertext to canonical AAD.
- Policy enforcement must prefer blocking over leaking plaintext when configuration is invalid.
- Plugin/provider implementations that read plaintext or use network egress must declare that capability in future plugin manifests.
