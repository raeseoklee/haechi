# Security Policy

## Scope

This repository is an early self-hosted security toolkit. It is not a compliance certification, legal opinion, or assurance report.

## Supported Versions

Only the current `0.1.x` development line is considered in scope.

## Reporting

Report suspected vulnerabilities privately to the repository maintainer. Do not include real secrets, production prompts, customer data, or personal information in reports.

## Security Invariants

- Audit output must not contain raw sensitive payload values.
- Encryption must bind ciphertext to canonical AAD.
- Policy enforcement must prefer blocking over leaking plaintext when configuration is invalid.
- Plugin/provider implementations that read plaintext or use network egress must declare that capability in future plugin manifests.
