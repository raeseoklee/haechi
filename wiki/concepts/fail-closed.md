---
updated: 2026-06-10
tags: [concept, security, invariant]
---

# Fail-Closed

The project's central design philosophy: when Haechi cannot positively verify that something is safe, it refuses rather than degrades. Every enforcement-path ambiguity resolves to denial.

## Where it is enforced

| Surface | Behavior |
|---|---|
| Config validation | Unknown providers, invalid reveal policies, bad failure modes, unknown `target.type` → throw at load |
| Response protection | Non-JSON, invalid JSON, compressed, oversized → 502 unless explicitly allowed; oversized is a hard deny even in `failureMode: "allow"` |
| Streaming | `stream: true` → 501 unless `pass-through` opted in; Ollama chat/generate treated as streaming unless `stream: false` ([[streaming-protection-gap]]) |
| Proxy bind | Non-loopback hosts refused without `--allow-remote-bind` |
| Policy merges | Weakening a stronger action throws (`ACTION_STRENGTH`); privacy profiles may only strengthen |
| Token reveal | `revealPolicy: "disabled"` by default ([[token-vault]]) |
| MCP filter | Non-2.0 JSON-RPC, disallowed methods, batch arrays → rejected; notifications dropped silently per spec |
| Plugin manifests | Only `runtime: "manifest-only"` accepted — no dynamic execution |

## The tension to manage

Fail-closed defaults conflict with adoption friction: the default config is `dry-run` + responseProtection off, which protects nothing. The compromise (0.3.2) is loud warnings at proxy startup and in `protect` output, plus the planned `haechi status` command ([[release-roadmap]] 0.4). Bypasses that ARE allowed (streaming pass-through, response allow-mode) always leave an audit decision record ([[audit-integrity]]).
