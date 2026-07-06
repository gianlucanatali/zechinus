---
name: datacloak
description: Use when reading, writing, or extending code inside datacloak/, when a consuming app needs to persist encrypted user data via defineStore/defineLabelDict, OR before writing/editing any AAD, envelope, encrypt/decrypt, or storage-upsert logic in the consuming app — that logic almost always belongs in DataCloak, not inline. Covers cardinality choice, the explicit-encryption guardrail, extending StorageAdapter, and the doc-sync convention.
---

# DataCloak — secure-store framework

Read **`datacloak/AGENTS.md`** — it is the actual guide (reflection checkpoint, cardinality
choice, versioning/fingerprint guardrails, extending `StorageAdapter`, v1 boundaries).

This file exists only so Claude Code's skill search can find and surface it by name or
description. The content itself lives in `AGENTS.md`, not here, so it stays usable by any
AI agent or tool — not just Claude Code — and travels correctly if `datacloak/` is ever
extracted into its own repository (a `SKILL.md` nested under `.claude/skills/` would not
mean anything to a different tool; a plain `AGENTS.md` at the package root does).
