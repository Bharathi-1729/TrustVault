# TrustVault Prompt Files

TrustVault includes reusable GitHub Copilot prompt files in
[`.github/prompts/`](./.github/prompts/). In VS Code, open Copilot Chat, type
`/`, and choose a prompt from the list.

| Prompt | Use it for |
|---|---|
| [`trustvault-feature.prompt.md`](./.github/prompts/trustvault-feature.prompt.md) | Implementing a feature while preserving TrustVault authorization and privacy boundaries. |
| [`trustvault-debug.prompt.md`](./.github/prompts/trustvault-debug.prompt.md) | Reproducing and fixing a bug using runtime and test evidence. |
| [`trustvault-tests.prompt.md`](./.github/prompts/trustvault-tests.prompt.md) | Adding focused tests with disposable databases and security edge cases. |
| [`trustvault-release-check.prompt.md`](./.github/prompts/trustvault-release-check.prompt.md) | Checking production settings, persistence, administrator setup, backups, and deployment tests. |
| [`trustvault-threat-review.prompt.md`](./.github/prompts/trustvault-threat-review.prompt.md) | Reviewing a change or scenario against the project threat model in [`THREATS.md`](./THREATS.md). |

Each prompt accepts a task-specific description when selected. The prompts
guide the agent to inspect existing patterns, protect private document
contents, and report only checks that were actually performed.
