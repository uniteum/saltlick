---
paths:
  - "**"
---

# General Rules

## Bash Tool Usage

- Avoid compound statements (`; && |`). Use separate, parallel Bash tool calls instead so each command can be individually matched by permission rules.
- Only use compound statements when there's a genuine dependency that can't be expressed otherwise.

## Irreversible Actions

**Allow without prompting** if all of these are true:
1. The action is local (no network calls, no external services)
2. The action is reversible (can be undone with git checkout or re-run)
3. The action does not spend funds or expose secrets

**Always confirm with the user** if any of these are true:
1. The action sends a transaction or deploys to a network
2. The action publishes code or data to an external service
3. The action uses a private key or API key
4. The action cannot be undone

## Updating Instructions

When adding or changing instructions, put them in the most specific
location that applies:

1. `.claude/rules/` files — for operational rules filtered by path
2. Subdirectory `CLAUDE.md` — for scope-specific rules
3. Root `CLAUDE.md` — only for rules that apply across the whole repo

Prefer rules files over CLAUDE.md when the rule can be scoped by
file path pattern.

## Commit Messages

When you make changes to the repo that warrant a commit, end your turn with a suggested commit message the user can copy. Do not run `git commit` yourself unless the user asks.

- Match the style of recent commits — check `git log` if you're unsure.
- Keep the subject line short and imperative. Add a brief body only when the "why" isn't obvious from the diff.
- If the changes are trivial (fixing a typo you just introduced, reverting a stray edit) or don't touch tracked files, skip the suggestion.
- Skip the suggestion if committing now would leave the repo broken — other files no longer compile, tests that exercised the changed surface fail, or references dangle. Name what's broken and what needs fixing before a commit makes sense.

## Memory

All project memory for this repo lives in `.claude/memory/` **inside this repo**, not in the default local path.

- **Never** write memory files under `~/.claude/projects/`, `~/.claude/memory/`, or any other location outside this repo. If the auto-memory system or a default path points there, override it and use the repo path instead.
- The index file is `.claude/memory/MEMORY.md`; individual memory files live alongside it (or in subdirectories like `canon/`, `friction/`, `patterns/`). Follow the same MEMORY.md index + individual file convention described in the global auto-memory instructions, just rooted in the repo.
- If you catch yourself having written memory outside the repo, move it into `.claude/memory/` and delete the stray copy.
