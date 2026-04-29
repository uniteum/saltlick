---
paths:
  - "lib/**"
---

# Submodule Maintenance

## Branch rule

Everything under `lib/` is a git submodule with its own repo.
**Before committing any change inside any `lib/` subdirectory:**

1. `cd` into the submodule directory.
2. Run `git checkout main` — never commit on a detached HEAD.
3. Make the change and commit on `main`.
4. `cd` back to the parent repo and stage the updated submodule pointer.

This keeps each submodule's history linear on `main` and avoids orphaned
commits that require cherry-picks to recover.

## Other guidelines (crucible)

- Consumer repos receive shared crucible files as **copies**, refreshed
  by `.claude/skills/smelt/smelt.sh`. The `FILES` array in that script
  is the authoritative list — keep it in sync with the "Files" table
  in the crucible README when adding or removing shared files.
- To refresh a consumer repo (including converting legacy symlinks to
  copies), run `bash lib/crucible/.claude/skills/smelt/smelt.sh` from
  the consumer repo root, or invoke `/smelt` in Claude Code.
- To find legacy symlinks still pointing into the submodule:
  `find . -maxdepth 4 -type l -lname '*lib/crucible*'`
