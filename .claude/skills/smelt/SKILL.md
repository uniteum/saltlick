---
name: smelt
description: >-
  Set up or refresh a repo to follow the crucible pattern — shared Foundry
  config, Claude Code rules, skills, and deployment scripts consumed via the
  crucible git submodule, copied into the repo rather than symlinked. Use
  when the user wants to smelt a repo, add crucible to a new repo, or sync
  crucible updates into an existing repo (including converting legacy
  symlinks to copies).
disable-model-invocation: true
allowed-tools: Read, Bash, Edit, Write
---

# Smelt — Apply the crucible pattern to a repo

"Smelting" a repo means pouring the current crucible config into it:
Foundry settings, Claude Code rules, skills, and the Etherscan MCP
config. Files are **copied**, not symlinked — each smelt run refreshes
the copies from the submodule.

Consumer repos built before this skill existed used symlinks. When you
smelt one of those, the script replaces each symlink with a copy of the
same content.

## Step 0: Confirm location

Run `pwd` and `git rev-parse --show-toplevel`. Confirm you are at the
root of the **consumer** repo, not inside the crucible submodule itself.
If the top-level is `uniteum/crucible`, stop — smelt is for consumers.

Run `git status`. If there are unrelated uncommitted changes, ask the
user before proceeding so the smelt diff stays isolated.

## Step 1: Identify mode

- **New repo**: `lib/crucible/` does not exist. Go to step 2.
- **Update**: `lib/crucible/` already exists. Skip step 2. Ask the user
  whether to pull the latest crucible first with
  `git submodule update --remote lib/crucible` — do not run it without
  their ok, since it changes the submodule pointer.

Also detect legacy symlinks so you can tell the user what to expect:

```bash
find . -maxdepth 4 -type l -lname '*lib/crucible*' 2>/dev/null
```

If any are printed, the smelt run will replace them with copies.

## Step 2 (new repos only): install the submodule

```bash
forge install foundry-rs/forge-std
git submodule add git@github.com:uniteum/crucible.git lib/crucible
```

## Step 3: Copy crucible files

From the repo root:

```bash
bash lib/crucible/.claude/skills/smelt/smelt.sh
```

The script:
- copies every file listed in its `FILES` array from `lib/crucible/`
  into the matching path in the consumer repo;
- deletes any existing symlink before copying, so legacy symlinks are
  replaced with real files;
- copies `.gitignore` only if the repo doesn't already have one, so
  per-repo patterns aren't clobbered.

The list of files is authoritative in `smelt.sh` — not in this file
and not in the README. If a new shared file is added to crucible, add
it to the `FILES` array.

## Step 4 (new repos only): create remappings.txt

```
forge-std/=lib/forge-std/src/
crucible/=lib/crucible/
```

Add lines for any other submodule dependencies the repo uses.

## Step 5 (new repos only): create source directories

```bash
mkdir -p src test script
```

## Step 6: Verify

```bash
forge build
```

For update mode, also run `git diff` and `git status` and walk the
user through the changed and newly-created files. Point out that
symlinks were replaced with copies if that happened. For new repos,
prompt the user to review and commit.

## Step 7: Do not commit without asking

Smelt changes config files that affect every build. Summarize what
changed and let the user stage and commit.
