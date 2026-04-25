#!/usr/bin/env bash
# Copy crucible files into this repo. Replaces any existing file or
# directory symlink (or hardlink) into lib/crucible with a plain copy
# of the same content.
#
# Run from the consumer repo root:
#   bash lib/crucible/.claude/skills/smelt/smelt.sh

set -euo pipefail

SUB=lib/crucible

if [ ! -d "$SUB" ]; then
    echo "error: $SUB not found. Run from the consumer repo root." >&2
    echo "If this is a brand-new repo, first add the submodule:" >&2
    echo "  git submodule add git@github.com:uniteum/crucible.git $SUB" >&2
    exit 1
fi

# Files to copy. Each entry is a path relative to both $SUB and the
# repo root — the file lands at the same location in the consumer.
FILES=(
    foundry.toml
    .mcp.json
    .vscode/settings.json
    .claude/settings.json
    .claude/rules/always.md
    .claude/rules/lint.md
    .claude/rules/solidity.md
    .claude/rules/crucible-tests.md
    .claude/rules/submodule.md
    .claude/skills/bitsify/SKILL.md
    .claude/skills/smelt/SKILL.md
    .claude/skills/smelt/smelt.sh
)

# Pre-pass: replace any directory-symlink ancestor that points into
# $SUB with a real directory, so later cp doesn't resolve dst back to
# src via a symlinked ancestor (which would make rm destroy the source).
real_sub="$(realpath "$SUB")"
for f in "${FILES[@]}"; do
    d="$(dirname "$f")"
    while [ "$d" != "." ] && [ "$d" != "/" ]; do
        if [ -L "$d" ]; then
            tgt="$(realpath "$d")"
            case "$tgt" in
                "$real_sub"|"$real_sub"/*)
                    rm "$d"
                    mkdir -p "$d"
                    echo "  $d/ (symlink -> real dir)"
                    ;;
            esac
        fi
        d="$(dirname "$d")"
    done
done

for f in "${FILES[@]}"; do
    src="$SUB/$f"
    dst="$f"

    if [ ! -f "$src" ]; then
        echo "skip $f (not in $SUB)"
        continue
    fi

    mkdir -p "$(dirname "$dst")"

    # Replace any existing symlink, or break any hardlink sharing the
    # same inode as the source, before copying.
    if [ -L "$dst" ] || [ "$src" -ef "$dst" ]; then
        rm "$dst"
    fi

    cp "$src" "$dst"

    if [[ "$f" == *.sh ]]; then
        chmod +x "$dst"
    fi

    echo "  $f"
done

# .gitignore is copied only if the repo doesn't already have one, so
# per-repo patterns aren't clobbered.
if [ ! -f .gitignore ]; then
    cp "$SUB/.gitignore" .gitignore
    echo "  .gitignore (new)"
fi

echo "done."
