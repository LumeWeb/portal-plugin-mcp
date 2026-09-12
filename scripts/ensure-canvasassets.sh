#!/usr/bin/env bash
# Stage pinner's canvasassets embed inputs (ESM bundles, mcpcanvas manifest,
# Tailwind theme) into whichever checkout of the pinner module go resolves.
# The embeds are regenerated, not committed, and the read-only module cache
# copy arrives without them. Delegate to pinner's own staging script so every
# consumer (CLI, hosted server/plugin) stages identically.
set -euo pipefail

MODULE="go.lumeweb.com/pinner"

# A fresh checkout may not have downloaded the module yet.
go mod download "$MODULE" 2>/dev/null || true

DIR="$(go list -m -f '{{.Dir}}' "$MODULE" 2>/dev/null || true)"
if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then
    echo "!! ensure-canvasassets: cannot resolve $MODULE dir; run 'go mod download go.lumeweb.com/pinner' first" >&2
    exit 1
fi

if [ ! -f "$DIR/scripts/ensure-canvasassets.sh" ]; then
    echo "!! ensure-canvasassets: $MODULE is pinned before the shared staging script existed; bump go.lumeweb.com/pinner in go.mod" >&2
    exit 1
fi

# shellcheck disable=SC1090
source "$DIR/scripts/ensure-canvasassets.sh" "$MODULE"

# CI starts with an empty cache, so only clear it locally to force the
# canvasassets package to recompile against the freshly staged embeds.
if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    go clean -cache
fi
