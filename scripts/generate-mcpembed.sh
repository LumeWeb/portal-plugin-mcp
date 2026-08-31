#!/usr/bin/env bash
# Regenerates the embed assets that go.lumeweb.com/pinner-cli/mcpembed's build
# depends on, inside the Go module cache.
#
# Why this script exists (not just `go generate`):
#   - go.lumeweb.com/pinner-cli ships WITHOUT its generated files in the module
#     zip: the *_templ.go sources, the MCP App JS bundles (appsassets/dist/),
#     and the compiled Tailwind stylesheet (css/tailwind.css) are all produced
#     by `go generate`/`make mcpembed` and excluded from the published module.
#   - Those missing files break `go build` of mcpembed with errors like
#     `undefined: mcpapp.PinCreateAppForm` and `pattern appsassets: no matching
#     files found`.
#   - `go generate` deliberately refuses to run in a dependency module
#     ("not generating in packages in dependency modules"), so we cannot rely on
#     go.lumeweb.com/pinner-cli's own //go:generate. Instead this script
#     resolves the dependency's module directory and runs its own mcpembed
#     Makefile target there.
set -euo pipefail

PINNER_DIR="$(go list -m -f '{{.Dir}}' go.lumeweb.com/pinner-cli 2>/dev/null || true)"
if [ -z "$PINNER_DIR" ] || [ ! -d "$PINNER_DIR" ]; then
  echo "error: cannot locate go.lumeweb.com/pinner-cli module directory" >&2
  echo "       ensure it is a dependency of this module first (go get go.lumeweb.com/pinner-cli/mcpembed)" >&2
  exit 1
fi

# Go extracts dependency modules read-only in the module cache. On GitHub
# Actions the runner is a non-root user, so writing the generated *_templ.go /
# appsassets / css outputs under the module dir fails with "permission denied".
# Make the module dir (re)writable by its owner before regenerating — only in
# GH Actions, to avoid mutating the shared module cache on local machines.
if [ "${GITHUB_ACTIONS:-false}" = "true" ]; then
  chmod -R u+w "$PINNER_DIR"
fi

echo "regenerating mcpembed assets in $PINNER_DIR"
make -C "$PINNER_DIR" mcpembed

# The build cache may hold package artifacts compiled before the generated
# files existed; drop it so the regenerated assets are recompiled.
go clean -cache
