.PHONY: build test assets clean

TAGS ?= no_tunnel

# assets stages the go.lumeweb.com/pinner/canvasassets embed inputs (the MCP
# App ESM bundles, mcpcanvas manifest, and compiled Tailwind theme) wherever
# this build resolves the pinner module — pinned pseudo-version in the module
# cache, or a checkout — regenerating them in place when absent. Those embeds
# are owned by the pinner module, so this plugin needs no JS/CSS toolchain of
# its own; staging delegates to pinner's shared ensure-canvasassets.sh.
assets:
	bash scripts/ensure-canvasassets.sh

build: assets
	go build -tags "$(TAGS)" ./...

test: assets
	go test -tags "$(TAGS)" ./...

clean:
	go clean -cache ./...
