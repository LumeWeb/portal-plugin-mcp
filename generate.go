package mcp

//go:generate bash ./scripts/generate-mcpembed.sh
//
// Regenerates the go.lumeweb.com/pinner-cli/mcpembed embed assets that this
// module requires before it can build (the module proxy ships pinner-cli
// without its generated *_templ.go, app JS bundles, and compiled CSS). See
// scripts/generate-mcpembed.sh for details.
