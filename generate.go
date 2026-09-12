package mcp

//go:generate bash ./scripts/ensure-canvasassets.sh
//
// Stages the go.lumeweb.com/pinner canvasassets embed inputs (the per-app ESM
// bundles, the mcpcanvas manifest, and the compiled Tailwind theme) into
// whichever checkout of the pinner module this build resolves. The module
// proxy ships pinner without those gitignored outputs, so go:embed over
// canvasassets/appsassets fails with "pattern appsassets: no matching files
// found" until they are staged. This directive is the meta-trigger that lets
// production builds running `go generate ./...` kickstart regeneration before
// compiling. See scripts/ensure-canvasassets.sh for details.
