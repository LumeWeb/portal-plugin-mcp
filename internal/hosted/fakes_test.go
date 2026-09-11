package hosted

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.lumeweb.com/mcpplane/sdk"
)

// fakeServer produces a minimal, real go-sdk MCP server for boundary tests so
// the assembled handler can actually be served. No tools are registered; the
// catalog/runtime assembly is the BuildServer seam under test.
func fakeServer() *sdk.Server {
	return mcp.NewServer(
		&mcp.Implementation{Name: "portal-plugin-mcp-test", Version: "test"},
		&mcp.ServerOptions{},
	)
}
