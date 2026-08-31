package mcp

import (
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// StreamableHTTPHandler returns the official SDK streamable-HTTP handler
// bound to the given server, in stateless mode. Stateless serving uses a
// temporary session per request (no MCP-Session-Id), which is how MCP Apps
// and simple tool servers behave and avoids holding long-lived connections
// behind the portal's router.
func StreamableHTTPHandler(getServer func(*http.Request) *Server) http.Handler {
	return mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Stateless: true,
	})
}

// NewStreamableHandler builds the streamable-HTTP handler for a concrete
// server.
func NewStreamableHandler(srv *Server) http.Handler {
	return StreamableHTTPHandler(func(*http.Request) *Server { return srv })
}
