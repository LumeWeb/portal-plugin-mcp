// Package mcp hosts the Model Context Protocol (MCP) server for the portal.
// It is the only package that imports the official MCP SDK
// (github.com/modelcontextprotocol/go-sdk/mcp). The API layer constructs the
// server and hands its streamable-HTTP handler to the portal router, wrapped
// in OAuth bearer-token middleware so only authorized MCP clients can reach
// it (per the MCP authorization spec).
package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server re-exports the official MCP server type so consumers in this package
// can name it without importing the SDK directly.
type Server = mcp.Server

// ImplementationVersion is the dev fallback stamped at build time.
const ImplementationVersion = "0.0.0-dev"

// Implementation returns the MCP server implementation descriptor used to
// initialize an SDK server.
func Implementation() *mcp.Implementation {
	return &mcp.Implementation{
		Name:    "portal-mcp",
		Version: ImplementationVersion,
	}
}

// ServerOptions is the SDK-neutral surface for official server options.
type ServerOptions struct {
	Instructions string
}

// NewServer builds an official-SDK MCP server pre-configured with this
// plugin's identity. Feature registration (tools, resources, prompts) is
// performed separately.
func NewServer(opts *ServerOptions) *Server {
	so := &mcp.ServerOptions{}
	if opts != nil {
		so.Instructions = opts.Instructions
	}
	return mcp.NewServer(Implementation(), so)
}

// AddTool registers a tool with the given handler. name is the tool name as
// exposed to clients; description and schema describe its input. schema is
// marshalled into the tool's JSON inputSchema.
func AddTool(srv *Server, name, description, title string, schema []byte, handler mcp.ToolHandler) error {
	if srv == nil {
		return fmt.Errorf("mcp: nil server for tool %q", name)
	}
	// The SDK's generic AddTool requires InputSchema to be a JSON object that
	// can be merged into a map. RawMessage marshals inline, so the caller's
	// JSON bytes are preserved as an object rather than base64-encoded (which
	// is what a plain []byte would do).
	tool := &mcp.Tool{
		Name:        name,
		Description: description,
		Title:       title,
		InputSchema: json.RawMessage(schema),
	}
	srv.AddTool(tool, handler)
	return nil
}
