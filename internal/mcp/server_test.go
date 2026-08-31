package mcp

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	srv := NewServer(nil)
	require.NotNil(t, srv)

	srvWithOpts := NewServer(&ServerOptions{Instructions: "hi"})
	require.NotNil(t, srvWithOpts)
}

func TestAddTool_NilServerReturnsError(t *testing.T) {
	err := AddTool(nil, "tool", "desc", "Tool", []byte(`{}`), handlerOK)
	require.Error(t, err)
}

func TestAddTool_RegistersTool(t *testing.T) {
	srv := NewServer(nil)
	err := AddTool(srv, "echo", "Echo input", "Echo", []byte(`{"type":"object"}`), handlerOK)
	require.NoError(t, err)
}

func TestNewStreamableHandler(t *testing.T) {
	srv := NewServer(nil)
	h := NewStreamableHandler(srv)
	require.NotNil(t, h)

	// A health-like ping through the streamable handler must not panic.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Accept", "application/json, text/event-stream")
	h.ServeHTTP(rec, req)
}

func handlerOK(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{}, nil
}

// Ensure the local AddTool signature matches the SDK's expected handler type so
// tool registration stays SDK-shaped.
func TestAddToolCanonicalTypes(t *testing.T) {
	var _ mcp.ToolHandler = handlerOK
}
