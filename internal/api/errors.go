package api

import "go.lumeweb.com/portal/core"

const (
	// Namespace is the error namespace for the MCP plugin.
	Namespace = "mcp"
)

// The MCP plugin's endpoints are OAuth 2.1 / MCP protocol endpoints consumed
// by automated MCP clients, not the portal UI. They MUST emit OAuth-spec error
// codes (RFC 6749 §5.2, RFC 7591, RFC 6750) that clients parse, so they do not
// register portal-style error envelopes here. The namespace is registered as an
// anchor for any future portal-UI-facing endpoints that need friendly,
// human-readable error messages.
func init() {
	core.MustRegisterNamespace(Namespace)
	core.MustRegisterDefaultErrorMessages(Namespace, map[core.ErrorType]core.ErrorDefinition{})
}
