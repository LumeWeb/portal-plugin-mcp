package config

import (
	z "github.com/Oudwins/zog"

	"go.lumeweb.com/portal/config"
)

var _ config.APIConfig = (*APIConfig)(nil)

// APIConfig holds MCP API configuration.
type APIConfig struct {
	// ResourcePath is the path on the MCP subdomain where the streamable HTTP
	// MCP endpoint is served. Defaults to "/mcp".
	ResourcePath string `config:"resource_path"`
	// Scopes are the scope values the MCP server advertises as supported
	// (RFC 9728 scopes_supported).
	Scopes []string `config:"scopes"`
	// DevTools, when set, registers the read-only dev_* introspection tools
	// (dev_host_env, dev_profile, dev_request) on the hosted MCP surface for
	// debugging the server and the connected host. The production surface
	// must not carry them; leave this disabled outside diagnostic deployments.
	DevTools bool `config:"dev_tools"`
}

func (a APIConfig) Schema() z.ZogSchema {
	return z.Struct(z.Shape{
		"ResourcePath": z.String().Default("/mcp").Optional(),
		"Scopes":       z.Slice(z.String()).Default([]string{"offline_access"}).Optional(),
		"DevTools":     z.Bool().Default(false).Optional(),
	})
}

func (a APIConfig) Defaults() map[string]any {
	return map[string]any{
		"ResourcePath": "/mcp",
		"Scopes":       []string{"offline_access"},
		"DevTools":     false,
	}
}
