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
}

func (a APIConfig) Schema() z.ZogSchema {
	return z.Struct(z.Shape{
		"ResourcePath": z.String().Default("/mcp").Optional(),
		"Scopes":       z.Slice(z.String()).Default([]string{"offline_access"}).Optional(),
	})
}

func (a APIConfig) Defaults() map[string]any {
	return map[string]any{
		"ResourcePath": "/mcp",
		"Scopes":       []string{"offline_access"},
	}
}
