package config

import (
	z "github.com/Oudwins/zog"

	"go.lumeweb.com/portal/config"
)

var _ config.APIConfig = (*APIConfig)(nil)

// APIConfig holds MCP API configuration. No subdomain routing is configured yet.
type APIConfig struct{}

func (APIConfig) Schema() z.ZogSchema {
	return z.Struct(z.Shape{})
}

func (APIConfig) Defaults() map[string]any {
	return map[string]any{}
}
