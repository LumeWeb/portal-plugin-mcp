package mcp

import (
	"go.lumeweb.com/portal-plugin-mcp/build"
	"go.lumeweb.com/portal-plugin-mcp/internal"
	"go.lumeweb.com/portal-plugin-mcp/internal/api"
	"go.lumeweb.com/portal/core"
)

func GetPluginInfo() core.PluginInfo {
	return core.PluginInfo{
		ID:      internal.PluginName,
		Version: build.GetInfo(),
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return api.NewAPI()
		},
	}
}

func init() {
	core.RegisterPlugin(GetPluginInfo())
}
