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
		Depends: []string{"dashboard"},
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return api.NewAPI()
		},
		APIExtensions: func(ctx core.Context) ([]core.APIExtensionFactory, error) {
			return []core.APIExtensionFactory{
				api.NewOAuthExtension(),
			}, nil
		},
	}
}

func init() {
	core.RegisterPlugin(GetPluginInfo())
}
