package api

import (
	"go.lumeweb.com/portal-plugin-mcp/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-mcp/internal/config"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
)

var _ core.API = (*API)(nil)

type API struct {
	*core.BaseComponent
}

func (a *API) ID() string            { return a.Name() }
func (a *API) Name() string          { return internal.PluginName }
func (a *API) Subdomain() string     { return internal.PluginName }
func (a *API) AuthTokenName() string { return internal.PluginName }

func (a *API) OpenAPIInfo() router.APIInfoDefinition {
	return router.APIInfo().
		Title("MCP API").
		Description("Model Context Protocol endpoints exposed from the portal.")
}

func (a *API) GetConfig() config.APIConfig {
	return &pluginConfig.APIConfig{}
}

func NewAPI() (core.API, []core.ContextBuilderOption, error) {
	return &API{}, core.ContextOptions(), nil
}

func (a *API) Configure(gRouter router.Router, accessSvc core.AccessService) error {
	return nil
}
