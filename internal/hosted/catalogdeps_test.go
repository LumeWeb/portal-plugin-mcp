package hosted

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/pinner/core/config"
	pinnermcp "go.lumeweb.com/pinner/mcp"
)

// TestBuildCatalogDepsWiresRealDomainFactories locks BuildCatalogDeps wiring:
// it must assemble the real per-domain service factories (auth, account,
// api-keys, websites, dns, ipns, ens, pins, operations) over the public pinner
// SDK constructors and the plugin-owned concrete services. The
// upload/download byte-route transfer domain stays unwired and degrades closed
// by design.
func TestBuildCatalogDepsWiresRealDomainFactories(t *testing.T) {
	cfgMgr, err := newTestConfigManager()
	require.NoError(t, err, "must build a live config manager fixture")

	bundle := BuildCatalogDeps(cfgMgr)
	require.NotNil(t, bundle)
	require.NotNil(t, bundle.CfgMgr, "bundle must thread the live config manager")
	assert.Equal(t, cfgMgr, bundle.CfgMgr(), "CfgMgr must resolve to the hosted manager")

	t.Run("auth", func(t *testing.T) {
		require.NotNil(t, bundle.Auth.AuthService, "AuthDeps.AuthService must be wired")
		require.NotNil(t, bundle.Auth.ResolveAuthToken, "AuthDeps.ResolveAuthToken must be wired")
		assert.NotNil(t, bundle.Auth.AuthService(cfgMgr, ""), "config-token auth service must construct")
		assert.NotNil(t, bundle.Auth.AuthService(cfgMgr, "override-token"), "override auth service must construct")
		assert.Equal(t, cfgMgr.Config().AuthToken, bundle.Auth.ResolveAuthToken(cfgMgr))
	})

	t.Run("account", func(t *testing.T) {
		require.NotNil(t, bundle.Account.AuthService, "AccountDeps.AuthService must be wired")
		require.NotNil(t, bundle.Account.PortalURL, "AccountDeps.PortalURL must be wired")
		url := bundle.Account.PortalURL(cfgMgr)
		assert.True(t, strings.HasSuffix(url, "/account/subscription"), "portal URL must deep-link subscriptions, got %q", url)
	})

	t.Run("api_keys", func(t *testing.T) {
		require.NotNil(t, bundle.APIKeys.Service, "APIKeysDeps.Service must be wired")
		assert.NotNil(t, bundle.APIKeys.Service(nil), "api-key service must construct even without an override")
	})

	t.Run("websites", func(t *testing.T) {
		require.NotNil(t, bundle.Websites.ServiceFactory, "WebsitesDeps.ServiceFactory must be wired to the SDK default")
		require.NotNil(t, bundle.Websites.NewAuthenticated, "WebsitesDeps.NewAuthenticated must be wired")
		require.NotNil(t, bundle.Websites.GetAuthToken, "WebsitesDeps.GetAuthToken must be wired")
	})

	t.Run("dns", func(t *testing.T) {
		require.NotNil(t, bundle.DNS.ServiceFactory, "DNSDeps.ServiceFactory must be wired")
		require.NotNil(t, bundle.DNS.NewAuthenticated, "DNSDeps.NewAuthenticated must be wired")
		require.NotNil(t, bundle.DNS.GetAuthToken, "DNSDeps.GetAuthToken must be wired")
	})

	t.Run("ipns", func(t *testing.T) {
		require.NotNil(t, bundle.IPNS.ServiceFactory, "IPNSDeps.ServiceFactory must be wired")
		require.NotNil(t, bundle.IPNS.NewAuthenticated, "IPNSDeps.NewAuthenticated must be wired")
		require.NotNil(t, bundle.IPNS.GetAuthToken, "IPNSDeps.GetAuthToken must be wired")
	})

	t.Run("ens", func(t *testing.T) {
		require.NotNil(t, bundle.ENS.IPNS.ServiceFactory, "ENSDeps reuses the IPNS deps which must be wired")
	})

	t.Run("pins", func(t *testing.T) {
		require.NotNil(t, bundle.Pins.ServiceFactory, "PinsDeps.ServiceFactory must be wired to the plugin-owned concrete")
		require.NotNil(t, bundle.Pins.NewAuthenticated, "PinsDeps.NewAuthenticated must be wired")
		require.NotNil(t, bundle.Pins.GetAuthToken, "PinsDeps.GetAuthToken must be wired")
		svc := bundle.Pins.ServiceFactory(cfgMgr, true)
		require.NotNil(t, svc, "pins service factory must construct a service (unauthenticated token => RequireAuthenticated fails closed)")
		require.Error(t, svc.RequireAuthenticated(), "an empty config token must yield an unauthenticated service that fails closed")
	})

	t.Run("operations", func(t *testing.T) {
		require.NotNil(t, bundle.Operations.Service, "OperationsDeps.Service must be wired")
		svc := bundle.Operations.Service(nil)
		require.NotNil(t, svc, "operations service must construct even without a per-request override")
		require.Error(t, svc.RequireAuthenticated(), "without a credential the operations service must fail closed")
	})
}

// TestBuildCatalogDepsHostedAssemblySucceeds documents that the hosted catalog
// assembles cleanly with the full wired deps (pins and operations use the
// plugin-owned concrete services). The upload/download byte-route transfer
// domain remains unwired, so assembly must NOT reject that — the transfer
// surface is simply absent (no /upload or /download route) while every wired
// domain is live.
func TestBuildCatalogDepsHostedAssemblySucceeds(t *testing.T) {
	cfgMgr, err := newTestConfigManager()
	require.NoError(t, err)

	bundle := BuildCatalogDeps(cfgMgr)
	require.NotNil(t, bundle)

	// The pins/operations domains must be live…
	assert.NotNil(t, bundle.Pins.ServiceFactory, "pins factory must be wired")
	assert.NotNil(t, bundle.Operations.Service, "operations factory must be wired")

	// …and the hosted surface assembles with them, producing a real catalog.
	presentation, err := pinnermcp.Assemble(pinnermcp.Config{
		DomainScope: toAssemblyScope(DomainScopeHosted),
		Hosted:      true,
		Deps:        bundle,
	})
	require.NoError(t, err, "hosted assembly with the wired deps must succeed")
	require.NotNil(t, presentation)
	require.NotNil(t, presentation.Catalog(), "hosted assembly must produce an operation catalog")
}

// newTestConfigManager builds a throwaway config.Manager wired to a base
// endpoint + secure, mirroring NewCatalogDeps' construction. It returns a
// config.Manager (interface) so the fixture reads like a real hosted manager.
func newTestConfigManager() (config.Manager, error) {
	dir, err := os.MkdirTemp("", "hosted-catalogdeps-test-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		return nil, err
	}
	if err := mgr.SetBaseEndpoint("https://pinner.xyz"); err != nil {
		return nil, err
	}
	if err := mgr.SetSecure(true); err != nil {
		return nil, err
	}
	return mgr, nil
}
