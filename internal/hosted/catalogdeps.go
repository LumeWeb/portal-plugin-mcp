package hosted

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.lumeweb.com/pinner/assembly"
	"go.lumeweb.com/pinner/catalogops"
	"go.lumeweb.com/pinner/core/apikeys"
	"go.lumeweb.com/pinner/core/auth"
	"go.lumeweb.com/pinner/core/config"
	"go.lumeweb.com/pinner/core/dns"
	"go.lumeweb.com/pinner/core/ipns"
	"go.lumeweb.com/pinner/core/operations"
	"go.lumeweb.com/pinner/core/pinning"
	"go.lumeweb.com/pinner/core/websites"
)

// CatalogDepsBuilder assembles the full operation-catalog dependency bundle
// (auth, account, pins, websites, DNS, IPNS, ENS, API keys, operations) for a
// hosted server against a live pinner config.Manager. It returns nil when the
// caller cannot build a bundle (the seam degrades closed rather than surfacing
// a hollow catalog).
type CatalogDepsBuilder func(cfg config.Manager) *assembly.CatalogDepsBundle

// NewCatalogDeps builds the production catalog-deps factory for a hosted
// (Portal-embedded) MCP server, pointed at the given Portal API endpoint.
//
// It creates a pinner core/config.Manager configured with BaseEndpoint and
// Secure, then delegates to the CatalogDepsBuilder seam to assemble the
// operation-catalog dependency graph against the hosted config manager. The
// per-request auth token is NOT stored in the config; it is threaded through
// the CredentialResolver seam (set on the bundle by New).
//
// The returned closure is suitable for use as Options.CatalogDeps. It returns
// the same pre-built bundle on each call (the bundle's closures re-read config
// and resolve services lazily per invocation, so live token reload is
// preserved).
func NewCatalogDeps(apiEndpoint string, secure bool, build CatalogDepsBuilder) (func() *assembly.CatalogDepsBundle, error) {
	dir, err := os.MkdirTemp("", "mcpembed-*")
	if err != nil {
		return nil, fmt.Errorf("hosted: create temp config dir: %w", err)
	}
	// The config manager reads its values from in-memory state after Load, so
	// the backing temp dir is only needed during construction; drop it to avoid
	// leaking a directory-plus-file into the process temp dir on every call.
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("hosted: create config manager: %w", err)
	}
	if err := cfgMgr.SetBaseEndpoint(apiEndpoint); err != nil {
		return nil, fmt.Errorf("hosted: set base endpoint: %w", err)
	}
	if err := cfgMgr.SetSecure(secure); err != nil {
		return nil, fmt.Errorf("hosted: set secure: %w", err)
	}

	if build == nil {
		return nil, fmt.Errorf("hosted: no CatalogDepsBuilder configured")
	}
	bundle := build(cfgMgr)
	return func() *assembly.CatalogDepsBundle { return bundle }, nil
}

// BuildCatalogDeps builds the production catalog-deps bundle for a hosted
// (Portal-embedded) MCP server against a live pinner core/config.Manager. It
// satisfies the CatalogDepsBuilder seam.
//
// The bundle threads the live config manager (resolved per invocation so a
// live token/config edit stays honored) and wires each domain's real service
// factories over the public pinner SDK constructors (auth, apikeys, websites,
// dns, ipns, pins, operations). Every factory is a lazy getter resolved per
// invocation, so services always read fresh config, never a frozen token. The
// pins and operations domains use plugin-owned concrete services implemented in
// internal/hosted (pinning_service.go, operations_service.go) over the public
// boxo/ipfs-sdk and portal-sdk clients.
//
// A hosted assembly authenticates each request as the calling user: the
// plugin's runtime dispatch (catalogToolHandler) seeds the one effective
// per-request credential onto the input map under opmesh.ReservedAuthTokenKey
// (catalogops.AuthTokenInputKey), and each NewAuthenticated/Service/AuthService
// closure pins that principal's token — never the shared config default. When
// no per-request credential is present the factories fall back to the
// config-stored token.
//
// The vault/admin factories are omitted because the hosted surface excludes
// them by construction (toAssemblyScope pins Vault/Admin false). The IPFS
// upload/download byte-route is NOT a catalog-deps concern here: the concrete
// uploads.Service / download.Service implementations and the /upload and
// /download coordinators are the plugin-owned hosted transfer services wired in
// runtime.go (buildHostedTransfer) and returned through the BuildServer seam.
func BuildCatalogDeps(cfgMgr config.Manager) *assembly.CatalogDepsBundle {
	// Resolved to the hosted manager on every read so live edits stay honored.
	cfg := func() config.Manager { return cfgMgr }
	secure := func() bool { return cfgMgr.Config().Secure }
	getToken := func() string { return cfgMgr.Config().AuthToken }
	apiEndpoint := func() string { return cfgMgr.Config().GetAPIEndpoint() }

	// authService builds an auth.AuthService honoring the per-invocation
	// credential override ("" to use the config-stored token). It is shared by
	// the auth and account domains.
	authService := func(m config.Manager, token string) auth.AuthService {
		ep := m.Config().GetAccountEndpointSecure()
		if token != "" {
			return auth.NewAuthService(m, ep, nil, auth.WithAuthToken(token))
		}
		return auth.DefaultAuthServiceFactory(m, ep)
	}

	ipnsDeps := catalogops.IPNSDeps{
		CfgMgr:         cfg,
		Secure:         secure,
		ServiceFactory: ipns.ServiceFactory,
		NewAuthenticated: func(m config.Manager, token string, sec bool) (ipns.Service, error) {
			return ipns.NewAuthenticated(m, token, sec)
		},
		GetAuthToken: getToken,
	}

	return &assembly.CatalogDepsBundle{
		CfgMgr: cfg,
		Auth: catalogops.AuthDeps{
			CfgMgr: cfg,
			AuthService: func(m config.Manager, token string) auth.AuthService {
				return authService(m, token)
			},
			ResolveAuthToken: func(m config.Manager) string {
				return m.Config().AuthToken
			},
		},
		Account: catalogops.AccountDeps{
			CfgMgr: cfg,
			AuthService: func(m config.Manager, token string) auth.AuthService {
				return authService(m, token)
			},
			PortalURL: func(m config.Manager) string {
				return strings.TrimSuffix(m.Config().GetAccountEndpointSecure(), "/") + "/account/subscription"
			},
		},
		APIKeys: catalogops.APIKeysDeps{
			Service: func(input map[string]any) apikeys.Service {
				// The per-invocation credential (threaded by the hosted runtime)
				// takes precedence over the config token; pin the auth service to
				// the override so List/Create/Delete authenticate as the caller.
				token := getToken()
				ep := apiEndpoint()
				var as auth.AuthService
				if t, ok := input[catalogops.AuthTokenInputKey].(string); ok && t != "" {
					token = t
					as = auth.NewAuthService(cfgMgr, ep, nil, auth.WithAuthToken(t))
				} else {
					as = auth.DefaultAuthServiceFactory(cfgMgr, ep)
				}
				return apikeys.New(as, token)
			},
		},
		Websites: catalogops.WebsitesDeps{
			CfgMgr:         cfg,
			Secure:         secure,
			ServiceFactory: websites.ServiceFactory,
			NewAuthenticated: func(m config.Manager, sec bool, token string) (websites.Service, error) {
				return websites.NewAuthenticated(m, token, sec)
			},
			GetAuthToken: getToken,
			// DownloadServiceFactory and IPNSResolveFunc are left nil (zero):
			// they back the website index.html structure guardrail; it is
			// skipped, so website create/update proceed without the root check.
		},
		DNS: catalogops.DNSDeps{
			CfgMgr:         cfg,
			Secure:         secure,
			ServiceFactory: dns.ServiceFactory,
			NewAuthenticated: func(m config.Manager, sec bool, token string) dns.Service {
				s, _ := dns.NewAuthenticated(m, token, sec)
				return s
			},
			GetAuthToken: getToken,
		},
		Pins: catalogops.PinsDeps{
			CfgMgr: cfg,
			Secure: secure,
			// ServiceFactory builds a service pinned to the config-stored token
			// (the no-per-request-credential fallback). Each NewAuthenticated
			// closure builds a service pinned to the caller's token instead.
			ServiceFactory: func(m config.Manager, sec bool) pinning.PinningService {
				return newPinnedServiceFor(m, sec, m.Config().AuthToken)
			},
			NewAuthenticated: func(m config.Manager, sec bool, token string) pinning.PinningService {
				return newPinnedServiceFor(m, sec, token)
			},
			GetAuthToken: getToken,
		},
		Operations: catalogops.OperationsDeps{
			// Service builds a plugin-owned operations.Service over the account
			// client resolved from the auth service, honoring the per-request
			// credential override on the input map (else the config token).
			Service: func(input map[string]any) operations.Service {
				ep := apiEndpoint()
				if t, ok := input[catalogops.AuthTokenInputKey].(string); ok && t != "" {
					return newOperationsService(auth.NewAuthService(cfgMgr, ep, nil, auth.WithAuthToken(t)))
				}
				return newOperationsService(auth.DefaultAuthServiceFactory(cfgMgr, ep))
			},
		},
		IPNS: ipnsDeps,
		ENS:  catalogops.ENSDeps{IPNS: ipnsDeps},
	}
}
