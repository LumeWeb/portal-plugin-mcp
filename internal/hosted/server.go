package hosted

import (
	"errors"
	"net/http"

	"go.lumeweb.com/mcpplane/sdk"
	"go.lumeweb.com/mcpplane/transfer"
	"go.lumeweb.com/pinner/assembly"
	"go.lumeweb.com/pinner/mcp/hosted"
)

// Options configures an embedded hosted Pinner MCP server.
type Options struct {
	// DomainScope declares which domains/tool families are exposed. A zero
	// DomainScope defaults to DomainScopeHosted (the standard hosted set); use
	// a partial DomainScope to enable only specific families.
	DomainScope DomainScope

	// CatalogDeps supplies the operation-catalog dependency bundle for this
	// server: the Portal API endpoint and per-request credential resolution.
	// It is optional at this boundary — the BuildServer seam consumes it — but
	// the compiled catalog is the source of the tool surface, so it is
	// effectively required for a real server.
	CatalogDeps func() *assembly.CatalogDepsBundle

	// BuildServer assembles the SDK server and any IPFS byte-route coordinators
	// for this embed from the construction config. It is the catalog/runtime
	// seam this package owns and implements here (BuildHostedServer). It is
	// required — New fails fast without it rather than returning a hollow
	// handler.
	BuildServer BuildServer

	// CredentialResolver maps the OAuth-authenticated caller of a request onto
	// the Portal API token used to serve that request. It is threaded through
	// the operation dispatch so every hosted operation authenticates as the
	// calling user instead of a shared config token. When nil, ops fall back to
	// their config-token source.
	CredentialResolver CredentialResolver

	// OAuthHandler protects the /mcp endpoint with OAuth. When nil, the
	// handler is served unauthenticated (the caller is responsible for any
	// upstream auth, e.g. Portal middleware).
	OAuthHandler OAuthHandler

	// DisableLocalhostProtection disables the Streamable-HTTP localhost
	// (DNS-rebinding) protection. Required when the handler is served behind a
	// proxy/tunnel that presents a non-loopback Origin.
	DisableLocalhostProtection bool

	// BaseURL is the externally reachable origin of this hosted server (e.g.
	// https://pinner.xyz). It is applied to the IPFS byte-route coordinators by
	// BuildServer so their presigned upload PUT / filedrop GET URLs mint
	// against the real origin rather than a loopback temp port.
	BaseURL string
}

// ServerConfig carries the construction values a BuildServer implementation
// needs to assemble the SDK server for this embed.
type ServerConfig struct {
	// DomainScope declares which domains/tool families the server exposes.
	DomainScope DomainScope

	// CatalogDeps supplies the operation-catalog dependency bundle. The
	// BuildServer seeds the one effective CredentialResolver onto each bundle
	// before assembly so dispatch authenticates as the resolved caller.
	CatalogDeps func() *assembly.CatalogDepsBundle

	// CredentialResolver is the ONE effective per-request credential for this
	// embed (already reconciled by New via hosted.NormalizeCredentialResolvers).
	CredentialResolver CredentialResolver

	// BaseURL is the externally reachable origin of this hosted server.
	BaseURL string
}

// ServerBuildResult carries what New needs to mount a hosted server: the SDK
// server whose /mcp streamable handler is OAuth-wrapped, and any IPFS
// byte-route coordinators to mount at /upload and /download. A nil Transfer
// field means the corresponding executor was not wired, so no route exists.
type ServerBuildResult struct {
	// Server is the assembled MCP server.
	Server *sdk.Server
	// Transfer carries the IPFS byte-route coordinators (never vault).
	Transfer HostedTransfer
}

// HostedTransfer carries the IPFS byte-route coordinators a hosted server
// built from its wired IPFS transfer executors. It lets the embedding host
// mount the presigned PUT/GET routes on its own transport mux, so a minted
// upload PUT or filedrop GET URL is reachable out of band of the MCP channel.
type HostedTransfer struct {
	// Upload is the presigned HTTP PUT upload coordinator, when an IPFS upload
	// task manager was wired. Never vault.
	Upload *transfer.Upload
	// Download is the one-time filedrop GET coordinator, when an IPFS download
	// executor was wired. Never vault.
	Download *transfer.Download
}

// BuildServer assembles the SDK server and IPFS byte-route coordinators for a
// hosted embed. It is the seam this package's New consumes; the concrete
// implementation (BuildHostedServer) lives in runtime.go.
type BuildServer func(cfg ServerConfig) (ServerBuildResult, error)

// bundleFrom invokes the CatalogDeps factory once, tolerating a nil factory.
func bundleFrom(factory func() *assembly.CatalogDepsBundle) *assembly.CatalogDepsBundle {
	if factory == nil {
		return nil
	}
	return factory()
}

// New assembles a hosted Pinner MCP server and returns its /mcp
// streamable-HTTP handler. It is the construction boundary: resolver
// normalization (via pinner/mcp/hosted), OAuth wrapping, localhost protection,
// and byte-route mux mounting.
//
// The BuildServer seam supplies the SDK server + IPFS coordinators; New wraps
// it with the credential middleware, applies the OAuthHandler (when provided),
// and — when IPFS byte routes exist — mounts them on a mux at /upload and
// /download alongside the /mcp streamable endpoint, so an embedding host that
// routes those paths gets the full transfer surface.
func New(opts Options) (http.Handler, error) {
	surface := opts.DomainScope
	if surface.IsZero() {
		surface = DomainScopeHosted
	}
	// Resolve the ONE effective credential resolver at construction time —
	// never separately per path — so the compiled catalog and every
	// HTTP/transfer path authenticate under the same resolver. Every
	// construction-time bundle-factory invocation is sampled into the
	// normalization: a non-uniform factory normalizes to the non-nil resolver
	// for every boundary, and two observed-but-disagreeing resolvers fail
	// construction closed.
	resolverBundle := bundleFrom(opts.CatalogDeps)
	wireBundle := bundleFrom(opts.CatalogDeps)
	resolverSamples := make([]CredentialResolver, 0, 2)
	for _, bundle := range []*assembly.CatalogDepsBundle{resolverBundle, wireBundle} {
		if bundle != nil {
			resolverSamples = append(resolverSamples, bundle.CredentialResolver)
		}
	}
	effectiveResolver, err := hosted.NormalizeCredentialResolvers(opts.CredentialResolver, resolverSamples)
	if err != nil {
		return nil, err
	}

	if opts.BuildServer == nil {
		return nil, errors.New("hosted MCP server: BuildServer is required to assemble the server")
	}

	res, err := opts.BuildServer(ServerConfig{
		DomainScope:        surface,
		CatalogDeps:        opts.CatalogDeps,
		CredentialResolver: effectiveResolver,
		BaseURL:            opts.BaseURL,
	})
	if err != nil {
		return nil, err
	}

	// Install the credential middleware so the per-request Portal API JWT is
	// resolved once at the HTTP boundary and carried on the context to every
	// handler.
	streamable := HTTPHandler(res.Server, effectiveResolver, opts.DisableLocalhostProtection)
	if opts.OAuthHandler != nil {
		streamable = opts.OAuthHandler.WrapHTTP(streamable)
	}

	// Mount the streamable MCP endpoint plus the IPFS byte routes on a mux, so
	// an embedding host that routes /upload and /download reaches the
	// coordinators out of band.
	if res.Transfer.Upload == nil && res.Transfer.Download == nil {
		return streamable, nil
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", streamable)
	if res.Transfer.Upload != nil {
		res.Transfer.Upload.RegisterHandlers(mux)
	}
	if res.Transfer.Download != nil {
		res.Transfer.Download.RegisterHandlers(mux)
	}
	return mux, nil
}
