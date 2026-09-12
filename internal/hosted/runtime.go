package hosted

// This file implements the BuildServer seam the construction boundary
// (server.go) consumes: the hosted presentation is assembled from the public
// go.lumeweb.com/pinner/mcp contract and projected onto a real mcpplane SDK
// server (sdk.NewServer / sdk.RegisterTool) with the dispatch bridge in
// runtime_dispatch.go.

import (
	"errors"
	"fmt"

	"go.lumeweb.com/canimcp"
	"go.lumeweb.com/mcpplane/model"
	"go.lumeweb.com/mcpplane/sdk"
	"go.lumeweb.com/mcpplane/transfer"
	"go.lumeweb.com/pinner/assembly"
	"go.lumeweb.com/pinner/core/auth"
	"go.lumeweb.com/pinner/mcp"
	pinnertransfer "go.lumeweb.com/pinner/transfer"
)

// BuildHostedServer assembles the hosted Pinner MCP server from a construction
// config. It satisfies the hosted.BuildServer seam: it builds the hosted
// operation surface AND the IPFS transfer byte route via the public pinner
// mcp.Assemble contract, then registers every compiled catalog operation and
// every direct tool (agent guide, capabilities, and the wired upload_file /
// upload_data / download_file transfer tools) as a real SDK tool. The IPFS
// byte-route coordinators (presigned upload PUT, filedrop GET) are built from
// the plugin-owned concrete uploads/download services and returned so
// hosted.New can mount them at /upload and /download.
func BuildHostedServer(cfg ServerConfig) (ServerBuildResult, error) {
	bundle := bundleFrom(cfg.CatalogDeps)
	if bundle == nil {
		return ServerBuildResult{}, errors.New("hosted MCP server: BuildHostedServer requires a catalog deps bundle")
	}

	// Build the IPFS byte-route transfer wiring: plugin-owned concrete
	// uploads/download services over public APIs (auth + ipfs-sdk + portal-sdk),
	// shared executors (pinner/transfer.StreamUpload / StreamDownload), and the
	// mcpplane HTTP coordinators. Hosted mode never wires the Sia vault and
	// never exposes a local filesystem path source (PathUpload stays nil).
	transferDeps, coordinators, err := buildHostedTransfer(cfg, bundle)
	if err != nil {
		return ServerBuildResult{}, err
	}

	// Resolve the SHARED tool-listing policy for this assembly: an explicit
	// override when the embedding host declared one, else the shared flat web
	// policy for the hosted audience (see hostedWebListingPolicy). It is
	// threaded into the assembly so the hosted tools/list materialization
	// (direct vs progressive, meta-on-flat) resolves through the one shared
	// policy/selector seam — the same seam the self-hosted CLI assembly uses.
	listing := hostedWebListingPolicy()
	if cfg.Listing != nil {
		listing = *cfg.Listing
	}

	// The hosted MCP Apps inventory: the shared table's CapHosted rows whose
	// dependencies this deployment wires. Computed before assembly so the
	// advertised capability (hostedProfile's FeatMCPApps) and the agent guide's
	// open_app prose (Config.InstalledApps) reflect exactly the views that are
	// about to register.
	appRows := hostedAppRows()
	appLaunchers := hostedLauncherNames(appRows)
	// Assembly validates the vocabulary/duplicates; this closes the remaining
	// registered-vs-listed half by construction, since the configured inventory
	// is exactly the rows this deployment wired. Order-insensitive: the
	// assembly may report launchers in a different order than the table
	// load-order.
	verifyApps := func(installed []string) error {
		if err := hostedVerifyInstalled(installed, appRows); err != nil {
			return fmt.Errorf("hosted MCP server: assembled app inventory %v does not match wired %v", installed, appLaunchers)
		}
		return nil
	}

	// Assemble the hosted presentation (compiled catalog surface + direct set)
	// from the public pinner contract. Hosted mode excludes the Sia vault and
	// portal admin from the surface by construction.
	presentation, err := mcp.Assemble(mcp.Config{
		DomainScope:         toAssemblyScope(cfg.DomainScope),
		Hosted:              true,
		Deps:                bundle,
		Transfer:            transferDeps,
		Listing:             &listing,
		DevTools:            cfg.DevTools,
		Profile:             hostedProfile(appRows),
		InstalledApps:       appLaunchers,
		VerifyInstalledApps: verifyApps,
	})
	if err != nil {
		return ServerBuildResult{}, fmt.Errorf("hosted MCP server: assemble presentation: %w", err)
	}
	cat := presentation.Catalog()
	if cat == nil {
		return ServerBuildResult{}, errors.New("hosted MCP server: assembly produced no operation catalog")
	}

	srv := sdk.NewServer(&sdk.ServerOptions{})
	// Per-request capabilities resolve through the shared mcpplane sdk caps
	// builder: hosted profile detection over wire signals, plus the dev wire
	// snapshot only when dev tools are on.
	deps := sdk.HandlerDeps{
		RequestCaps: sdk.NewRequestCapsBuilder(sdk.RequestCapsOptions{
			Hosted:      true,
			DevSnapshot: cfg.DevTools,
		}),
	}
	// Only the DIRECT surface materializes on tools/list: the compiled
	// descriptors carry DirectVisible exactly where the resolved listing policy
	// materializes them (flat stamps every agent-safe op, progressive leaves
	// the non-direct ops reachable only through the meta-tools below). Full
	// dispatch still goes through the owning catalog gate via catalogToolHandler.
	for _, t := range presentation.Tools {
		if !t.DirectVisible {
			continue
		}
		desc := t
		desc.Handler = catalogToolHandler(cat, desc.Name, cfg.CredentialResolver)
		if err := sdk.RegisterTool(srv, deps, desc); err != nil {
			return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register tool %q: %w", desc.Name, err)
		}
	}
	// Register the direct-only tools (agent_guide, capabilities, and the wired
	// transfer tools). These descriptors carry their own baked-in handlers that
	// dispatch through the injected executors/coordinators, so they are
	// registered as-is.
	for _, d := range presentation.Direct {
		if err := sdk.RegisterTool(srv, deps, d); err != nil {
			return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register direct tool %q: %w", d.Name, err)
		}
	}

	// Wire the hosted MCP Apps: install the selected views (each registers a
	// ui:// resource + tool→view association through the shared appswire
	// seam), assert the installed set matches the wired inventory, then
	// register the consolidated open_app launcher, the single directly-listed
	// app tool on the hosted surface.
	//
	// The pin creator's poll provider authenticates each request as the calling
	// user via the hosted credential on the request context. Resolve it before
	// the scoped app-install so the serialized install has a stable provider.
	// (installHostedAppsSerialized also scopes the SDK tool-registrar seam,
	// which sdk.RegisterAppTool uses for the app-only helpers, to this build.)
	cfgMgr := bundle.CfgMgr()
	var pins pinStatusProvider
	if cfgMgr != nil {
		pins = newHostedPinProvider(bundle.Pins, cfgMgr, cfgMgr.Config().Secure)
	}

	installedApps, err := installHostedAppsSerialized(srv, deps, appRows, cfg.BaseURL, pins, transferDeps.PresignedUpload, transferDeps.FileDrop)
	if err != nil {
		return ServerBuildResult{}, err
	}
	if err := hostedVerifyInstalled(installedApps, appRows); err != nil {
		return ServerBuildResult{}, err
	}
	// Register the single directly-listed app launcher only when views exist,
	// mirroring the FeatMCPApps gate so an apps-less hosted assembly exposes no
	// open_app tool with an always-empty inventory.
	if len(appRows) > 0 {
		if err := sdk.RegisterTool(srv, deps, openAppDescriptor(appRows)); err != nil {
			return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register open_app: %w", err)
		}
	}

	// Register the surface-gated prompt and pinner:// resource sets for parity
	// with the local stdio composition: the assembly projects them onto
	// SDK-neutral descriptors whose handlers are already baked in, so they can
	// be registered as-is on the live server.
	if err := sdk.RegisterPrompts(srv, presentation.Prompts); err != nil {
		return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register prompts: %w", err)
	}
	if err := sdk.RegisterResources(srv, presentation.Resources, presentation.ResourceTemplates); err != nil {
		return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register resources: %w", err)
	}

	// Register the progressive-disclosure meta-tools (search_tools,
	// describe_tool, and the typed invoke_*_tool dispatchers) from the shared
	// pinner/mcp presentation layer, gated on the RESOLVED listing policy this
	// same assembly materializes: progressive always; flat unless the policy
	// explicitly opts out with IncludeMetaOnFlat=false — never the hosted
	// deployment mode. Catalog ops dispatch through the existing catalog gate
	// (the same seam every direct catalog tool uses) and the shared
	// HandlerDeps thread the per-request caps builder into the meta handlers.
	if presentation.ServesMetaTools() {
		metaDescs, err := presentation.MetaToolDescriptors(func(name string) model.ToolHandler {
			return catalogToolHandler(cat, name, cfg.CredentialResolver)
		})
		if err != nil {
			return ServerBuildResult{}, fmt.Errorf("hosted MCP server: build meta tools: %w", err)
		}
		for _, d := range metaDescs {
			if err := sdk.RegisterTool(srv, deps, d); err != nil {
				return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register meta tool %q: %w", d.Name, err)
			}
		}
	}

	return ServerBuildResult{
		Server:   srv,
		Transfer: coordinators,
		// The RESOLVED policy the assembly actually materializes (the shared
		// flat default unless an override was supplied), exposed so an
		// embedding host never has to re-derive it.
		Listing: presentation.ListingPolicy(),
	}, nil
}

// hostedWebListingPolicy resolves the SHARED tools/list policy for the
// hosted (Portal-embedded) web audience. A hosted server is served over HTTP
// to web MCP hosts — Claude Web, Grok Web, and ChatGPT/OpenAI Web — which the
// shared Pinner host selector (pinner/mcp.PolicyForHost) maps to flat
// tools/list because progressive discovery is unreliable on cloud-hosted
// clients. All of those hosts resolve the same flat strategy, so the hosted
// construction root resolves the shared flat policy for its web-HTTP audience
// once, at assembly time; an embedding host that targets a specific host
// (or its own progressive surface) passes that policy via cfg.Listing instead.
func hostedWebListingPolicy() mcp.ListingPolicy {
	return mcp.PolicyForHost(canimcp.HostClaude, canimcp.TransportHTTP)
}

// buildHostedTransfer assembles the mcp.TransferDeps (the executor/coordinator
// wiring mcp.Assemble projects onto the upload_file / download_file tools) and
// the coordinators hosted.New mounts at /upload and /download. It builds the
// plugin-owned concrete uploads/download services from the live config manager
// and threads the per-request credential via mcpplane/credctx (the executors
// receive a request context carrying the credential stamped by the HTTP
// middleware). The relay/upload executor is stream-only: hosted mode exposes no
// local filesystem path source.
func buildHostedTransfer(cfg ServerConfig, bundle *assembly.CatalogDepsBundle) (mcp.TransferDeps, HostedTransfer, error) {
	cfgMgr := bundle.CfgMgr()
	if cfgMgr == nil {
		return mcp.TransferDeps{}, HostedTransfer{}, errors.New("hosted MCP server: catalog deps bundle has no config manager")
	}
	conf := cfgMgr.Config()
	secure := conf.Secure
	ipfsEndpoint := conf.GetIPFSEndpointWithSecure(secure)
	authSvc := auth.NewAuthService(cfgMgr, conf.GetAccountEndpointSecure(), nil)

	uploadSvc := newHostedUploadService(cfgMgr, ipfsEndpoint, authSvc)
	downloadSvc := newHostedDownloadService(cfgMgr, ipfsEndpoint, authSvc)

	maxBytes := int64(conf.GetMaxMCPUploadSize())
	relay := pinnertransfer.StreamUpload(uploadSvc, maxBytes)
	ipfsDownload := pinnertransfer.StreamDownload(downloadSvc)

	uploadTasks := transfer.NewUploadTaskManager(relay, 0)
	curlUpload := transfer.NewHTTPUpload(uploadTasks, maxBytes)
	dl := transfer.NewHTTPDownload()
	// Point the coordinators at the externally reachable origin (BaseURL) when
	// configured, so minted presigned PUT / filedrop GET URLs resolve against
	// the real deployment origin rather than a loopback temp port.
	if cfg.BaseURL != "" {
		curlUpload.SetBaseURL(cfg.BaseURL)
		dl.SetBaseURL(cfg.BaseURL)
	}

	deps := mcp.TransferDeps{
		CoLocated:        false, // hosted transport is HTTP, not stdio
		TunnelOpenAI:     false, // hosted transport is not the OpenAI tunnel
		Relay:            relay,
		IPFSDownload:     ipfsDownload,
		PresignedUpload:  curlUpload,
		FileDrop:         dl,
		DownloadRoot:     conf.GetDownloadRoot(),
		MaxDownloadBytes: maxBytes,
		MaxRelayBytes:    maxBytes,
		UploadFile:       true,
		DownloadFile:     true,
		DropWired:        true,
	}
	return deps, HostedTransfer{Upload: curlUpload, Download: dl}, nil
}

// toAssemblyScope converts the plugin-owned hosted DomainScope onto the pinner
// assembly.DomainScope the catalog compiler consumes. The hosted surface never
// enables the Sia vault or portal admin, so those axes are pinned false.
func toAssemblyScope(s DomainScope) assembly.DomainScope {
	return assembly.DomainScope{
		Account:    s.Account,
		Pins:       s.Pins,
		Websites:   s.Websites,
		DNS:        s.DNS,
		IPNS:       s.IPNS,
		ENS:        s.ENS,
		Operations: s.Operations,
		Upload:     s.Upload,
		Vault:      false,
		Admin:      false,
	}
}
