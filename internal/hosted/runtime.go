package hosted

// This file implements the BuildServer seam the construction boundary
// (server.go) consumes: the hosted presentation is assembled from the public
// go.lumeweb.com/pinner/mcp contract and projected onto a real mcpplane SDK
// server (sdk.NewServer / sdk.RegisterTool) with the dispatch bridge in
// runtime_dispatch.go.

import (
	"errors"
	"fmt"

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

	// Assemble the hosted presentation (compiled catalog surface + direct set)
	// from the public pinner contract. Hosted mode excludes the Sia vault and
	// portal admin from the surface by construction.
	presentation, err := mcp.Assemble(mcp.Config{
		DomainScope: toAssemblyScope(cfg.DomainScope),
		Hosted:      true,
		Deps:        bundle,
		Transfer:    transferDeps,
	})
	if err != nil {
		return ServerBuildResult{}, fmt.Errorf("hosted MCP server: assemble presentation: %w", err)
	}
	cat := presentation.Catalog()
	if cat == nil {
		return ServerBuildResult{}, errors.New("hosted MCP server: assembly produced no operation catalog")
	}

	srv := sdk.NewServer(&sdk.ServerOptions{})
	for _, t := range presentation.Tools {
		desc := t
		desc.Handler = catalogToolHandler(cat, desc.Name, cfg.CredentialResolver)
		if err := sdk.RegisterTool(srv, sdk.HandlerDeps{}, desc); err != nil {
			return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register tool %q: %w", desc.Name, err)
		}
	}
	// Register the direct-only tools (agent_guide, capabilities, and the wired
	// transfer tools). These descriptors carry their own baked-in handlers that
	// dispatch through the injected executors/coordinators, so they are
	// registered as-is.
	for _, d := range presentation.Direct {
		if err := sdk.RegisterTool(srv, sdk.HandlerDeps{}, d); err != nil {
			return ServerBuildResult{}, fmt.Errorf("hosted MCP server: register direct tool %q: %w", d.Name, err)
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

	return ServerBuildResult{Server: srv, Transfer: coordinators}, nil
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
