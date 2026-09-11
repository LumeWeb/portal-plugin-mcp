package hosted

// This file implements the hosted download.Service over the public ipfs-sdk
// download service. In hosted mode there is no frozen config token: the
// per-request Portal API credential travels on the context (stamped via
// mcpplane/credctx by the HTTP credential middleware), so each call resolves
// the credential from ctx and never from a shared config token. StreamDownload
// (pinner/transfer) consumes Cat to power the filedrop GET byte route.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipfs/boxo/files"
	"github.com/ipfs/go-cid"
	ipfs "go.lumeweb.com/ipfs-sdk"
	"go.lumeweb.com/mcpplane/credctx"
	"go.lumeweb.com/pinner/core/auth"
	"go.lumeweb.com/pinner/core/config"
	"go.lumeweb.com/pinner/core/download"
	portalsdk "go.lumeweb.com/portal-sdk"
)

// hostedDownloadService is the plugin-owned hosted implementation of
// download.Service over the public ipfs-sdk download service. It is reused per
// hosted server; the auth token is resolved lazily per call from the request
// context so it always authenticates as the effective credential — never a
// frozen shared token.
type hostedDownloadService struct {
	configMgr       config.Manager
	authSvc         auth.AuthService
	ipfsEndpoint    string
	accountEndpoint string
}

// newHostedDownloadService builds the plugin-owned download.Service from the
// config manager and auth service. A nil auth service is tolerated: API-key
// JWTs are then passed through un-exchanged (the endpoint either accepts them
// directly or the caller supplied a login token).
func newHostedDownloadService(cfgMgr config.Manager, ipfsEndpoint string, authSvc auth.AuthService) download.Service {
	return &hostedDownloadService{
		configMgr:       cfgMgr,
		authSvc:         authSvc,
		ipfsEndpoint:    ipfsEndpoint,
		accountEndpoint: cfgMgr.Config().GetAPIEndpoint(),
	}
}

// RequireAuthenticated reports whether the service can authenticate a request.
// On the hosted path the gate is enforced per call via the context credential
// (Cat's newSDKDownloadService), so this ctx-less method has no frozen token to
// validate and always reports authenticated; a request without a credential
// fails closed inside Cat instead.
func (s *hostedDownloadService) RequireAuthenticated() error {
	return nil
}

// resolveHostedDownloadToken returns the token for a download, preferring the
// per-request hosted credential (credctx) and exchanging an API-key JWT for a
// login JWT when one is available (the Pinner IPFS gateway rejects API-key
// tokens). A missing credential fails closed.
func (s *hostedDownloadService) resolveHostedDownloadToken(ctx context.Context) (string, error) {
	tok := credctx.From(ctx)
	if tok == "" {
		return "", errHostedNotAuthenticated
	}
	return s.exchangeIfAPIKey(ctx, tok)
}

// exchangeIfAPIKey returns the token to use, exchanging an API-key JWT for a
// login JWT when an authService is available. Decode errors fall back to the
// raw token; non-"api" tokens are returned as-is.
func (s *hostedDownloadService) exchangeIfAPIKey(ctx context.Context, authToken string) (string, error) {
	if s.authSvc == nil {
		return authToken, nil
	}
	purpose, err := auth.GetJWTPurpose(authToken)
	if err != nil {
		return authToken, nil
	}
	if purpose != "api" {
		return authToken, nil
	}
	client := portalsdk.NewClient(portalsdk.WithEndpoint(s.accountEndpoint))
	loginJWT, err := client.LoginWithAPIKey(ctx, authToken)
	if err != nil {
		return "", fmt.Errorf("failed to exchange API key for download: %w", err)
	}
	return loginJWT, nil
}

// newSDKDownload builds an ipfs-sdk download service pinned to the per-request
// credential.
func (s *hostedDownloadService) newSDKDownload(ctx context.Context) (*ipfs.DownloadService, error) {
	authToken, err := s.resolveHostedDownloadToken(ctx)
	if err != nil {
		return nil, err
	}
	dl, err := ipfs.NewDownloadService(s.ipfsEndpoint, authToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create download service: %w", err)
	}
	return dl, nil
}

// hostedIPFSPath is a parsed IPFS node (CID + optional sub-path).
type hostedIPFSPath struct {
	cid  cid.Cid
	path string
}

// parseHostedIPFSPath parses a CID[/path] into its node parts.
func parseHostedIPFSPath(ipfsPathStr string) (hostedIPFSPath, error) {
	parts := strings.SplitN(ipfsPathStr, "/", 2)
	parsedCID, err := cid.Decode(parts[0])
	if err != nil {
		return hostedIPFSPath{}, fmt.Errorf("invalid CID: %w", err)
	}
	p := hostedIPFSPath{cid: parsedCID}
	if len(parts) > 1 {
		p.path = strings.Trim(parts[1], "/")
	}
	return p, nil
}

// Cat streams a single IPFS node (CID or CID/path) to the caller — the engine
// behind StreamDownload and the filedrop GET byte route.
func (s *hostedDownloadService) Cat(ctx context.Context, ipfsPathStr string) (io.ReadCloser, error) {
	p, err := parseHostedIPFSPath(ipfsPathStr)
	if err != nil {
		return nil, err
	}
	dl, err := s.newSDKDownload(ctx)
	if err != nil {
		return nil, err
	}
	if p.path != "" {
		return dl.GetFile(ctx, p.cid, p.path)
	}
	return dl.DownloadFile(ctx, p.cid)
}

// Download writes a single IPFS node to a host-side output path (sink=local).
// It is confined to no root on its own — the catalog/download tool enforcement
// (pinner/transfer.WriteLocalDownload) is what the byte-route uses.
func (s *hostedDownloadService) Download(ctx context.Context, ipfsPathStr string, outputPath string, force bool) (*download.DownloadResult, error) {
	startTime := time.Now()
	p, err := parseHostedIPFSPath(ipfsPathStr)
	if err != nil {
		return nil, err
	}
	dl, err := s.newSDKDownload(ctx)
	if err != nil {
		return nil, err
	}
	if outputPath == "" {
		if p.path != "" {
			outputPath = filepath.Base(p.path)
		} else {
			outputPath = p.cid.String()
		}
	}
	if fi, err := os.Stat(outputPath); err == nil && !force {
		if fi.IsDir() {
			if p.path != "" {
				outputPath = filepath.Join(outputPath, filepath.Base(p.path))
			} else {
				outputPath = filepath.Join(outputPath, p.cid.String())
			}
		}
		if _, statErr := os.Stat(outputPath); statErr == nil {
			return nil, fmt.Errorf("file already exists: %s (use force to overwrite)", outputPath)
		}
	}
	var reader io.ReadCloser
	if p.path != "" {
		reader, err = dl.GetFile(ctx, p.cid, p.path)
	} else {
		reader, err = dl.DownloadFile(ctx, p.cid)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	f, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	written, err := io.Copy(f, reader)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(outputPath)
		return nil, fmt.Errorf("failed to write file: %w", err)
	}
	return &download.DownloadResult{
		CID:      p.cid.String(),
		Path:     outputPath,
		Size:     written,
		Duration: time.Since(startTime),
	}, nil
}

// FileSize reports the size of a single IPFS node.
func (s *hostedDownloadService) FileSize(ctx context.Context, ipfsPathStr string) (int64, error) {
	p, err := parseHostedIPFSPath(ipfsPathStr)
	if err != nil {
		return -1, err
	}
	dl, err := s.newSDKDownload(ctx)
	if err != nil {
		return -1, err
	}
	return dl.FileSize(ctx, p.cid)
}

// ListDirectory lists the entries of an IPFS directory node (CID or CID/path),
// degrading to a single file entry when the node is not a directory.
func (s *hostedDownloadService) ListDirectory(ctx context.Context, ipfsPathStr string) ([]download.DirEntry, error) {
	p, err := parseHostedIPFSPath(ipfsPathStr)
	if err != nil {
		return nil, err
	}
	dl, err := s.newSDKDownload(ctx)
	if err != nil {
		return nil, err
	}
	var entries []files.DirEntry
	if p.path != "" {
		entries, err = dl.ListDirectoryPath(ctx, p.cid, p.path)
	} else {
		entries, err = dl.ListDirectory(ctx, p.cid)
	}
	if err == nil {
		return mapHostedDirEntries(entries), nil
	}
	// Not a directory: surface a single file entry.
	name := p.cid.String()
	if p.path != "" {
		name = filepath.Base(p.path)
	}
	return []download.DirEntry{{Name: name, Size: -1, Type: "file"}}, nil
}

// mapHostedDirEntries projects ipfs-sdk directory entries onto the shared
// download.DirEntry model.
func mapHostedDirEntries(entries []files.DirEntry) []download.DirEntry {
	result := make([]download.DirEntry, 0, len(entries))
	for _, entry := range entries {
		entryType := "file"
		node := entry.Node()
		if _, ok := node.(files.Directory); ok {
			entryType = "directory"
		}
		var size int64 = -1
		if f, ok := node.(files.File); ok {
			size, _ = f.Size()
		}
		result = append(result, download.DirEntry{Name: entry.Name(), Size: size, Type: entryType})
	}
	return result
}

// compile assertion: hostedDownloadService satisfies download.Service.
var _ download.Service = (*hostedDownloadService)(nil)
