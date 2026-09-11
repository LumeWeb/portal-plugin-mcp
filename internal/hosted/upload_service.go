package hosted

// This file implements the hosted uploads.Service over the public ipfs-sdk
// upload service. In hosted mode there is no frozen config token: the
// per-request Portal API credential travels on the context (stamped via
// mcpplane/credctx by the HTTP credential middleware), so each call resolves
// the credential from ctx and never from a shared config token. StreamUpload
// (pinner/transfer) consumes Upload to power the presigned PUT byte route.

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	ipfs "go.lumeweb.com/ipfs-sdk"
	"go.lumeweb.com/mcpplane/credctx"
	"go.lumeweb.com/pinner/core/auth"
	"go.lumeweb.com/pinner/core/config"
	"go.lumeweb.com/pinner/core/uploads"
	portalsdk "go.lumeweb.com/portal-sdk"
	"go.lumeweb.com/queryutil"
	"go.lumeweb.com/queryutil/filter"
)

// hostedUploadService is the plugin-owned hosted implementation of
// uploads.Service over the public ipfs-sdk upload service. The auth token is
// resolved lazily per call from the request context so it always authenticates
// as the effective credential — never a frozen shared token.
type hostedUploadService struct {
	configMgr       config.Manager
	authSvc         auth.AuthService
	ipfsEndpoint    string
	accountEndpoint string
}

// newHostedUploadService builds the plugin-owned uploads.Service from the
// config manager and auth service. A nil auth service is tolerated: API-key
// JWTs are then passed through un-exchanged.
func newHostedUploadService(cfgMgr config.Manager, ipfsEndpoint string, authSvc auth.AuthService) uploads.Service {
	return &hostedUploadService{
		configMgr:       cfgMgr,
		authSvc:         authSvc,
		ipfsEndpoint:    ipfsEndpoint,
		accountEndpoint: cfgMgr.Config().GetAPIEndpoint(),
	}
}

// resolveHostedUploadToken returns the token for an upload, preferring the
// per-request hosted credential (credctx) and exchanging an API-key JWT for a
// login JWT when one is available (the Pinner TUS/IPFS upload endpoint rejects
// API-key tokens). A missing credential fails closed.
func (s *hostedUploadService) resolveHostedUploadToken(ctx context.Context) (string, error) {
	tok := credctx.From(ctx)
	if tok == "" {
		return "", errHostedNotAuthenticated
	}
	return s.exchangeIfAPIKey(ctx, tok)
}

// exchangeIfAPIKey returns the token to use, exchanging an API-key JWT for a
// login JWT when an authService is available. Decode errors fall back to the
// raw token; non-"api" tokens are returned as-is.
func (s *hostedUploadService) exchangeIfAPIKey(ctx context.Context, authToken string) (string, error) {
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
		return "", fmt.Errorf("failed to exchange API key for upload: %w", err)
	}
	return loginJWT, nil
}

// Upload uploads a file/directory to IPFS and, when wait is true, blocks until
// the pin operation settles. This is the engine behind StreamUpload and the
// presigned PUT byte route.
func (s *hostedUploadService) Upload(ctx context.Context, filesystem fs.FS, name string, wait bool, wrap bool) (*uploads.UploadResult, error) {
	startTime := time.Now()
	authToken, err := s.resolveHostedUploadToken(ctx)
	if err != nil {
		return nil, err
	}

	// Determine the account's upload limit; fall back to the SDK default on
	// error so an unavailable limit never blocks an otherwise-valid upload.
	uploadLimit := int64(0)
	accountClient := portalsdk.NewClient(portalsdk.WithEndpoint(s.accountEndpoint), portalsdk.WithJWT(authToken))
	if lim, err := accountClient.UploadLimit(ctx); err == nil {
		uploadLimit = lim
	}

	opts := &ipfs.UploadOptions{
		MemoryLimit: s.configMgr.Config().GetMemoryLimitBytes(),
		UploadLimit: uploadLimit,
		WrapInDir:   wrap,
	}

	sdkUpload, err := ipfs.NewUploadService(s.ipfsEndpoint, authToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create upload service: %w", err)
	}

	sdkResult, err := sdkUpload.UploadFromFS(ctx, filesystem, name, opts)
	if err != nil {
		return nil, fmt.Errorf("upload failed: %w", err)
	}

	if wait && sdkResult.CID != "" {
		if err := s.waitForPin(ctx, sdkResult.CID, authToken); err != nil {
			return nil, err
		}
	}

	return &uploads.UploadResult{
		CID:      sdkResult.CID,
		Size:     sdkResult.Size,
		Duration: time.Since(startTime),
		Location: sdkResult.Location,
	}, nil
}

// waitForPin waits for the upload's pin to settle by locating the CID's
// account operation (FindOperation) and waiting on it (WaitForOperation).
func (s *hostedUploadService) waitForPin(ctx context.Context, rootCID string, authToken string) error {
	accountClient := portalsdk.NewClient(portalsdk.WithEndpoint(s.accountEndpoint), portalsdk.WithJWT(authToken))
	op, err := findHostedOperationByCID(ctx, accountClient, rootCID)
	if err != nil {
		return err
	}
	_, err = accountClient.WaitForOperation(ctx, int64(op.Id),
		portalsdk.WithPollInterval(2*time.Second),
		portalsdk.WithPollTimeout(s.configMgr.Config().GetUploadTimeout()),
	)
	if err != nil {
		return fmt.Errorf("pin operation failed for CID %s: %w", rootCID, err)
	}
	return nil
}

// findHostedOperationByCID locates the most recent account operation for a
// given CID, or fails closed when none exists. It requests newest-first
// ordering AND defensively selects the operation with the highest id, so a
// re-upload of previously-pinned content resolves to THIS session's fresh
// operation rather than an older completed one for the same CID (attaching
// waitForPin to the stale operation would report success prematurely).
func findHostedOperationByCID(ctx context.Context, client portalsdk.AccountAPI, cid string) (*portalsdk.Operation, error) {
	operations, _, err := client.ListOperations(ctx,
		portalsdk.WithFilters(filter.FieldEqual("cid", cid)),
		portalsdk.WithSorts(queryutil.Sort{Field: "id", Order: queryutil.OrderDesc}),
	)
	if err != nil {
		return nil, err
	}
	if len(operations) == 0 {
		return nil, fmt.Errorf("no pin operation found for CID %s", cid)
	}
	newest := operations[0]
	for _, op := range operations[1:] {
		if op.Id > newest.Id {
			newest = op
		}
	}
	return newest, nil
}

// compile assertion: hostedUploadService satisfies uploads.Service.
var _ uploads.Service = (*hostedUploadService)(nil)
