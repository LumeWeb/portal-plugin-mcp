package hosted

// This file implements the hosted PinningService over the public boxo and
// ipfs-sdk pinning clients. Handlers return pure data; the MCP layer renders
// it. Watch paths terminate once a pin settles (pinned / failed) because an MCP
// agent cannot press Ctrl+C.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gammazero/workerpool"
	boxo "github.com/ipfs/boxo/pinning/remote/client"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multiaddr"
	"github.com/samber/lo"
	ipfs "go.lumeweb.com/ipfs-sdk"
	"go.lumeweb.com/pinner/core/config"
	"go.lumeweb.com/pinner/core/pinning"
)

const (
	// hostedPinPollInterval is the delay between status polls while waiting for
	// a pin to settle (Add-with-wait, Status-watch).
	hostedPinPollInterval = 2 * time.Second
)

// errPinNotFound is returned when a CID has no matching pin.
var errPinNotFound = fmt.Errorf("pin not found")

// pinnedService is the plugin-owned hosted implementation of
// pinning.PinningService. It holds the boxo protocol client for pin
// mutations/status and the ipfs-sdk pinning service for server-side list
// search. Both are pin-bound to the token used at construction.
type pinnedService struct {
	boxoClient    *boxo.Client
	sdkPinningSvc ipfs.PinningService
	ipfsEndpoint  string
	authenticated bool
}

// newPinnedService builds the plugin-owned PinningService against the given
// IPFS pinning endpoint and auth token. An empty token yields an
// unauthenticated service whose operations fail RequireAuthenticated (degrade
// closed); it never panics.
func newPinnedService(ipfsEndpoint, authToken string) pinning.PinningService {
	s := &pinnedService{ipfsEndpoint: ipfsEndpoint}
	if authToken == "" {
		return s
	}
	s.authenticated = true
	s.boxoClient = boxo.NewClient(ipfsEndpoint, authToken)
	if sdk, err := ipfs.NewClient(ipfsEndpoint, authToken); err == nil {
		s.sdkPinningSvc = sdk.Pinning()
	}
	return s
}

// RequireAuthenticated reports whether the service carries a credential. A
// nil token at construction means no client was built, so every operation
// fails closed here.
func (s *pinnedService) RequireAuthenticated() error {
	if !s.authenticated || s.boxoClient == nil {
		return errHostedNotAuthenticated
	}
	return nil
}

// Pin pins existing content by CID. wait=true blocks (polling) until the pin
// settles.
func (s *pinnedService) Pin(ctx context.Context, cidStr, name string, wait bool) (*pinning.PinResult, error) {
	if err := s.RequireAuthenticated(); err != nil {
		return nil, err
	}

	parsedCid, err := cid.Decode(cidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CID: %w", err)
	}

	var opts []boxo.AddOption
	if name != "" {
		opts = append(opts, boxo.PinOpts.WithName(name))
	}

	result, err := s.boxoClient.Add(ctx, parsedCid, opts...)
	if err != nil {
		return nil, err
	}

	if wait {
		if err := s.waitForPinCompletion(ctx, result.GetRequestId()); err != nil {
			return nil, err
		}
	}

	return &pinning.PinResult{CID: cidStr, RequestID: result.GetRequestId(), Status: result.GetStatus().String()}, nil
}

// List returns pinned content with the shared list options. Exact name, status,
// and server-side substring search (match=partial) are evaluated by the
// ipfs-sdk service; Start paging is applied client-side because the IPFS
// pinning-service spec has no server-side offset.
func (s *pinnedService) List(ctx context.Context, opts pinning.ListOptions) ([]pinning.Pin, error) {
	if err := s.RequireAuthenticated(); err != nil {
		return nil, err
	}

	if s.sdkPinningSvc != nil {
		return s.listViaSDK(ctx, opts)
	}
	return s.listViaBoxo(ctx, opts)
}

func (s *pinnedService) listViaSDK(ctx context.Context, opts pinning.ListOptions) ([]pinning.Pin, error) {
	var o []ipfs.ListOption
	switch {
	case opts.Search != "":
		o = append(o, ipfs.WithFilterNamePartial(opts.Search))
	case opts.Name != "":
		o = append(o, ipfs.WithFilterName(opts.Name), ipfs.WithFilterMatch(ipfs.MatchExact))
	}
	if opts.Status != "" {
		o = append(o, ipfs.WithFilterStatus(ipfs.PinStatusEnum(opts.Status)))
	}
	if opts.Limit > 0 {
		o = append(o, ipfs.WithPinningLimit(int32(opts.Start+opts.Limit)))
	}

	statuses, err := s.sdkPinningSvc.ListPins(ctx, o...)
	if err != nil {
		return nil, err
	}

	pins := lo.Map(statuses, func(ps ipfs.PinStatus, _ int) pinning.Pin {
		name := ""
		if ps.Pin.Name != nil {
			name = *ps.Pin.Name
		}
		return pinning.Pin{
			CID:       ps.Pin.Cid,
			Name:      name,
			Status:    string(ps.PinStatusEnum),
			Created:   ps.Created.Format(time.RFC3339),
			RequestID: ps.Requestid,
			Metadata:  mapHostedMeta(ps.Pin.Meta),
		}
	})
	return pageHostedPins(pins, opts.Start, opts.Limit), nil
}

func (s *pinnedService) listViaBoxo(ctx context.Context, opts pinning.ListOptions) ([]pinning.Pin, error) {
	var o []boxo.LsOption
	if opts.Name != "" {
		o = append(o, boxo.PinOpts.FilterName(opts.Name))
	}
	if opts.Status != "" {
		o = append(o, boxo.PinOpts.FilterStatus(boxo.Status(opts.Status)))
	}

	results, err := s.boxoClient.LsSync(ctx, o...)
	if err != nil {
		return nil, err
	}
	if opts.Limit > 0 && len(results) > opts.Start+opts.Limit {
		results = results[:opts.Start+opts.Limit]
	}

	pins := lo.Map(results, func(r boxo.PinStatusGetter, _ int) pinning.Pin {
		p := r.GetPin()
		return pinning.Pin{
			CID:       p.GetCid().String(),
			Name:      p.GetName(),
			Status:    r.GetStatus().String(),
			Created:   r.GetCreated().Format(time.RFC3339),
			RequestID: r.GetRequestId(),
			Metadata:  p.GetMeta(),
		}
	})
	return pageHostedPins(pins, opts.Start, opts.Limit), nil
}

// Status returns the current status of a pin, optionally watching until it
// settles.
func (s *pinnedService) Status(ctx context.Context, cidStr string, watch bool) (*pinning.PinStatus, error) {
	if err := s.RequireAuthenticated(); err != nil {
		return nil, err
	}

	if watch {
		return s.watchPinStatus(ctx, cidStr)
	}

	parsedCid, err := cid.Decode(cidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CID: %w", err)
	}
	results, err := s.boxoClient.LsSync(ctx, boxo.PinOpts.FilterCIDs(parsedCid))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("%w for CID %s", errPinNotFound, cidStr)
	}

	r := results[0]
	return &pinning.PinStatus{
		CID:       r.GetPin().GetCid().String(),
		Status:    string(r.GetStatus()),
		Created:   r.GetCreated().Format(time.RFC3339),
		Delegates: lo.Map(r.GetDelegates(), func(d multiaddr.Multiaddr, _ int) string { return d.String() }),
	}, nil
}

// Unpin removes a pin by CID. confirm must be true; without confirmation a
// single-CID unpin silently no-ops (the destructive gate lives in the wiring
// layer).
func (s *pinnedService) Unpin(ctx context.Context, cidStr string, confirm bool) (*pinning.UnpinResult, error) {
	if err := s.RequireAuthenticated(); err != nil {
		return nil, err
	}

	if !confirm {
		return &pinning.UnpinResult{CID: cidStr}, nil
	}

	parsedCid, err := cid.Decode(cidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CID: %w", err)
	}
	results, err := s.boxoClient.LsSync(ctx, boxo.PinOpts.FilterCIDs(parsedCid))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("%w for CID %s", errPinNotFound, cidStr)
	}

	if err := s.boxoClient.DeleteByID(ctx, results[0].GetRequestId()); err != nil {
		return nil, err
	}
	return &pinning.UnpinResult{CID: cidStr}, nil
}

// UpdateMetadata is a thin alias over UpdatePin with an unchanged name.
func (s *pinnedService) UpdateMetadata(ctx context.Context, cidStr string, set []string, clear bool) error {
	return s.UpdatePin(ctx, cidStr, "", set, clear)
}

// UpdatePin renames and/or updates metadata on an existing pin via a boxo
// Replace, merging the current metadata with the supplied key/value pairs.
func (s *pinnedService) UpdatePin(ctx context.Context, cidStr string, name string, set []string, clear bool) error {
	if err := s.RequireAuthenticated(); err != nil {
		return err
	}
	if len(set)%2 != 0 {
		return fmt.Errorf("metadata key-value pairs must be provided in pairs")
	}

	parsedCid, err := cid.Decode(cidStr)
	if err != nil {
		return fmt.Errorf("invalid CID: %w", err)
	}
	results, err := s.boxoClient.LsSync(ctx, boxo.PinOpts.FilterCIDs(parsedCid))
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("%w: %s", errPinNotFound, cidStr)
	}

	requestID := results[0].GetRequestId()
	meta := results[0].GetPin().GetMeta()
	if meta == nil {
		meta = make(map[string]string)
	}
	if clear {
		meta = make(map[string]string)
	}
	for i := 0; i < len(set); i += 2 {
		if i+1 < len(set) {
			meta[set[i]] = set[i+1]
		}
	}

	opts := []boxo.AddOption{}
	if name != "" {
		opts = append(opts, boxo.PinOpts.WithName(name))
	}
	if len(meta) > 0 {
		opts = append(opts, boxo.PinOpts.AddMeta(meta))
	}
	_, err = s.boxoClient.Replace(ctx, requestID, parsedCid, opts...)
	return err
}

// PinBatch pins multiple CIDs in parallel using a worker pool.
func (s *pinnedService) PinBatch(ctx context.Context, cids []string, name string, opts pinning.BatchOptions) (*pinning.BatchResult, error) {
	if err := s.RequireAuthenticated(); err != nil {
		return nil, err
	}
	if len(cids) == 0 {
		return &pinning.BatchResult{}, nil
	}

	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 1
	}
	startTime := time.Now()
	result := &pinning.BatchResult{
		Total:     len(cids),
		Succeeded: make([]pinning.OperationResult, 0, len(cids)),
		Failed:    make([]pinning.OperationError, 0),
	}
	var mu sync.Mutex
	var firstError error

	wp := workerpool.New(parallel)
	defer wp.Stop()
	for _, cidStr := range cids {
		cidVal := cidStr
		wp.Submit(func() {
			pinResult, err := s.Pin(ctx, cidVal, name, opts.Wait)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if opts.ContinueOn {
					result.Failed = append(result.Failed, errPinBatchFailure(cidVal, err))
					return
				}
				if firstError == nil {
					firstError = err
				}
				return
			}
			result.Succeeded = append(result.Succeeded, pinning.OperationResult{
				CID:       pinResult.CID,
				RequestID: pinResult.RequestID,
				Status:    pinResult.Status,
			})
		})
	}
	wp.StopWait()
	result.Duration = time.Since(startTime)

	if firstError != nil {
		return result, firstError
	}
	return result, nil
}

// UnpinBatch unpins multiple CIDs in parallel using a worker pool.
func (s *pinnedService) UnpinBatch(ctx context.Context, cids []string, opts pinning.BatchOptions) (*pinning.BatchResult, error) {
	if err := s.RequireAuthenticated(); err != nil {
		return nil, err
	}
	if len(cids) == 0 {
		return &pinning.BatchResult{}, nil
	}

	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 1
	}
	startTime := time.Now()
	result := &pinning.BatchResult{
		Total:     len(cids),
		Succeeded: make([]pinning.OperationResult, 0, len(cids)),
		Failed:    make([]pinning.OperationError, 0),
	}
	var mu sync.Mutex
	var firstError error

	wp := workerpool.New(parallel)
	defer wp.Stop()
	for _, cidStr := range cids {
		cidVal := cidStr
		wp.Submit(func() {
			unpinResult, err := s.Unpin(ctx, cidVal, true)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if opts.ContinueOn {
					result.Failed = append(result.Failed, errPinBatchFailure(cidVal, err))
					return
				}
				if firstError == nil {
					firstError = err
				}
				return
			}
			result.Succeeded = append(result.Succeeded, pinning.OperationResult{CID: unpinResult.CID})
		})
	}
	wp.StopWait()
	result.Duration = time.Since(startTime)

	if firstError != nil {
		return result, firstError
	}
	return result, nil
}

// UnpinAll lists all pins (optionally filtered by status) and unpins them in
// parallel.
func (s *pinnedService) UnpinAll(ctx context.Context, statusFilter string, opts pinning.BatchOptions) (*pinning.BatchResult, error) {
	if err := s.RequireAuthenticated(); err != nil {
		return nil, err
	}

	pins, err := s.List(ctx, pinning.ListOptions{Status: statusFilter})
	if err != nil {
		return nil, err
	}
	if len(pins) == 0 {
		return &pinning.BatchResult{}, nil
	}

	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 1
	}
	startTime := time.Now()
	result := &pinning.BatchResult{
		Total:     len(pins),
		Succeeded: make([]pinning.OperationResult, 0, len(pins)),
		Failed:    make([]pinning.OperationError, 0),
	}
	var mu sync.Mutex
	var firstError error

	wp := workerpool.New(parallel)
	defer wp.Stop()
	for _, p := range pins {
		pin := p
		wp.Submit(func() {
			err := s.boxoClient.DeleteByID(ctx, pin.RequestID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if opts.ContinueOn {
					result.Failed = append(result.Failed, errPinBatchFailure(pin.CID, err))
					return
				}
				if firstError == nil {
					firstError = err
				}
				return
			}
			result.Succeeded = append(result.Succeeded, pinning.OperationResult{CID: pin.CID, RequestID: pin.RequestID})
		})
	}
	wp.StopWait()
	result.Duration = time.Since(startTime)

	if firstError != nil {
		return result, firstError
	}
	return result, nil
}

// waitForPinCompletion polls a pin by request ID until it settles (pinned =
// success, failed = error) or the context is canceled.
func (s *pinnedService) waitForPinCompletion(ctx context.Context, requestID string) error {
	ticker := time.NewTicker(hostedPinPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			result, err := s.boxoClient.GetStatusByID(ctx, requestID)
			if err != nil {
				return err
			}
			switch result.GetStatus() {
			case boxo.StatusPinned:
				return nil
			case boxo.StatusFailed:
				return errors.New("pin failed")
			}
		}
	}
}

// watchPinStatus polls a CID's status until it settles. It terminates on
// pinned (returns the final status) or failed (error) so an agent never blocks
// indefinitely.
func (s *pinnedService) watchPinStatus(ctx context.Context, cidStr string) (*pinning.PinStatus, error) {
	ticker := time.NewTicker(hostedPinPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			status, err := s.Status(ctx, cidStr, false)
			if err != nil {
				return nil, err
			}
			switch boxo.Status(status.Status) {
			case boxo.StatusPinned:
				return status, nil
			case boxo.StatusFailed:
				return nil, fmt.Errorf("pin failed for CID %s", cidStr)
			}
		}
	}
}

// mapHostedMeta converts the SDK's *PinMeta metadata to a plain map.
func mapHostedMeta(meta *ipfs.PinMeta) map[string]string {
	if meta == nil {
		return map[string]string{}
	}
	return map[string]string(*meta)
}

// pageHostedPins applies the client-side Start/Limit slice. A zero Limit means
// "keep all rows from Start onward".
func pageHostedPins(pins []pinning.Pin, start, limit int) []pinning.Pin {
	if start > 0 {
		if start >= len(pins) {
			return []pinning.Pin{}
		}
		pins = pins[start:]
	}
	if limit > 0 && len(pins) > limit {
		pins = pins[:limit]
	}
	return pins
}

// errPinBatchFailure builds a batch OperationError row for a failed CID.
func errPinBatchFailure(cidStr string, err error) pinning.OperationError {
	return pinning.OperationError{CID: cidStr, Error: err.Error()}
}

// newPinnedServiceFor is the per-endpoint constructor used by the PinsDeps
// wiring: it derives the IPFS endpoint from the live config manager and the
// secure flag, then builds a service pinned to the given token ("" = config
// token fallback handled by the caller).
func newPinnedServiceFor(cfgMgr config.Manager, secure bool, token string) pinning.PinningService {
	return newPinnedService(cfgMgr.Config().GetIPFSEndpointWithSecure(secure), token)
}

// compile assertions.
var (
	_ pinning.PinningService = (*pinnedService)(nil)
)
