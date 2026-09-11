package hosted

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.lumeweb.com/pinner/core/auth"
	"go.lumeweb.com/pinner/core/operations"
	portalsdk "go.lumeweb.com/portal-sdk"
	"go.lumeweb.com/queryutil"
	"go.lumeweb.com/queryutil/filter"
)

// operationsService is the plugin-owned hosted implementation of
// operations.Service over the public Portal SDK account client. It is reused
// per hosted server; the account client is resolved lazily per call from the
// auth service so it always authenticates as the effective credential.
type operationsService struct {
	authSvc auth.AuthService
}

// newOperationsService builds the plugin-owned operations.Service from the
// given auth service. A nil auth service yields a service whose calls fail the
// authentication requirement (degrade closed) rather than panicking.
func newOperationsService(authSvc auth.AuthService) operations.Service {
	return &operationsService{authSvc: authSvc}
}

// resolveAccountClient lazily exchanges the current credential for an
// authenticated account client, caching it on first use.
func (s *operationsService) resolveAccountClient(ctx context.Context) (portalsdk.AccountAPI, error) {
	if s.authSvc == nil {
		return nil, errHostedNotAuthenticated
	}
	client, err := s.authSvc.GetAuthenticatedClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}
	return client, nil
}

// RequireAuthenticated checks the service can build an authenticated account
// client, surfacing a clear error when no credential is available.
func (s *operationsService) RequireAuthenticated() error {
	if s.authSvc == nil {
		return errHostedNotAuthenticated
	}
	_, err := s.resolveAccountClient(context.Background())
	return err
}

// List returns a paginated, filterable listing of the calling account's
// operations. When no statuses are requested and IncludeAll/IsWatch are unset,
// only active operations (pending, processing) are shown.
func (s *operationsService) List(ctx context.Context, opts operations.ListOptions) (*operations.OperationsListResult, error) {
	client, err := s.resolveAccountClient(ctx)
	if err != nil {
		return nil, err
	}

	var listOpts []portalsdk.ListOption
	var filters []queryutil.CrudFilter

	statuses := opts.StatusFilters
	if len(statuses) == 0 && !opts.IncludeAll && !opts.IsWatch {
		statuses = []string{
			string(portalsdk.OperationStatusPending),
			string(portalsdk.OperationStatusProcessing),
		}
	}
	if len(statuses) > 0 {
		vals := make([]any, len(statuses))
		for i, st := range statuses {
			vals[i] = st
		}
		filters = append(filters, filter.FieldIn("status", vals...))
	}
	if opts.OperationFilter != "" {
		filters = append(filters, filter.FieldEqual("operation", opts.OperationFilter))
	}
	if opts.ProtocolFilter != "" {
		filters = append(filters, filter.FieldEqual("protocol", opts.ProtocolFilter))
	}
	if opts.CIDFilter != "" {
		filters = append(filters, filter.FieldEqual("cid", opts.CIDFilter))
	}
	if len(filters) > 0 {
		listOpts = append(listOpts, portalsdk.WithFilters(filters...))
	}

	if opts.Search != "" {
		listOpts = append(listOpts, portalsdk.WithSearch(opts.Search))
	}

	sortStr := opts.Sort
	if sortStr == "" {
		sortStr = "id:desc"
	}
	if sorts := parseHostedSorts(sortStr); len(sorts) > 0 {
		listOpts = append(listOpts, portalsdk.WithSorts(sorts...))
	}

	if opts.Limit > 0 {
		listOpts = append(listOpts, portalsdk.WithPagination(&queryutil.Pagination{
			Start:    opts.Start,
			End:      opts.Start + opts.Limit,
			PageSize: opts.Limit,
		}))
	}

	operationsList, total, err := client.ListOperations(ctx, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to list operations: %w", err)
	}

	result := &operations.OperationsListResult{
		Operations: make([]operations.OperationListItem, 0, len(operationsList)),
		Total:      total,
	}
	for _, op := range operationsList {
		result.Operations = append(result.Operations, mapOperationListItem(op))
	}
	return result, nil
}

// Get returns the full detail of a single operation by ID.
func (s *operationsService) Get(ctx context.Context, id int64) (*operations.OperationDetail, error) {
	client, err := s.resolveAccountClient(ctx)
	if err != nil {
		return nil, err
	}
	op, err := client.GetOperation(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get operation %d: %w", id, err)
	}
	return mapOperationDetail(op), nil
}

// Watch polls a single operation until it settles, surfacing the terminal
// detail (or error) to an awaiting agent.
func (s *operationsService) Watch(ctx context.Context, id int64) (*operations.OperationDetail, error) {
	client, err := s.resolveAccountClient(ctx)
	if err != nil {
		return nil, err
	}
	op, err := client.WaitForOperation(ctx, id,
		portalsdk.WithPollInterval(2*time.Second),
		portalsdk.WithPollTimeout(5*time.Minute),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for operation %d: %w", id, err)
	}
	return mapOperationDetail(op), nil
}

// mapOperationListItem projects a Portal SDK operation row onto the shared
// operations.OperationListItem model.
func mapOperationListItem(op *portalsdk.Operation) operations.OperationListItem {
	item := operations.OperationListItem{
		ID:                   op.Id,
		Operation:            op.Operation,
		OperationDisplayName: op.OperationDisplayName,
		Protocol:             op.Protocol,
		ProtocolDisplayName:  op.ProtocolDisplayName,
		Status:               op.Status,
		StatusDisplayName:    op.StatusDisplayName,
		StatusMessage:        op.StatusMessage,
		ProgressPercent:      op.ProgressPercent,
		StartedAt:            op.StartedAt.Format(time.RFC3339),
		UpdatedAt:            op.UpdatedAt.Format(time.RFC3339),
		CurrentStep:          op.CurrentStep,
		TotalSteps:           op.TotalSteps,
	}
	if op.Cid != nil {
		item.CID = *op.Cid
	}
	if op.Error != nil {
		item.Error = *op.Error
	}
	return item
}

// mapOperationDetail projects a Portal SDK operation onto the shared
// operations.OperationDetail model.
func mapOperationDetail(op *portalsdk.Operation) *operations.OperationDetail {
	detail := &operations.OperationDetail{
		ID:                   op.Id,
		Operation:            op.Operation,
		OperationDisplayName: op.OperationDisplayName,
		Protocol:             op.Protocol,
		ProtocolDisplayName:  op.ProtocolDisplayName,
		Status:               op.Status,
		StatusDisplayName:    op.StatusDisplayName,
		StatusMessage:        op.StatusMessage,
		ProgressPercent:      op.ProgressPercent,
		StartedAt:            op.StartedAt.Format(time.RFC3339),
		UpdatedAt:            op.UpdatedAt.Format(time.RFC3339),
		CurrentStep:          op.CurrentStep,
		TotalSteps:           op.TotalSteps,
	}
	if op.Cid != nil {
		detail.CID = *op.Cid
	}
	if op.Error != nil && *op.Error != "" {
		detail.Error = *op.Error
	}
	return detail
}

// parseHostedSorts parses a comma-separated "field:order" sort string into
// queryutil.Sort values, defaulting an order-less field to descending.
func parseHostedSorts(sortStr string) []queryutil.Sort {
	var sorts []queryutil.Sort
	for _, part := range strings.Split(sortStr, ",") {
		field := strings.TrimSpace(part)
		if field == "" {
			continue
		}
		order := queryutil.OrderDesc
		if idx := strings.Index(part, ":"); idx > 0 {
			field = strings.TrimSpace(part[:idx])
			switch strings.ToLower(strings.TrimSpace(part[idx+1:])) {
			case "asc":
				order = queryutil.OrderAsc
			case "desc":
				order = queryutil.OrderDesc
			}
		}
		sorts = append(sorts, queryutil.Sort{Field: field, Order: order})
	}
	return sorts
}

// compile assertion: operationsService satisfies operations.Service.
var _ operations.Service = (*operationsService)(nil)
