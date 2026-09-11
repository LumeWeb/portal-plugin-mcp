package hosted

import "errors"

// errHostedNotAuthenticated is returned by the hosted service concrete
// implementations (operations, pins) when no credential is available to build
// an authenticated client. Catalog handlers wrap this as a clear "authenticate
// to continue" execution error.
var errHostedNotAuthenticated = errors.New("not authenticated: no credential is configured for this hosted request")
