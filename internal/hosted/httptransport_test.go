package hosted

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/mcpplane/credctx"
)

// rawResolver is a plain CredentialResolver fixture that resolves a fixed
// token, blank → a caller-supplied error, so fail-closed behaviour is pinned
// without identity semantics in scope.
type rawResolver struct {
	token string
	err   error
}

func (r rawResolver) TokenForRequest(ctx context.Context) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	return r.token, nil
}

func TestHTTPHandlerNilResolverIsPassthrough(t *testing.T) {
	h := HTTPHandler(fakeServer(), nil, false)
	require.NotNil(t, h)

	// The credential middleware is not installed when there is no resolver:
	// the request reaches the streamable handler and no credential is injected.
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// A stateless streamable handler answers the ping (200) rather than 401 —
	// proving no fail-closed credential gate is in front of it.
	require.NotEqual(t, http.StatusUnauthorized, rec.Code, "nil resolver must not install the credential gate")
}

func TestCredentialMiddlewareFailClosedOnBlankToken(t *testing.T) {
	var nextCalled bool
	mw := credentialMiddleware(rawResolver{token: ""}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code, "blank token must fail closed")
	assert.False(t, nextCalled, "downstream handler must not run on fail-closed rejection")
}

func TestCredentialMiddlewareFailClosedOnError(t *testing.T) {
	var nextCalled bool
	mw := credentialMiddleware(rawResolver{err: errors.New("boom")}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, nextCalled)
}

func TestCredentialMiddlewarePassesThroughOnNotConfigured(t *testing.T) {
	var nextCalled bool
	mw := credentialMiddleware(rawResolver{err: ErrCredentialsNotConfigured}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		assert.Equal(t, "", credctx.From(r.Context()), "not-configured must pass through with no injected identity")
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, nextCalled, "ErrCredentialsNotConfigured behaves like an absent middleware")
}

func TestCredentialMiddlewareInjectsResolvedToken(t *testing.T) {
	var gotCred string
	mw := credentialMiddleware(rawResolver{token: "tok-123"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCred = credctx.From(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "tok-123", gotCred, "resolved token must be carried on the request context")
}

func TestCredentialFromContextEmpty(t *testing.T) {
	assert.Equal(t, "", credentialFromContext(context.Background()))
}
