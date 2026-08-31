package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	portalservice "go.lumeweb.com/portal/service"
)

func TestOAuthServerError(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"disabled", portalservice.ErrOAuthDisabled, http.StatusServiceUnavailable},
		{"resource-not-registered", portalservice.ErrResourceNotRegistered, http.StatusNotFound},
		{"wrapped-disabled", fmt.Errorf("wrap: %w", portalservice.ErrOAuthDisabled), http.StatusServiceUnavailable},
		{"generic", errors.New("boom"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, status := oauthServerError(tc.err)
			require.Equal(t, serverErrorCode, code)
			require.Equal(t, tc.wantStatus, status)
		})
	}
}
