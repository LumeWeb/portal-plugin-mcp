package hosted

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/pinner/core/pinning"
	"go.lumeweb.com/queryutil"
)

// TestParseHostedSorts locks the hosted sort-string parser (comma-separated
// field[:order], default desc).
func TestParseHostedSorts(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []queryutil.Sort
	}{
		{name: "default desc", in: "id", want: []queryutil.Sort{{Field: "id", Order: queryutil.OrderDesc}}},
		{name: "explicit desc", in: "id:desc", want: []queryutil.Sort{{Field: "id", Order: queryutil.OrderDesc}}},
		{name: "explicit asc", in: "started:asc", want: []queryutil.Sort{{Field: "started", Order: queryutil.OrderAsc}}},
		{name: "multi", in: "status:asc,id", want: []queryutil.Sort{{Field: "status", Order: queryutil.OrderAsc}, {Field: "id", Order: queryutil.OrderDesc}}},
		{name: "empty", in: "", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseHostedSorts(tt.in))
		})
	}
}

// TestPageHostedPins locks the client-side Start/Limit paging the IPFS
// pinning-service spec requires (no server-side offset).
func TestPageHostedPins(t *testing.T) {
	pins := []pinning.Pin{{CID: "a"}, {CID: "b"}, {CID: "c"}, {CID: "d"}}

	assert.Len(t, pageHostedPins(pins, 0, 0), 4, "zero limit keeps all rows")
	assert.Equal(t, []string{"b", "c", "d"}, cids(pageHostedPins(pins, 1, 0)), "start offsets, no limit")
	assert.Equal(t, []string{"b", "c"}, cids(pageHostedPins(pins, 1, 2)), "start+limit pages")
	assert.Empty(t, pageHostedPins(pins, 10, 0), "start past end yields empty")
}

// TestNewPinnedServiceUnauthenticatedFailsClosed verifies an empty token yields
// a PinningService that degrades closed on RequireAuthenticated instead of
// panicking on a nil client.
func TestNewPinnedServiceUnauthenticatedFailsClosed(t *testing.T) {
	svc := newPinnedService("https://ipfs.example", "")
	require.NotNil(t, svc)
	assert.ErrorIs(t, svc.RequireAuthenticated(), errHostedNotAuthenticated,
		"an empty token must fail closed, not build a client")

	// Same via the endpoint-deriving constructor against a nil-free manager is
	// exercised by catalogdeps_test; here we assert the fail-closed contract.
	assert.NotNil(t, svc, "the service object is non-nil even unauthenticated")
}

// cids is a helper extracting CID values from a pins slice for assertions.
func cids(pins []pinning.Pin) []string {
	out := make([]string, 0, len(pins))
	for _, p := range pins {
		out = append(out, p.CID)
	}
	return out
}
