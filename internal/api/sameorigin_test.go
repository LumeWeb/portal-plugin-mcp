package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSameOrigin(t *testing.T) {
	base := "https://dashboard.example.com"
	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		{"same host and scheme", "https://dashboard.example.com", true},
		{"origin without port matches", "https://dashboard.example.com:443", true},
		{"different host", "https://evil.example.com", false},
		{"different scheme", "http://dashboard.example.com", false},
		{"unparsable origin", "%%%", false},
		{"empty origin", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, sameOrigin(base, tc.origin))
		})
	}
}

func TestSameOrigin_SchemeLessBase(t *testing.T) {
	// Tests may resolve an APISubdomain without a scheme; the host must still
	// match while a scheme mismatch is tolerated when the base has none.
	require.True(t, sameOrigin("dashboard.example.com", "https://dashboard.example.com"))
	require.False(t, sameOrigin("dashboard.example.com", "https://evil.example.com"))
}
