package hosted

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	portalsdk "go.lumeweb.com/portal-sdk"
	sdkMocks "go.lumeweb.com/portal-sdk/mocks"
)

// TestFindHostedOperationByCIDSelectsNewest locks waitForPin's operation
// selection: when a CID maps to multiple account operations (a re-upload of
// already-pinned content leaves an older completed operation for the same CID,
// plus THIS session's fresh one), findHostedOperationByCID must resolve to the
// NEWEST operation — regardless of the order the server returns them — or it
// would attach waitForPin to the stale completed operation and report success
// prematurely.
func TestFindHostedOperationByCIDSelectsNewest(t *testing.T) {
	cid := "QmReuploadedContent"
	// Old completed operation returned FIRST (i.e. not newest-first), to prove
	// selection does not depend on the server ordering the results.
	old := operationFromJSON(t, `{"id":100,"cid":"`+cid+`","status":"completed"}`)
	fresh := operationFromJSON(t, `{"id":101,"cid":"`+cid+`","status":"pending"}`)

	client := sdkMocks.NewMockAccountAPI(t)
	client.EXPECT().ListOperations(mock.Anything, mock.Anything, mock.Anything).
		Return([]*portalsdk.Operation{old, fresh}, 2, nil)

	got, err := findHostedOperationByCID(context.Background(), client, cid)
	require.NoError(t, err)
	require.Equal(t, 101, got.Id, "must select THIS session's newest operation, not the stale completed one")
}

// TestFindHostedOperationByCIDNoOperationFailsClosed verifies the fail-closed
// contract: a CID with no account operation must surface an error rather than
// waiting on a nonexistent pin.
func TestFindHostedOperationByCIDNoOperationFailsClosed(t *testing.T) {
	client := sdkMocks.NewMockAccountAPI(t)
	client.EXPECT().ListOperations(mock.Anything, mock.Anything, mock.Anything).
		Return([]*portalsdk.Operation{}, 0, nil)

	_, err := findHostedOperationByCID(context.Background(), client, "QmNothingPinned")
	require.Error(t, err, "a CID with no operation must fail closed")
}

// operationFromJSON builds an account.Operation from a JSON object. The type
// embeds a generated internal/client struct, so it cannot be constructed by
// composite literal from outside the SDK; JSON unmarshal populates the embedded
// struct's tagged fields instead.
func operationFromJSON(t *testing.T, raw string) *portalsdk.Operation {
	t.Helper()
	var op portalsdk.Operation
	require.NoError(t, json.Unmarshal([]byte(raw), &op))
	return &op
}
