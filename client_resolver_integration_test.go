// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestClientResolverIsUsedForClientAuthentication(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	resolved := &fosite.DefaultClient{ID: "resolved-client", Public: true}
	config := &fosite.Config{
		ClientResolver: fosite.ClientResolverFunc(func(_ context.Context, clientID string, _ fosite.ClientLookupFunc) (fosite.Client, error) {
			assert.Equal(t, "requested-client", clientID)
			return resolved, nil
		}),
	}
	provider := &fosite.Fosite{Store: store, Config: config}
	request := httptest.NewRequest("POST", "https://server.example.com/oauth/token", nil)

	client, err := provider.DefaultClientAuthenticationStrategy(t.Context(), request, url.Values{"client_id": {"requested-client"}})
	require.NoError(t, err)
	assert.Same(t, resolved, client)
}
