// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubCIMDFetcher struct {
	document *ClientMetadataDocument
	ttl      time.Duration
	err      error
	calls    int
}

func (f *stubCIMDFetcher) Fetch(_ context.Context, _ string) (*ClientMetadataDocument, time.Duration, error) {
	f.calls++
	return f.document, f.ttl, f.err
}

type stubCIMDCache struct {
	clients    map[string]CIMDCachedClient
	storeCalls int
	evictions  int
}

func (c *stubCIMDCache) LoadCIMDClient(_ context.Context, clientID string) (CIMDCachedClient, bool, error) {
	client, found := c.clients[clientID]
	return client, found, nil
}

func (c *stubCIMDCache) StoreCIMDClient(_ context.Context, client Client, _ *ClientMetadataDocument, expiresAt time.Time) (Client, error) {
	c.storeCalls++
	c.clients[client.GetID()] = CIMDCachedClient{Client: client, ExpiresAt: expiresAt}
	return client, nil
}

func (c *stubCIMDCache) EvictCIMDClient(_ context.Context, clientID string) error {
	c.evictions++
	delete(c.clients, clientID)
	return nil
}

func TestCIMDResolver(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	document := &ClientMetadataDocument{ClientID: id, TokenEndpointAuthMethod: "none"}
	notFound := ClientLookupFunc(func(context.Context, string) (Client, error) {
		return nil, ErrNotFound
	})

	t.Run("pre-registered URL client wins", func(t *testing.T) {
		registered := &DefaultClient{ID: id}
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		resolver := &CIMDResolver{Fetcher: fetcher, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) {
			return registered, nil
		})
		require.NoError(t, err)
		assert.Same(t, registered, client)
		assert.Zero(t, fetcher.calls)
	})

	t.Run("unregistered URL client is discovered and cached", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.NoError(t, err)
		assert.Equal(t, id, client.GetID())
		assert.Equal(t, 1, fetcher.calls)
		assert.Equal(t, 1, cache.storeCalls)
		assert.Equal(t, now.Add(time.Hour), cache.clients[id].ExpiresAt)

		_, err = resolver.ResolveClient(t.Context(), id, notFound)
		require.NoError(t, err)
		assert.Equal(t, 1, fetcher.calls)
	})

	t.Run("stale associated client is refreshed", func(t *testing.T) {
		stale := &DefaultClient{ID: id}
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: stale, ExpiresAt: now.Add(-time.Minute)},
		}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.NoError(t, err)
		assert.NotSame(t, stale, client)
		assert.Equal(t, 1, fetcher.calls)
		assert.Equal(t, 1, cache.storeCalls)
	})

	t.Run("policy rejects before fetching", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		resolver := &CIMDResolver{
			Fetcher: fetcher,
			Policy: CIMDClientPolicyFuncs{Allow: func(context.Context, string) error {
				return errors.New("denied")
			}},
		}

		_, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.ErrorContains(t, err, "denied")
		assert.Zero(t, fetcher.calls)
	})

	t.Run("policy is reapplied to cached metadata clients", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: &DefaultClient{ID: id}, ExpiresAt: now.Add(time.Hour)},
		}}
		resolver := &CIMDResolver{
			Fetcher: fetcher,
			Cache:   cache,
			Policy: CIMDClientPolicyFuncs{Allow: func(context.Context, string) error {
				return errors.New("denied")
			}},
			Now: func() time.Time { return now },
		}

		_, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.ErrorContains(t, err, "denied")
		assert.Zero(t, fetcher.calls)
	})

	t.Run("no-store response is returned but not cached", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{document: document}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: &DefaultClient{ID: id}, ExpiresAt: now.Add(-time.Minute)},
		}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.NoError(t, err)
		assert.Equal(t, id, client.GetID())
		assert.Zero(t, cache.storeCalls)
		assert.Equal(t, 1, cache.evictions)
		_, found := cache.clients[id]
		assert.False(t, found)
	})
}

func TestCIMDResolver_RefreshClientRequiresAssociation(t *testing.T) {
	resolver := &CIMDResolver{
		Fetcher: &stubCIMDFetcher{},
		Cache:   &stubCIMDCache{clients: map[string]CIMDCachedClient{}},
	}

	_, err := resolver.RefreshClient(t.Context(), "https://app.example.com/oauth/client")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestCIMDResolver_ConfiguresGuardedJWKSFetching(t *testing.T) {
	const (
		id      = "https://client.example.com/oauth/client"
		jwksURI = "https://keys.example.com/jwks.json"
	)
	documentResponse := cimdMockResponse(http.StatusOK, `{
		"client_id":"https://client.example.com/oauth/client",
		"token_endpoint_auth_method":"private_key_jwt",
		"jwks_uri":"https://keys.example.com/jwks.json"
	}`)
	keysResponse := cimdMockResponse(http.StatusOK, `{"keys":[]}`)
	fetcher := NewDefaultCIMDFetcher(
		WithCIMDTransport(&cimdMockRoundTripper{responses: map[string]*http.Response{
			id:      documentResponse,
			jwksURI: keysResponse,
		}}),
		WithCIMDAllowPrivateIPs(true),
	)
	resolver := &CIMDResolver{Fetcher: fetcher}

	resolved, err := resolver.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) {
		return nil, ErrNotFound
	})
	require.NoError(t, err)

	client, ok := resolved.(*CIMDClient)
	require.True(t, ok)
	keys, err := client.ResolveCIMDJSONWebKeys(t.Context(), false)
	require.NoError(t, err)
	assert.Empty(t, keys.Keys)
}
