// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/singleflight"
)

// ClientLookupFunc resolves a client from its identifier.
type ClientLookupFunc func(context.Context, string) (Client, error)

// ClientResolver decorates the authorization server's registered-client lookup.
type ClientResolver interface {
	ResolveClient(context.Context, string, ClientLookupFunc) (Client, error)
}

// ClientResolverProvider optionally provides a client resolver without extending Configurator.
type ClientResolverProvider interface {
	GetClientResolver(context.Context) ClientResolver
}

// ClientResolverFunc implements ClientResolver for a function.
type ClientResolverFunc func(context.Context, string, ClientLookupFunc) (Client, error)

// ResolveClient implements ClientResolver for a function.
func (f ClientResolverFunc) ResolveClient(ctx context.Context, clientID string, next ClientLookupFunc) (Client, error) {
	return f(ctx, clientID, next)
}

// resolveClient applies the optional resolver around the configured client store.
func (f *Fosite) resolveClient(ctx context.Context, clientID string) (Client, error) {
	next := ClientLookupFunc(f.Store.GetClient)
	if provider, ok := f.Config.(ClientResolverProvider); ok {
		if resolver := provider.GetClientResolver(ctx); resolver != nil {
			return resolver.ResolveClient(ctx, clientID, next)
		}
	}
	return next(ctx, clientID)
}

// CIMDCachedClient contains a materialized metadata client and its HTTP freshness lifetime.
type CIMDCachedClient struct {
	Client    Client
	ExpiresAt time.Time
}

// CIMDClientCache persists materialized metadata clients while their metadata is fresh.
type CIMDClientCache interface {
	LoadCIMDClient(context.Context, string) (CIMDCachedClient, bool, error)
	StoreCIMDClient(context.Context, Client, *ClientMetadataDocument, time.Time) (Client, error)
}

// CIMDClientCacheEvictor removes an existing cached metadata client when a response forbids storage.
type CIMDClientCacheEvictor interface {
	EvictCIMDClient(context.Context, string) error
}

// CIMDClientMaterializer projects a validated metadata document into a provider client.
type CIMDClientMaterializer interface {
	MaterializeCIMDClient(context.Context, *ClientMetadataDocument) (Client, error)
}

// CIMDClientMaterializerFunc implements CIMDClientMaterializer for a function.
type CIMDClientMaterializerFunc func(context.Context, *ClientMetadataDocument) (Client, error)

// MaterializeCIMDClient calls f.
func (f CIMDClientMaterializerFunc) MaterializeCIMDClient(ctx context.Context, document *ClientMetadataDocument) (Client, error) {
	return f(ctx, document)
}

// CIMDClientPolicy applies authorization-server policy before and after discovery.
type CIMDClientPolicy interface {
	AllowCIMDClient(context.Context, string) error
	ValidateCIMDClient(context.Context, *ClientMetadataDocument) error
}

// CIMDClientPolicyFuncs implements CIMDClientPolicy with optional functions.
type CIMDClientPolicyFuncs struct {
	Allow    func(context.Context, string) error
	Validate func(context.Context, *ClientMetadataDocument) error
}

// AllowCIMDClient applies the identifier policy when configured.
func (p CIMDClientPolicyFuncs) AllowCIMDClient(ctx context.Context, clientID string) error {
	if p.Allow == nil {
		return nil
	}
	return p.Allow(ctx, clientID)
}

// ValidateCIMDClient applies the document policy when configured.
func (p CIMDClientPolicyFuncs) ValidateCIMDClient(ctx context.Context, document *ClientMetadataDocument) error {
	if p.Validate == nil {
		return nil
	}
	return p.Validate(ctx, document)
}

// CIMDResolver resolves unregistered Client Identifier URLs while preserving pre-registered-client precedence.
type CIMDResolver struct {
	Fetcher      CIMDFetcher
	Cache        CIMDClientCache
	Materializer CIMDClientMaterializer
	Policy       CIMDClientPolicy
	Now          func() time.Time

	group singleflight.Group
}

var _ ClientResolver = (*CIMDResolver)(nil)

// ResolveClient returns a fresh cached metadata client, a pre-registered client, or a newly discovered metadata client.
func (r *CIMDResolver) ResolveClient(ctx context.Context, clientID string, next ClientLookupFunc) (Client, error) {
	if next == nil {
		return nil, errors.New("registered client resolver is required")
	}

	cached, found, err := r.load(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if found {
		if err := r.allow(ctx, clientID); err != nil {
			return nil, err
		}
		if r.now().Before(cached.ExpiresAt) {
			return r.configureClient(cached.Client)
		}
		return r.discover(ctx, clientID, next, true)
	}

	client, err := next(ctx, clientID)
	if err == nil {
		return client, nil
	}
	if !errors.Is(err, ErrNotFound) || !LooksLikeCIMDURL(clientID) {
		return nil, err
	}
	return r.discover(ctx, clientID, next, false)
}

// RefreshClient re-fetches a previously associated metadata client regardless of its freshness.
func (r *CIMDResolver) RefreshClient(ctx context.Context, clientID string) (Client, error) {
	_, found, err := r.load(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return r.discover(ctx, clientID, nil, true)
}

func (r *CIMDResolver) discover(ctx context.Context, clientID string, next ClientLookupFunc, associated bool) (Client, error) {
	result := r.group.DoChan(clientID, func() (any, error) {
		cached, found, err := r.load(ctx, clientID)
		if err != nil {
			return nil, err
		}
		if found && !associated && r.now().Before(cached.ExpiresAt) {
			return r.configureClient(cached.Client)
		}
		if !found && next != nil {
			client, err := next(ctx, clientID)
			if err == nil {
				return client, nil
			}
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
		}
		return r.fetchAndMaterialize(ctx, clientID)
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resolved := <-result:
		if resolved.Err != nil {
			return nil, resolved.Err
		}
		client, ok := resolved.Val.(Client)
		if !ok {
			return nil, errors.New("CIMD resolver returned an invalid client")
		}
		return client, nil
	}
}

func (r *CIMDResolver) fetchAndMaterialize(ctx context.Context, clientID string) (Client, error) {
	if r.Fetcher == nil {
		return nil, errors.New("CIMD fetcher is required")
	}
	if _, err := ParseCIMDURL(clientID); err != nil {
		return nil, err
	}
	if err := r.allow(ctx, clientID); err != nil {
		return nil, err
	}

	document, ttl, err := r.Fetcher.Fetch(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	if r.Policy != nil {
		if err := r.Policy.ValidateCIMDClient(ctx, document); err != nil {
			return nil, fmt.Errorf("client metadata violates authorization server policy: %w", err)
		}
	}

	client, err := r.materialize(ctx, document)
	if err != nil {
		return nil, fmt.Errorf("materialize client metadata: %w", err)
	}
	client, err = r.configureClient(client)
	if err != nil {
		return nil, err
	}
	if r.Cache == nil {
		return client, nil
	}
	if ttl <= 0 {
		if evictor, ok := r.Cache.(CIMDClientCacheEvictor); ok {
			if err := evictor.EvictCIMDClient(ctx, clientID); err != nil {
				return nil, fmt.Errorf("evict client metadata: %w", err)
			}
		}
		return client, nil
	}
	stored, err := r.Cache.StoreCIMDClient(ctx, client, document, r.now().Add(ttl))
	if err != nil {
		return nil, fmt.Errorf("store client metadata: %w", err)
	}
	if stored == nil {
		return nil, errors.New("stored CIMD client is nil")
	}
	return r.configureClient(stored)
}

func (r *CIMDResolver) load(ctx context.Context, clientID string) (CIMDCachedClient, bool, error) {
	if r.Cache == nil {
		return CIMDCachedClient{}, false, nil
	}
	cached, found, err := r.Cache.LoadCIMDClient(ctx, clientID)
	if err != nil {
		return CIMDCachedClient{}, false, fmt.Errorf("load client metadata: %w", err)
	}
	if found && cached.Client == nil {
		return CIMDCachedClient{}, false, errors.New("cached CIMD client is nil")
	}
	return cached, found, nil
}

func (r *CIMDResolver) materialize(ctx context.Context, document *ClientMetadataDocument) (Client, error) {
	if r.Materializer != nil {
		return r.Materializer.MaterializeCIMDClient(ctx, document)
	}
	return NewCIMDClient(document)
}

func (r *CIMDResolver) allow(ctx context.Context, clientID string) error {
	if r.Policy == nil {
		return nil
	}
	if err := r.Policy.AllowCIMDClient(ctx, clientID); err != nil {
		return fmt.Errorf("CIMD client is not allowed: %w", err)
	}
	return nil
}

func (r *CIMDResolver) configureClient(client Client) (Client, error) {
	metadataClient, ok := client.(*CIMDClient)
	if !ok {
		return client, nil
	}
	provider, _ := r.Fetcher.(CIMDSecureHTTPClientProvider)
	if err := metadataClient.configureSecureHTTPClient(provider); err != nil {
		return nil, fmt.Errorf("configure CIMD client: %w", err)
	}
	return metadataClient, nil
}

func (r *CIMDResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
