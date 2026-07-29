// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-retryablehttp"
)

// LooksLikeCIMDURL reports whether clientID is a candidate Client Identifier URL.
//
// A URL-shaped identifier is not necessarily backed by a Client ID Metadata
// Document. Callers must give pre-registered clients precedence before attempting
// metadata discovery.
func LooksLikeCIMDURL(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") && u.Hostname() != ""
}

// ParseCIMDURL parses and validates a Client Identifier URL.
func ParseCIMDURL(clientID string) (*url.URL, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id URL: %w", err)
	}
	if err := ValidateCIMDURL(u); err != nil {
		return nil, err
	}
	if strings.Contains(clientID, "#") {
		return nil, errors.New("client_id URL must not contain a fragment")
	}
	return u, nil
}

// ValidateCIMDURL enforces the Client Identifier URL requirements from draft-ietf-oauth-client-id-metadata-document-02 section 3.
func ValidateCIMDURL(u *url.URL) error {
	if u == nil {
		return errors.New("client_id URL is required")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("client_id URL must use the https scheme")
	}
	if u.Hostname() == "" {
		return errors.New("client_id URL must have a host")
	}
	if u.User != nil {
		return errors.New("client_id URL must not contain userinfo")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return errors.New("client_id URL must not contain a fragment")
	}
	if u.Path == "" {
		return errors.New("client_id URL must contain a path component")
	}
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("client_id URL must not contain %q path segments", seg)
		}
	}
	return nil
}

// ClientMetadataDocument contains registered OAuth client metadata published at a Client Identifier URL.
//
// AdditionalMetadata preserves registered extensions and future metadata members
// that this version of Fosite does not interpret.
type ClientMetadataDocument struct {
	ClientID                      string                     `json:"client_id"`
	RedirectURIs                  []string                   `json:"redirect_uris"`
	TokenEndpointAuthMethod       string                     `json:"token_endpoint_auth_method"`
	GrantTypes                    []string                   `json:"grant_types"`
	ResponseTypes                 []string                   `json:"response_types"`
	ClientName                    string                     `json:"client_name"`
	ClientURI                     string                     `json:"client_uri"`
	LogoURI                       string                     `json:"logo_uri"`
	Scope                         string                     `json:"scope"`
	Contacts                      []string                   `json:"contacts"`
	TOSURI                        string                     `json:"tos_uri"`
	PolicyURI                     string                     `json:"policy_uri"`
	JWKSURI                       string                     `json:"jwks_uri"`
	JWKS                          *jose.JSONWebKeySet        `json:"jwks"`
	SoftwareID                    string                     `json:"software_id"`
	SoftwareVersion               string                     `json:"software_version"`
	SoftwareStatement             string                     `json:"software_statement"`
	RequestURIs                   []string                   `json:"request_uris"`
	RequestObjectSigningAlgorithm string                     `json:"request_object_signing_alg"`
	TokenEndpointAuthSigningAlg   string                     `json:"token_endpoint_auth_signing_alg"`
	PostLogoutRedirectURIs        []string                   `json:"post_logout_redirect_uris"`
	AdditionalMetadata            map[string]json.RawMessage `json:"-"`

	// Presence of these values is forbidden by the CIMD credential restrictions.
	ClientSecret          *string `json:"client_secret"`
	ClientSecretExpiresAt *int64  `json:"client_secret_expires_at"`
}

// UnmarshalJSON decodes known metadata and retains unrecognized members for provider policy and change detection.
func (d *ClientMetadataDocument) UnmarshalJSON(data []byte) error {
	type documentAlias ClientMetadataDocument

	var decoded documentAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	var additional map[string]json.RawMessage
	if err := json.Unmarshal(data, &additional); err != nil {
		return err
	}
	for _, key := range clientMetadataDocumentKnownFields {
		delete(additional, key)
	}
	if len(additional) == 0 {
		additional = nil
	}

	*d = ClientMetadataDocument(decoded)
	d.AdditionalMetadata = additional
	return nil
}

var clientMetadataDocumentKnownFields = []string{
	"client_id",
	"redirect_uris",
	"token_endpoint_auth_method",
	"grant_types",
	"response_types",
	"client_name",
	"client_uri",
	"logo_uri",
	"scope",
	"contacts",
	"tos_uri",
	"policy_uri",
	"jwks_uri",
	"jwks",
	"software_id",
	"software_version",
	"software_statement",
	"request_uris",
	"request_object_signing_alg",
	"token_endpoint_auth_signing_alg",
	"post_logout_redirect_uris",
	"client_secret",
	"client_secret_expires_at",
}

// Validate checks the protocol-level CIMD invariants against the URL used to retrieve the document.
func (d *ClientMetadataDocument) Validate(clientID string) error {
	if d == nil {
		return errors.New("client metadata document is required")
	}
	if d.ClientID == "" {
		return errors.New("client metadata document must contain client_id")
	}
	if _, err := ParseCIMDURL(clientID); err != nil {
		return fmt.Errorf("invalid client_id in metadata document: %w", err)
	}
	if d.ClientID != clientID {
		return fmt.Errorf("client_id %q does not match document URL %q", d.ClientID, clientID)
	}
	if d.ClientSecret != nil || d.ClientSecretExpiresAt != nil {
		return errors.New("client metadata document must not contain a client secret")
	}
	switch d.TokenEndpointAuthMethod {
	case "client_secret_basic", "client_secret_post", "client_secret_jwt":
		return fmt.Errorf("client metadata document must not use symmetric authentication method %q", d.TokenEndpointAuthMethod)
	}
	if d.JWKS != nil && d.JWKSURI != "" {
		return errors.New("client metadata document must not contain both jwks and jwks_uri")
	}
	if d.JWKS != nil {
		for i := range d.JWKS.Keys {
			if !d.JWKS.Keys[i].IsPublic() {
				return errors.New("client metadata document must not contain private key material")
			}
		}
	}
	if d.TokenEndpointAuthMethod == "private_key_jwt" && d.JWKS == nil && d.JWKSURI == "" {
		return errors.New("private_key_jwt requires jwks or jwks_uri")
	}
	return nil
}

// CIMDClient is the standard Fosite projection of a Client ID Metadata Document.
type CIMDClient struct {
	*DefaultOpenIDConnectClient
	Document *ClientMetadataDocument

	jwksFetcher JWKSFetcherStrategy
	validateURL func(context.Context, string) error
}

// CIMDJWKSResolver resolves keys referenced by a metadata client through its guarded fetcher.
type CIMDJWKSResolver interface {
	ResolveCIMDJSONWebKeys(context.Context, bool) (*jose.JSONWebKeySet, error)
}

// NewCIMDClient projects protocol-defined client metadata into Fosite's standard client interfaces.
//
// Authorization-server policy may wrap or transform the returned client to
// restrict grants, scopes, audiences, or other locally controlled behavior.
func NewCIMDClient(doc *ClientMetadataDocument) (*CIMDClient, error) {
	if doc == nil {
		return nil, errors.New("client metadata document is required")
	}
	if err := doc.Validate(doc.ClientID); err != nil {
		return nil, err
	}

	authMethod := doc.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "none"
	}

	return &CIMDClient{
		DefaultOpenIDConnectClient: &DefaultOpenIDConnectClient{
			DefaultClient: &DefaultClient{
				ID:            doc.ClientID,
				RedirectURIs:  append([]string(nil), doc.RedirectURIs...),
				GrantTypes:    append([]string(nil), doc.GrantTypes...),
				ResponseTypes: append([]string(nil), doc.ResponseTypes...),
				Scopes:        strings.Fields(doc.Scope),
				Public:        authMethod == "none",
			},
			JSONWebKeysURI:                    doc.JWKSURI,
			JSONWebKeys:                       doc.JWKS,
			TokenEndpointAuthMethod:           authMethod,
			RequestURIs:                       append([]string(nil), doc.RequestURIs...),
			RequestObjectSigningAlgorithm:     doc.RequestObjectSigningAlgorithm,
			TokenEndpointAuthSigningAlgorithm: doc.TokenEndpointAuthSigningAlg,
		},
		Document: doc,
	}, nil
}

// GetClientMetadataDocument returns the metadata used to materialize the client.
func (c *CIMDClient) GetClientMetadataDocument() *ClientMetadataDocument {
	return c.Document
}

// ResolveCIMDJSONWebKeys resolves the client's remote keys through the SSRF-guarded CIMD transport.
func (c *CIMDClient) ResolveCIMDJSONWebKeys(ctx context.Context, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	if c.JSONWebKeysURI == "" {
		return nil, errors.New("CIMD client has no jwks_uri")
	}
	if c.jwksFetcher == nil || c.validateURL == nil {
		return nil, errors.New("CIMD client has no secure jwks_uri fetcher")
	}
	if err := c.validateURL(ctx, c.JSONWebKeysURI); err != nil {
		return nil, fmt.Errorf("jwks_uri is not safe to fetch: %w", err)
	}
	return c.jwksFetcher.Resolve(ctx, c.JSONWebKeysURI, ignoreCache)
}

func (c *CIMDClient) configureSecureHTTPClient(provider CIMDSecureHTTPClientProvider) error {
	if c.JSONWebKeysURI == "" {
		return nil
	}
	if c.jwksFetcher != nil && c.validateURL != nil {
		return nil
	}
	if provider == nil {
		return errors.New("CIMD client with jwks_uri requires a secure HTTP client")
	}
	httpClient := provider.CIMDHTTPClient()
	if httpClient == nil {
		return errors.New("CIMD secure HTTP client is nil")
	}
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient = httpClient
	retryClient.Logger = nil
	c.jwksFetcher = NewDefaultJWKSFetcherStrategy(JWKSFetcherWithHTTPClient(retryClient))
	c.validateURL = provider.ValidateFetchURL
	return nil
}
