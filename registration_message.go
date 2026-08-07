// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

// ClientRegistrationRequest is the client metadata an OAuth client sends to the
// registration endpoint, as defined by OpenID Connect Dynamic Client Registration
// and RFC 7591 section 2. It is also the request body for an RFC 7592 update.
type ClientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
}

// IsPublicClient reports whether the request asks for a public client, i.e. one
// that cannot hold a secret and authenticates with no credential at the token
// endpoint. Per RFC 7591 section 2 this is expressed as
// token_endpoint_auth_method "none".
func (r ClientRegistrationRequest) IsPublicClient() bool {
	return r.TokenEndpointAuthMethod == "none"
}

// ClientRegistrationResponse is the client information response returned by the
// registration endpoint (RFC 7591 section 3.2.1) and by the client configuration
// endpoint (RFC 7592 section 3).
//
// Per RFC 7591 section 3.2.1, client_id is required and client_id_issued_at is
// optional; client_secret_expires_at is required whenever a client_secret is
// issued, where 0 means the secret never expires. The registration access token
// and client URI are only returned when the server supports RFC 7592.
type ClientRegistrationResponse struct {
	ClientRegistrationRequest

	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret,omitempty"`
	ClientIDIssuedAt int64  `json:"client_id_issued_at,omitempty"`

	// ClientSecretExpiresAt is a pointer because 0 is the meaningful value "this
	// secret never expires". With omitempty on a plain int64 that value would be
	// dropped from the response, which is precisely the case RFC 7591 requires to
	// be present. Left nil for a public client, where no secret was issued and the
	// field must be absent.
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`

	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// NeverExpires is the client_secret_expires_at value meaning the issued secret
// does not expire (RFC 7591 section 3.2.1).
func NeverExpires() *int64 {
	never := int64(0)
	return &never
}
