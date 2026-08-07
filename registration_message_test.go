// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientRegistrationRequestIsPublicClient(t *testing.T) {
	assert.True(t, ClientRegistrationRequest{TokenEndpointAuthMethod: "none"}.IsPublicClient())
	assert.False(t, ClientRegistrationRequest{TokenEndpointAuthMethod: "client_secret_basic"}.IsPublicClient())
	// An omitted method defaults to client_secret_basic per RFC 7591 section 2.
	assert.False(t, ClientRegistrationRequest{}.IsPublicClient())
}

// The response must serialise to the member names RFC 7591 section 3.2.1 defines,
// since clients parse it by name.
func TestClientRegistrationResponseWireFormat(t *testing.T) {
	resp := ClientRegistrationResponse{
		ClientRegistrationRequest: ClientRegistrationRequest{
			RedirectURIs:            []string{"https://example.com/cb"},
			ClientName:              "Example",
			TokenEndpointAuthMethod: "client_secret_basic",
		},
		ClientID:                "client-1",
		ClientSecret:            "secret",
		ClientIDIssuedAt:        1700000000,
		ClientSecretExpiresAt:   NeverExpires(),
		RegistrationAccessToken: "rat",
		RegistrationClientURI:   "https://as.example.com/register/client-1",
	}

	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))

	// The embedded request metadata is flattened into the same object.
	assert.Equal(t, "Example", out["client_name"])
	assert.Equal(t, []any{"https://example.com/cb"}, out["redirect_uris"])

	assert.Equal(t, "client-1", out["client_id"])
	assert.Equal(t, "secret", out["client_secret"])
	assert.Equal(t, float64(1700000000), out["client_id_issued_at"])
	// RFC 7591 section 3.2.1 requires client_secret_expires_at whenever a secret is
	// issued, and 0 (never expires) is exactly the value a naive omitempty drops.
	require.Contains(t, out, "client_secret_expires_at")
	assert.Equal(t, float64(0), out["client_secret_expires_at"])
	assert.Equal(t, "rat", out["registration_access_token"])
	assert.Equal(t, "https://as.example.com/register/client-1", out["registration_client_uri"])
}

// A public client is issued no secret, so the secret members must be omitted
// rather than serialised as empty values.
func TestClientRegistrationResponseOmitsUnsetMembers(t *testing.T) {
	resp := ClientRegistrationResponse{
		ClientRegistrationRequest: ClientRegistrationRequest{
			RedirectURIs:            []string{"https://example.com/cb"},
			TokenEndpointAuthMethod: "none",
		},
		ClientID: "client-1",
	}

	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))

	assert.NotContains(t, out, "client_secret")
	assert.NotContains(t, out, "registration_access_token")
	assert.NotContains(t, out, "client_id_issued_at")
	assert.Contains(t, out, "client_id")
	assert.Contains(t, out, "redirect_uris")
}
