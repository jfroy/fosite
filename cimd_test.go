// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLooksLikeCIMDURL(t *testing.T) {
	cases := map[string]bool{
		"https://app.example.com/oauth/client": true,
		"https://app.example.com/c":            true,
		"my-app":                               false,
		"client-1234":                          false,
		"http://app.example.com/oauth/client":  false,
		"":                                     false,
	}
	for in, want := range cases {
		assert.Equalf(t, want, LooksLikeCIMDURL(in), "input %q", in)
	}
}

func TestValidateCIMDURL(t *testing.T) {
	valid := []string{
		"https://app.example.com/oauth/client",
		"https://app.example.com:8443/oauth/client",
		"https://app.example.com/",
		"https://app.example.com/oauth?foo=bar",
	}
	for _, in := range valid {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.NoErrorf(t, ValidateCIMDURL(u), "input %q", in)
	}

	invalid := []string{
		"http://app.example.com/oauth/client",
		"https://app.example.com",
		"https://app.example.com/a/../b",
		"https://app.example.com/./a",
		"https://app.example.com/oauth#frag",
		"https://user:pass@app.example.com/oauth",
	}
	for _, in := range invalid {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.Errorf(t, ValidateCIMDURL(u), "input %q", in)
	}
}

func TestClientMetadataDocument_Validate(t *testing.T) {
	const id = "https://app.example.com/oauth/client"

	t.Run("matching client_id passes", func(t *testing.T) {
		doc := &ClientMetadataDocument{ClientID: id}
		require.NoError(t, doc.Validate(id))
	})

	t.Run("client_id mismatch is rejected", func(t *testing.T) {
		doc := &ClientMetadataDocument{ClientID: "https://evil.example.com/c"}
		require.Error(t, doc.Validate(id))
	})

	t.Run("client secret is rejected", func(t *testing.T) {
		secret := "shh"
		doc := &ClientMetadataDocument{ClientID: id, ClientSecret: &secret}
		require.Error(t, doc.Validate(id))

		exp := int64(0)
		doc2 := &ClientMetadataDocument{ClientID: id, ClientSecretExpiresAt: &exp}
		require.Error(t, doc2.Validate(id))
	})

	t.Run("symmetric authentication is rejected", func(t *testing.T) {
		for _, method := range []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"} {
			doc := &ClientMetadataDocument{ClientID: id, TokenEndpointAuthMethod: method}
			require.Error(t, doc.Validate(id))
		}
	})

	t.Run("private key material is rejected", func(t *testing.T) {
		doc := &ClientMetadataDocument{
			ClientID: id,
			JWKS: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: []byte("symmetric-secret"),
			}}},
		}
		require.Error(t, doc.Validate(id))
	})

	t.Run("private key authentication requires keys", func(t *testing.T) {
		doc := &ClientMetadataDocument{ClientID: id, TokenEndpointAuthMethod: "private_key_jwt"}
		require.Error(t, doc.Validate(id))
	})
}

func TestClientMetadataDocument_UnmarshalJSON(t *testing.T) {
	var doc ClientMetadataDocument
	require.NoError(t, json.Unmarshal([]byte(`{
		"client_id":"https://app.example.com/oauth/client",
		"client_name":"Example",
		"custom_metadata":{"enabled":true}
	}`), &doc))

	assert.Equal(t, "Example", doc.ClientName)
	assert.JSONEq(t, `{"enabled":true}`, string(doc.AdditionalMetadata["custom_metadata"]))
}

func TestNewCIMDClient(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	doc := &ClientMetadataDocument{
		ClientID:                      id,
		RedirectURIs:                  []string{"https://app.example.com/callback"},
		GrantTypes:                    []string{"authorization_code"},
		ResponseTypes:                 []string{"code"},
		Scope:                         "openid profile",
		TokenEndpointAuthMethod:       "private_key_jwt",
		TokenEndpointAuthSigningAlg:   "ES256",
		JWKSURI:                       "https://app.example.com/jwks.json",
		RequestURIs:                   []string{"https://app.example.com/request.jwt"},
		RequestObjectSigningAlgorithm: "ES256",
	}

	client, err := NewCIMDClient(doc)
	require.NoError(t, err)
	assert.Equal(t, id, client.GetID())
	assert.Equal(t, []string{"https://app.example.com/callback"}, client.GetRedirectURIs())
	assert.Equal(t, Arguments{"authorization_code"}, client.GetGrantTypes())
	assert.Equal(t, Arguments{"code"}, client.GetResponseTypes())
	assert.Equal(t, Arguments{"openid", "profile"}, client.GetScopes())
	assert.Equal(t, "private_key_jwt", client.GetTokenEndpointAuthMethod())
	assert.Equal(t, "ES256", client.GetTokenEndpointAuthSigningAlgorithm())
	assert.Equal(t, "https://app.example.com/jwks.json", client.GetJSONWebKeysURI())
	assert.False(t, client.IsPublic())
	assert.Same(t, doc, client.GetClientMetadataDocument())
}
