// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"net/url"
	"testing"

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
	}
	for _, in := range valid {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.NoErrorf(t, ValidateCIMDURL(u), "input %q", in)
	}

	invalid := []string{
		"http://app.example.com/oauth/client",
		"https://app.example.com",
		"https://app.example.com/",
		"https://app.example.com/a/../b",
		"https://app.example.com/./a",
		"https://app.example.com/oauth#frag",
		"https://user:pass@app.example.com/oauth",
		"https://app.example.com/oauth?foo=bar",
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
}
