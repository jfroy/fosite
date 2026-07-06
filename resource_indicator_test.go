// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetResourceIndicator(t *testing.T) {
	resource, err := GetResourceIndicator(url.Values{})
	require.NoError(t, err)
	assert.Empty(t, resource)

	resource, err = GetResourceIndicator(url.Values{"resource": {"https://api.example.com"}})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", resource)

	resource, err = GetResourceIndicator(url.Values{"audience": {"https://api.example.com"}})
	require.NoError(t, err)
	assert.Empty(t, resource)

	resource, err = GetResourceIndicator(url.Values{
		"resource": {"https://api.example.com"},
		"audience": {"https://other.example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", resource)

	_, err = GetResourceIndicator(url.Values{"resource": {"https://api.example.com", "https://other.example.com"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTarget))

	resource, err = GetResourceIndicator(url.Values{"audience": {"https://api.example.com", "https://other.example.com"}})
	require.NoError(t, err)
	assert.Empty(t, resource)
}

func TestValidateResourceIndicator(t *testing.T) {
	resource, err := ValidateResourceIndicator(url.Values{"resource": {"https://api.example.com"}})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", resource)

	resource, err = ValidateResourceIndicator(url.Values{"audience": {"https://api.example.com https://other.example.com"}})
	require.NoError(t, err)
	assert.Empty(t, resource)

	_, err = ValidateResourceIndicator(url.Values{"resource": {"https://api.example.com#fragment"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTarget))

	_, err = ValidateResourceIndicator(url.Values{"resource": {"https://api.example.com", "https://other.example.com"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTarget))
}

func TestIsValidResourceIndicatorURI(t *testing.T) {
	for _, raw := range []string{
		"https://api.example.com",
		"urn:example:resource",
	} {
		assert.True(t, IsValidResourceIndicatorURI(raw), raw)
	}

	for _, raw := range []string{
		"",
		"/relative",
		"https://api.example.com#fragment",
		"https://api.example.com/with space",
	} {
		assert.False(t, IsValidResourceIndicatorURI(raw), raw)
	}
}

func TestIsValidScopeToken(t *testing.T) {
	for _, scope := range []string{"read", "read:orders", "urn:example:scope"} {
		assert.True(t, IsValidScopeToken(scope), scope)
	}

	for _, scope := range []string{"", "read orders", `read"orders`, `read\\orders`} {
		assert.False(t, IsValidScopeToken(scope), scope)
	}
}
