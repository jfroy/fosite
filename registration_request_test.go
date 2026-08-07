// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRegistrationRedirectURIs(t *testing.T) {
	t.Run("requires at least one redirect_uri", func(t *testing.T) {
		require.Error(t, ValidateRegistrationRedirectURIs(nil))
		require.Error(t, ValidateRegistrationRedirectURIs([]string{}))
	})

	t.Run("rejects active-content schemes", func(t *testing.T) {
		for _, uri := range []string{
			"javascript:alert(1)",
			"JavaScript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
			"vbscript:msgbox(1)",
			"file:///etc/passwd",
			"blob:https://example.com/uuid",
			"about:blank",
		} {
			assert.Error(t, ValidateRegistrationRedirectURIs([]string{uri}), "must reject %q", uri)
		}
	})

	t.Run("rejects relative URIs", func(t *testing.T) {
		require.Error(t, ValidateRegistrationRedirectURIs([]string{"/relative/callback"}))
		require.Error(t, ValidateRegistrationRedirectURIs([]string{"//example.com/callback"}))
	})

	t.Run("rejects a fragment component", func(t *testing.T) {
		require.Error(t, ValidateRegistrationRedirectURIs([]string{"https://example.com/cb#frag"}))
	})

	t.Run("accepts legitimate redirect URIs", func(t *testing.T) {
		require.NoError(t, ValidateRegistrationRedirectURIs([]string{
			"https://example.com/callback",
			"http://127.0.0.1:8080/callback",
			// RFC 8252 private-use scheme for native apps
			"com.example.app:/oauth2redirect",
		}))
	})

	t.Run("rejects when any one of several URIs is invalid", func(t *testing.T) {
		require.Error(t, ValidateRegistrationRedirectURIs([]string{
			"https://example.com/callback",
			"javascript:alert(1)",
		}))
	})

	t.Run("returns an RFC 7591 invalid_redirect_uri error", func(t *testing.T) {
		err := ValidateRegistrationRedirectURIs([]string{"javascript:alert(1)"})
		require.Error(t, err)
		rfcErr := ErrorToRFC6749Error(err)
		assert.Equal(t, "invalid_redirect_uri", rfcErr.ErrorField)
	})
}
