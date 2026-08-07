// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Active-content schemes must be rejected regardless of any allowlist, because a
// redirect to one of them executes script or exposes local content rather than
// returning the user to a real callback.
func TestIsActiveContentRedirectURI(t *testing.T) {
	rejected := []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)", // scheme comparison is case-insensitive
		"javascript://example.com/%0Aalert(1)",
		"data:text/html,<script>alert(1)</script>",
		"data://example.com/text/html,x",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"blob:https://example.com/uuid",
		"about:blank",
		"filesystem:https://example.com/temporary/x",
	}
	for _, raw := range rejected {
		u, err := url.Parse(raw)
		require.NoError(t, err, "parsing %q", raw)
		assert.True(t, IsActiveContentRedirectURI(u), "%q must be treated as active content", raw)
	}

	// Legitimate redirect targets, including the private-use schemes native apps
	// rely on under RFC 8252, must not be caught by this check.
	allowed := []string{
		"https://example.com/callback",
		"http://127.0.0.1:8080/callback",
		"com.example.app:/oauth2redirect",
		"myapp://callback",
	}
	for _, raw := range allowed {
		u, err := url.Parse(raw)
		require.NoError(t, err, "parsing %q", raw)
		assert.False(t, IsActiveContentRedirectURI(u), "%q must be allowed", raw)
	}

	assert.False(t, IsActiveContentRedirectURI(nil), "a nil URI is not active content")
}
