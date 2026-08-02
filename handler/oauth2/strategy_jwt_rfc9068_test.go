// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

func TestRFC9068JWTStrategyGeneratesCompliantAccessToken(t *testing.T) {
	strategy, request, _ := newRFC9068JWTStrategyTestCase()
	request.Session.(*JWTSession).JWTClaims.Extra["client_id"] = "spoofed-client"

	token, signature, err := strategy.GenerateAccessToken(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, strategy.signature(token), signature)

	header := decodeRFC9068JWTPart(t, token, 0)
	claims := decodeRFC9068JWTPart(t, token, 1)

	require.Equal(t, RFC9068JWTType, header["typ"])
	require.Equal(t, "RS256", header["alg"])
	require.Equal(t, "https://issuer.example.com", claims["iss"])
	require.Equal(t, "peter", claims["sub"])
	require.Equal(t, "client-id", claims["client_id"])
	require.ElementsMatch(t, []interface{}{"group0"}, claims["aud"])
	require.Equal(t, "email offline", claims["scope"])
	require.NotEmpty(t, claims["jti"])
	require.NotZero(t, claims["iat"])
	require.NotZero(t, claims["exp"])
	require.NotContains(t, claims, "azp")
}

func TestRFC9068JWTStrategyRejectsIncompleteAccessTokens(t *testing.T) {
	tests := map[string]struct {
		configure func(*fosite.Config, *fosite.Request)
		error     string
	}{
		"issuer": {
			configure: func(config *fosite.Config, _ *fosite.Request) {
				config.AccessTokenIssuer = ""
			},
			error: "without an issuer",
		},
		"subject": {
			configure: func(_ *fosite.Config, request *fosite.Request) {
				request.Session.(*JWTSession).JWTClaims.Subject = ""
			},
			error: "without a subject",
		},
		"audience": {
			configure: func(_ *fosite.Config, request *fosite.Request) {
				request.GrantedAudience = nil
			},
			error: "without an audience",
		},
		"expiration": {
			configure: func(_ *fosite.Config, request *fosite.Request) {
				delete(request.Session.(*JWTSession).ExpiresAt, fosite.AccessToken)
			},
			error: "without an expiration",
		},
		"client ID": {
			configure: func(_ *fosite.Config, request *fosite.Request) {
				request.Client.(*fosite.DefaultClient).ID = ""
			},
			error: "without a client ID",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			strategy, request, config := newRFC9068JWTStrategyTestCase()
			test.configure(config, request)

			_, _, err := strategy.GenerateAccessToken(t.Context(), request)
			require.ErrorContains(t, err, test.error)
		})
	}
}

func TestDefaultJWTStrategyDoesNotDeclareRFC9068Conformance(t *testing.T) {
	strategy, request, _ := newRFC9068JWTStrategyTestCase()

	token, _, err := strategy.DefaultJWTStrategy.GenerateAccessToken(t.Context(), request)
	require.NoError(t, err)

	header := decodeRFC9068JWTPart(t, token, 0)
	claims := decodeRFC9068JWTPart(t, token, 1)
	require.Equal(t, "JWT", header["typ"])
	require.NotContains(t, claims, "client_id")
}

func newRFC9068JWTStrategyTestCase() (*RFC9068JWTStrategy, *fosite.Request, *fosite.Config) {
	config := &fosite.Config{
		AccessTokenIssuer: "https://issuer.example.com",
		JWTScopeClaimKey:  jwt.JWTScopeFieldList,
	}
	strategy := &RFC9068JWTStrategy{
		DefaultJWTStrategy: &DefaultJWTStrategy{
			Signer: &jwt.DefaultSigner{
				GetPrivateKey: func(context.Context) (interface{}, error) {
					return rsaKey, nil
				},
			},
			HMACSHAStrategy: hmacshaStrategy,
			Config:          config,
		},
	}
	request := jwtValidCase(fosite.AccessToken)
	request.Client.(*fosite.DefaultClient).ID = "client-id"
	request.Session.(*JWTSession).JWTClaims.Issuer = ""

	return strategy, request, config
}

func decodeRFC9068JWTPart(t *testing.T, token string, part int) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[part])
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}
