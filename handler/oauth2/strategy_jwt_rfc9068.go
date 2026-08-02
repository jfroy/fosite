// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

// RFC9068JWTType is the media type used to identify RFC 9068 access tokens in the JWT typ header
const RFC9068JWTType = "at+jwt"

// RFC9068JWTStrategy issues JWT access tokens conforming to RFC 9068
type RFC9068JWTStrategy struct {
	*DefaultJWTStrategy
}

var _ CoreStrategy = (*RFC9068JWTStrategy)(nil)

func (h *RFC9068JWTStrategy) GenerateAccessToken(ctx context.Context, requester fosite.Requester) (string, string, error) {
	// Derive the client identifier from the authenticated requester so custom session claims cannot spoof it
	if requester.GetClient() == nil || requester.GetClient().GetID() == "" {
		return "", "", errors.New("cannot issue an RFC 9068 access token without a client ID")
	}

	// Materialize Fosite's standard JWT claims before enforcing the RFC 9068 profile
	claims, header, err := h.prepareJWT(ctx, fosite.AccessToken, requester)
	if err != nil {
		return "", "", err
	}
	claims["client_id"] = requester.GetClient().GetID()

	// RFC 9068 recommends the OAuth scope claim whenever scopes were granted
	if len(requester.GetGrantedScopes()) > 0 {
		claims["scope"] = strings.Join(requester.GetGrantedScopes(), " ")
	}

	// Reject incomplete claim sets instead of emitting a token that declares RFC 9068 conformance
	if err := validateRFC9068Claims(claims); err != nil {
		return "", "", err
	}

	// Explicit typing prevents resource servers from confusing access tokens with other JWT types
	header.Add("typ", RFC9068JWTType)

	return h.Signer.Generate(ctx, claims, header)
}

func validateRFC9068Claims(claims jwt.MapClaims) error {
	requiredStringClaims := []struct {
		name        string
		description string
	}{
		{name: "iss", description: "an issuer"},
		{name: "sub", description: "a subject"},
		{name: "client_id", description: "a client ID"},
		{name: "jti", description: "a JWT ID"},
	}
	for _, claim := range requiredStringClaims {
		value, ok := claims[claim.name].(string)
		if !ok || value == "" {
			return errors.Errorf("cannot issue an RFC 9068 access token without %s", claim.description)
		}
	}

	if !hasRFC9068Audience(claims["aud"]) {
		return errors.New("cannot issue an RFC 9068 access token without an audience")
	}
	if !isRFC9068NumericDate(claims["exp"]) {
		return errors.New("cannot issue an RFC 9068 access token without an expiration")
	}
	if !isRFC9068NumericDate(claims["iat"]) {
		return errors.New("cannot issue an RFC 9068 access token without an issued-at time")
	}

	return nil
}

func hasRFC9068Audience(value interface{}) bool {
	switch audience := value.(type) {
	case string:
		return audience != ""
	case []string:
		if len(audience) == 0 {
			return false
		}
		for _, item := range audience {
			if item == "" {
				return false
			}
		}
		return true
	case []interface{}:
		if len(audience) == 0 {
			return false
		}
		for _, item := range audience {
			stringItem, ok := item.(string)
			if !ok || stringItem == "" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isRFC9068NumericDate(value interface{}) bool {
	switch value.(type) {
	case int64, float64, json.Number:
		return true
	default:
		return false
	}
}
