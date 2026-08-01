// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite/token/jwt"
)

func mustGenerateAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.RS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateHSAssertion(t *testing.T, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jose.HS256, claims)
	tokenString, err := token.SignedString([]byte("aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"))
	require.NoError(t, err)
	return tokenString
}

func mustGenerateNoneAssertion(t *testing.T, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tokenString
}

type stubCIMDSecureRequestURIClient struct {
	*DefaultOpenIDConnectClient
	body string
}

func (c *stubCIMDSecureRequestURIClient) FetchCIMDReferencedURL(context.Context, string) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     make(http.Header),
	}, nil
}

func TestAuthorizeRequestParametersFromOpenIDConnectRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &key.PublicKey,
			},
		},
	}

	validRequestObject := mustGenerateAssertion(t, jwt.MapClaims{"scope": "foo", "foo": "bar", "baz": "baz", "response_type": "token", "response_mode": "post_form"}, key, "kid-foo")
	validRequestObjectWithoutKid := mustGenerateAssertion(t, jwt.MapClaims{"scope": "foo", "foo": "bar", "baz": "baz"}, key, "")
	validNoneRequestObject := mustGenerateNoneAssertion(t, jwt.MapClaims{"scope": "foo", "foo": "bar", "baz": "baz", "state": "some-state"})
	signedRequestObjectWithClientID := mustGenerateAssertion(t, jwt.MapClaims{"scope": "foo", "client_id": "foo"}, key, "kid-foo")
	noneRequestObjectWithWrongClientID := mustGenerateNoneAssertion(t, jwt.MapClaims{"scope": "foo", "client_id": "not-foo"})
	noneRequestObjectWithTypedClaims := mustGenerateNoneAssertion(t, jwt.MapClaims{
		"scope":   "foo",
		"max_age": 3600,
		"foo":     true,
		"claims":  map[string]interface{}{"userinfo": map[string]interface{}{"email": nil}},
	})
	noneRequestObjectWithNestedRequest := mustGenerateNoneAssertion(t, jwt.MapClaims{"scope": "foo", "request": "nested", "request_uri": "https://foo.bar/nested"})
	expiredNoneRequestObject := mustGenerateNoneAssertion(t, jwt.MapClaims{"scope": "foo", "exp": time.Now().Add(-time.Hour).Unix()})
	noneRequestObjectWithNumericClientID := mustGenerateNoneAssertion(t, jwt.MapClaims{"scope": "foo", "client_id": 12345})

	var reqH http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(validRequestObject))
	}
	reqTS := httptest.NewServer(reqH)
	defer reqTS.Close()
	hugeReqTS := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte(strings.Repeat("a", DefaultCIMDReferencedURLMaxSize+1)))
	}))
	defer hugeReqTS.Close()

	var hJWK http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(rw).Encode(jwks))
	}
	reqJWK := httptest.NewServer(hJWK)
	defer reqJWK.Close()

	f := &Fosite{Config: &Config{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy()}}
	for k, tc := range []struct {
		client Client
		form   url.Values
		d      string
		algs   []string

		expectErr       error
		expectErrReason string
		expectForm      url.Values
	}{
		{
			d:          "should pass because no request context given and not openid",
			form:       url.Values{},
			expectErr:  nil,
			expectForm: url.Values{},
		},
		{
			d:          "should pass because no request context given",
			form:       url.Values{"scope": {"openid"}},
			expectErr:  nil,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should pass because request context given but not openid",
			form:       url.Values{"request": {"foo"}},
			expectErr:  nil,
			expectForm: url.Values{"request": {"foo"}},
		},
		{
			d:          "should fail because the request object is malformed even though the client is not an OpenIDConnect compliant client",
			form:       url.Values{"scope": {"openid"}, "request": {"foo"}},
			expectErr:  ErrInvalidRequestObject,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because not an OpenIDConnect compliant client",
			form:       url.Values{"scope": {"openid"}, "request_uri": {"foo"}},
			expectErr:  ErrRequestURINotSupported,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because request uri is not whitelisted and no key set",
			form:       url.Values{"scope": {"openid"}, "request_uri": {"foo"}},
			client:     &DefaultOpenIDConnectClient{RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequestURI,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because the request object is signed but the client is not an OpenIDConnect compliant client",
			form:            url.Values{"scope": {"openid"}, "request": {validRequestObject}},
			client:          &DefaultClient{ID: "foo"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object is signed with algorithm 'RS256', but the OAuth 2.0 Client does not implement advanced OpenID Connect capabilities needed to verify signed request objects.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because the request object is signed but the client has no JSON Web Keys registered",
			form:            url.Values{"scope": {"openid"}, "request": {validRequestObject}},
			client:          &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object is signed with algorithm 'RS256', but the OAuth 2.0 Client does not have any JSON Web Keys registered.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because token invalid",
			form:       url.Values{"scope": {"openid"}, "request": {"foo"}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequestObject,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because kid does not exist",
			form:            url.Values{"scope": {"openid"}, "request": {mustGenerateAssertion(t, jwt.MapClaims{}, key, "does-not-exists")}},
			client:          &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "Unable to retrieve RSA signing key from OAuth 2.0 Client. The JSON Web Token uses signing key with kid 'does-not-exists', which could not be found.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because not RS256 token",
			form:            url.Values{"scope": {"openid"}, "request": {mustGenerateHSAssertion(t, jwt.MapClaims{})}},
			client:          &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object uses signing algorithm 'HS256', but the requested OAuth 2.0 Client enforces signing algorithm 'RS256'.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:      "should pass and set request parameters properly",
			form:   url.Values{"scope": {"openid"}, "response_type": {"code"}, "response_mode": {"none"}, "request": {validRequestObject}},
			client: &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			// The values from form are overwritten by the request object.
			expectForm: url.Values{"response_type": {"token"}, "response_mode": {"post_form"}, "scope": {"foo"}, "request": {validRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass even if kid is unset",
			form:       url.Values{"scope": {"openid"}, "request": {validRequestObjectWithoutKid}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectForm: url.Values{"scope": {"foo"}, "request": {validRequestObjectWithoutKid}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should fail because request uri is not whitelisted",
			form:       url.Values{"scope": {"openid"}, "request_uri": {reqTS.URL}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "RS256"},
			expectForm: url.Values{"scope": {"foo"}, "request_uri": {reqTS.URL}, "foo": {"bar"}, "baz": {"baz"}},
			expectErr:  ErrInvalidRequestURI,
		},
		{
			d:          "should pass and set request_uri parameters properly and also fetch jwk from remote",
			form:       url.Values{"scope": {"openid"}, "request_uri": {reqTS.URL}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "RS256", RequestURIs: []string{reqTS.URL}},
			expectForm: url.Values{"response_type": {"token"}, "response_mode": {"post_form"}, "scope": {"foo"}, "request_uri": {reqTS.URL}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:    "should reject an oversized CIMD request_uri response",
			form: url.Values{"scope": {"openid"}, "request_uri": {hugeReqTS.URL}},
			client: &stubCIMDSecureRequestURIClient{
				DefaultOpenIDConnectClient: &DefaultOpenIDConnectClient{RequestURIs: []string{hugeReqTS.URL}},
				body:                       strings.Repeat("a", DefaultCIMDReferencedURLMaxSize+1),
			},
			expectErr:  ErrInvalidRequestURI,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should not apply the CIMD size limit to another request_uri client",
			form:       url.Values{"scope": {"openid"}, "request_uri": {hugeReqTS.URL}},
			client:     &DefaultOpenIDConnectClient{RequestURIs: []string{hugeReqTS.URL}},
			expectErr:  ErrInvalidRequestObject,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should pass when request object uses algorithm none",
			form:       url.Values{"scope": {"openid"}, "request": {validNoneRequestObject}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "none"},
			expectForm: url.Values{"state": {"some-state"}, "scope": {"foo"}, "request": {validNoneRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass when request object uses algorithm none and the client did not explicitly allow any algorithm",
			form:       url.Values{"scope": {"openid"}, "request": {validNoneRequestObject}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL},
			expectForm: url.Values{"state": {"some-state"}, "scope": {"foo"}, "request": {validNoneRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass when request object uses algorithm none and the client is not an OpenIDConnect compliant client",
			form:       url.Values{"scope": {"openid"}, "request": {validNoneRequestObject}},
			client:     &DefaultClient{ID: "foo"},
			expectForm: url.Values{"state": {"some-state"}, "scope": {"foo"}, "request": {validNoneRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass when request object uses algorithm none and the server only supports none",
			form:       url.Values{"scope": {"openid"}, "request": {validNoneRequestObject}},
			client:     &DefaultClient{ID: "foo"},
			algs:       []string{"none"},
			expectForm: url.Values{"state": {"some-state"}, "scope": {"foo"}, "request": {validNoneRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:               "should fail because the request object algorithm is not supported by the server",
			form:            url.Values{"scope": {"openid"}, "request": {validRequestObject}},
			client:          &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}, JSONWebKeys: jwks},
			algs:            []string{"none"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object uses signing algorithm 'RS256', but the authorization server only supports [none].",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because the client_id claim does not match the client_id request parameter",
			form:            url.Values{"scope": {"openid"}, "request": {noneRequestObjectWithWrongClientID}},
			client:          &DefaultClient{ID: "foo"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object contains a 'client_id' claim that does not match the 'client_id' request parameter.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:          "should pass because the client_id claim matches the client_id request parameter",
			form:       url.Values{"scope": {"openid"}, "request": {signedRequestObjectWithClientID}},
			client:     &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}, JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectForm: url.Values{"client_id": {"foo"}, "scope": {"foo"}, "request": {signedRequestObjectWithClientID}},
		},
		{
			d:      "should map non-string claims to their request parameter representation",
			form:   url.Values{"scope": {"openid"}, "request": {noneRequestObjectWithTypedClaims}},
			client: &DefaultClient{ID: "foo"},
			expectForm: url.Values{
				"scope":   {"foo"},
				"request": {noneRequestObjectWithTypedClaims},
				"max_age": {"3600"},
				"foo":     {"true"},
				"claims":  {`{"userinfo":{"email":null}}`},
			},
		},
		{
			d:          "should ignore nested request and request_uri claims",
			form:       url.Values{"scope": {"openid"}, "request": {noneRequestObjectWithNestedRequest}},
			client:     &DefaultClient{ID: "foo"},
			expectForm: url.Values{"scope": {"foo"}, "request": {noneRequestObjectWithNestedRequest}},
		},
		{
			d:               "should fail because the request object is expired",
			form:            url.Values{"scope": {"openid"}, "request": {expiredNoneRequestObject}},
			client:          &DefaultClient{ID: "foo"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because the client_id claim is not a string",
			form:            url.Values{"scope": {"openid"}, "request": {noneRequestObjectWithNumericClientID}},
			client:          &DefaultClient{ID: "foo"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object contains a 'client_id' claim that does not match the 'client_id' request parameter.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because the server allowlist applies even when the client-registered algorithm matches",
			form:            url.Values{"scope": {"openid"}, "request": {validRequestObject}},
			client:          &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}, JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			algs:            []string{"none"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object uses signing algorithm 'RS256', but the authorization server only supports [none].",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because the client-registered algorithm applies even when the server allowlist matches",
			form:            url.Values{"scope": {"openid"}, "request": {validRequestObject}},
			client:          &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}, JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "none"},
			algs:            []string{"RS256", "none"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object uses signing algorithm 'RS256', but the requested OAuth 2.0 Client enforces signing algorithm 'none'.",
			expectForm:      url.Values{"scope": {"openid"}},
		},
		{
			d:               "should fail because the algorithm of the request object fetched from the request_uri is not supported by the server",
			form:            url.Values{"scope": {"openid"}, "request_uri": {reqTS.URL}},
			client:          &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}, JSONWebKeysURI: reqJWK.URL, RequestURIs: []string{reqTS.URL}},
			algs:            []string{"none"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object uses signing algorithm 'RS256', but the authorization server only supports [none].",
			expectForm:      url.Values{"scope": {"openid"}},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			req := &AuthorizeRequest{
				Request: Request{
					Client: tc.client,
					Form:   tc.form,
				},
			}

			provider := f
			if tc.algs != nil {
				provider = &Fosite{Config: &Config{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(), SupportedRequestObjectSigningAlgorithms: tc.algs}}
			}

			err := provider.authorizeRequestParametersFromOpenIDConnectRequest(context.Background(), req, false)
			if tc.expectErr != nil {
				require.EqualError(t, err, tc.expectErr.Error(), "%+v", err)
				if tc.expectErrReason != "" {
					real := new(RFC6749Error)
					require.True(t, errors.As(err, &real))
					assert.EqualValues(t, tc.expectErrReason, real.Reason())
				}
			} else {
				if err != nil {
					real := new(RFC6749Error)
					errors.As(err, &real)
					require.NoErrorf(t, err, "Hint: %v\nDebug:%v", real.HintField, real.DebugField)
				}
				require.NoErrorf(t, err, "%+v", err)
				require.Equal(t, len(tc.expectForm), len(req.Form))
				for k, v := range tc.expectForm {
					assert.EqualValues(t, v, req.Form[k])
				}
			}
		})
	}
}
