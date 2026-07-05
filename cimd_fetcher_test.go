// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cimdMockRoundTripper serves canned responses keyed by request URL.
type cimdMockRoundTripper struct {
	responses map[string]*http.Response
}

func (m *cimdMockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if resp, ok := m.responses[req.URL.String()]; ok {
		return resp, nil
	}
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("not found")), Header: make(http.Header)}, nil
}

func cimdMockResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func newTestFetcher(responses map[string]*http.Response) *DefaultCIMDFetcher {
	return NewDefaultCIMDFetcher(
		WithCIMDTransport(&cimdMockRoundTripper{responses: responses}),
	)
}

func TestDefaultCIMDFetcher_Fetch(t *testing.T) {
	const id = "https://8.8.8.8/oauth/client"
	body := `{"client_id":"https://8.8.8.8/oauth/client","client_name":"App","redirect_uris":["https://app/cb"],"token_endpoint_auth_method":"none"}`

	t.Run("fetches and parses", func(t *testing.T) {
		resp := cimdMockResponse(http.StatusOK, body)
		resp.Header.Set("Cache-Control", "max-age=600")
		f := newTestFetcher(map[string]*http.Response{id: resp})
		doc, ttl, err := f.Fetch(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, id, doc.ClientID)
		assert.Equal(t, "App", doc.ClientName)
		assert.Equal(t, 10*time.Minute, ttl)
	})

	t.Run("non-200 is an error", func(t *testing.T) {
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusNotFound, "nope")})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})

	t.Run("oversize body is rejected", func(t *testing.T) {
		big := `{"client_id":"https://8.8.8.8/oauth/client","padding":"` + strings.Repeat("a", 6*1024) + `"}`
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusOK, big)})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})

	t.Run("non-JSON body is rejected", func(t *testing.T) {
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusOK, "<html>not json</html>")})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})

	t.Run("redirects are not followed", func(t *testing.T) {
		redir := cimdMockResponse(http.StatusFound, "")
		redir.Header.Set("Location", "https://8.8.8.8/elsewhere")
		f := newTestFetcher(map[string]*http.Response{id: redir})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})

	t.Run("client_id mismatch is rejected", func(t *testing.T) {
		mismatch := `{"client_id":"https://evil.example.com/c","token_endpoint_auth_method":"none"}`
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusOK, mismatch)})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})

	t.Run("invalid client_id URL is rejected before fetching", func(t *testing.T) {
		f := newTestFetcher(nil)
		_, _, err := f.Fetch(t.Context(), "https://app.example.com")
		require.Error(t, err)
	})

	t.Run("private url is rejected", func(t *testing.T) {
		f := NewDefaultCIMDFetcher()
		_, _, err := f.Fetch(t.Context(), "https://127.0.0.1/oauth/client")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private IP addresses are not allowed")
	})
}

func TestDefaultCIMDFetcher_ParseCacheTTL(t *testing.T) {
	f := NewDefaultCIMDFetcher()
	assert.Equal(t, DefaultCIMDCacheTTL, f.parseCacheTTL(""))
	assert.Equal(t, DefaultCIMDCacheTTL, f.parseCacheTTL("no-store"))
	assert.Equal(t, 10*time.Minute, f.parseCacheTTL("max-age=600"))
	assert.Equal(t, DefaultCIMDMinCacheTTL, f.parseCacheTTL("max-age=1"))
	assert.Equal(t, DefaultCIMDMaxCacheTTL, f.parseCacheTTL("max-age=999999"))
	assert.Equal(t, 10*time.Minute, f.parseCacheTTL("public, max-age=600"))
}

func TestDefaultCIMDFetcher_IsPrivateIP(t *testing.T) {
	f := NewDefaultCIMDFetcher(
		WithCIMDExtraPrivateRanges([]*net.IPNet{
			{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(8, 128)},
		}),
	)
	private := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::1", "0.0.0.0"}
	for _, s := range private {
		assert.Truef(t, f.isPrivateIP(net.ParseIP(s)), "expected %s private", s)
	}
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, s := range public {
		assert.Falsef(t, f.isPrivateIP(net.ParseIP(s)), "expected %s public", s)
	}
}

func TestDefaultCIMDFetcher_AllowPrivateIPs(t *testing.T) {
	const id = "https://127.0.0.1/oauth/client"
	body := `{"client_id":"https://127.0.0.1/oauth/client","token_endpoint_auth_method":"none"}`
	f := NewDefaultCIMDFetcher(
		WithCIMDTransport(&cimdMockRoundTripper{responses: map[string]*http.Response{id: cimdMockResponse(http.StatusOK, body)}}),
		WithCIMDAllowPrivateIPs(true),
	)
	doc, _, err := f.Fetch(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, id, doc.ClientID)
}
