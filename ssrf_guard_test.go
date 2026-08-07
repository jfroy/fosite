// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSpecialUseIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // IPv6 loopback
		"10.0.0.5",        // RFC 1918
		"192.168.1.1",     // RFC 1918
		"172.16.0.1",      // RFC 1918
		"169.254.169.254", // link-local / cloud metadata
		"0.0.0.0",         // unspecified
	}
	for _, raw := range blocked {
		assert.True(t, IsSpecialUseIP(net.ParseIP(raw)), "%s must be special-use", raw)
	}

	for _, raw := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		assert.False(t, IsSpecialUseIP(net.ParseIP(raw)), "%s must be routable", raw)
	}

	assert.True(t, IsSpecialUseIP(nil), "a nil IP must fail closed")
}

func TestSSRFGuardedTransport(t *testing.T) {
	t.Run("blocks a reachable loopback destination", func(t *testing.T) {
		internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer internal.Close()

		client := &http.Client{Transport: SSRFGuardedTransport(http.DefaultTransport, nil)}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, internal.URL, http.NoBody)
		require.NoError(t, err)

		//nolint:bodyclose
		_, err = client.Do(req)
		require.Error(t, err, "a loopback destination must be refused")
		assert.ErrorIs(t, err, ErrSpecialUseAddressBlocked)
	})

	// A proxy is the most important bypass to close: with one configured the
	// dialer only ever sees the proxy's address, so the guard would inspect the
	// proxy while the proxy fetches the internal target on the caller's behalf.
	t.Run("clears the bypass vectors on the base transport", func(t *testing.T) {
		proxyURL, err := url.Parse("http://proxy.example.com:3128")
		require.NoError(t, err)

		base := http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = http.ProxyURL(proxyURL)
		base.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, nil
		}

		guarded, ok := SSRFGuardedTransport(base, nil).(*http.Transport)
		require.True(t, ok)

		assert.Nil(t, guarded.Proxy, "a proxy would hide the real destination from the guard")
		assert.Nil(t, guarded.DialTLS, "DialTLS bypasses DialContext")
		assert.Nil(t, guarded.DialTLSContext, "DialTLSContext bypasses DialContext")
		require.NotNil(t, guarded.DialContext)

		// The caller's transport must not be mutated.
		assert.NotNil(t, base.Proxy)
	})

	t.Run("honours a custom special-use checker", func(t *testing.T) {
		// Treat everything as special-use, so even a public address is refused.
		guarded := SSRFGuardedTransport(http.DefaultTransport, func(net.IP) bool { return true })
		tr, ok := guarded.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, tr.DialContext)
	})

	t.Run("fails closed for a round tripper it cannot introspect", func(t *testing.T) {
		// A wrapper hides the transport that actually dials, so returning it
		// unchanged would hand back something that looks guarded but is not.
		custom := &stubRoundTripper{}
		guarded := SSRFGuardedTransport(custom, nil)
		assert.NotSame(t, http.RoundTripper(custom), guarded)
		tr, ok := guarded.(*http.Transport)
		require.True(t, ok, "an unguardable base must be replaced by a guarded transport")
		require.NotNil(t, tr.DialContext)
	})

	t.Run("blocks loopback through a wrapped transport", func(t *testing.T) {
		// The production shape: the base has already been wrapped for
		// instrumentation before the guard is applied.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &http.Client{Transport: SSRFGuardedTransport(&stubRoundTripper{}, nil)}
		_, err := client.Get(server.URL)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSpecialUseAddressBlocked)
	})
}

type stubRoundTripper struct{}

func (*stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

// TestSSRFGuardedTransportExemption covers the explicit opt-out used by in-memory
// test doubles, which never dial and so have nothing to guard.
func TestSSRFGuardedTransportExemption(t *testing.T) {
	exempt := &exemptRoundTripper{}
	assert.Same(t, http.RoundTripper(exempt), SSRFGuardedTransport(exempt, nil),
		"a round tripper that declares itself exempt must be left alone")
}

type exemptRoundTripper struct{}

func (*exemptRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (*exemptRoundTripper) SSRFGuardExempt()                                {}
