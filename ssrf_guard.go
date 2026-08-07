// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ErrSpecialUseAddressBlocked is returned when an outbound request would connect
// to a loopback, private, link-local, or otherwise special-use address.
var ErrSpecialUseAddressBlocked = errors.New("special-use IP addresses are not allowed")

// SpecialUseIPChecker reports whether an address must not be connected to.
type SpecialUseIPChecker func(ip net.IP) bool

// SSRFGuardExempt is implemented by an http.RoundTripper that never dials a
// network socket, such as an in-memory test double. SSRFGuardedTransport returns
// such a round tripper unchanged instead of failing closed.
//
// This is deliberately an opt-in marker rather than a type switch: a round
// tripper that does reach the network but is not an *http.Transport cannot be
// guarded, and silently returning it would produce something that looks guarded
// and is not. Implementing this interface is an explicit assertion that the round
// tripper resolves nothing and connects to nothing.
type SSRFGuardExempt interface {
	http.RoundTripper

	// SSRFGuardExempt asserts that this round tripper does not dial sockets.
	SSRFGuardExempt()
}

// IsSpecialUseIP reports whether ip is unusable as a public fetch destination.
// It covers loopback, private, link-local and unspecified addresses along with
// the IANA special-use ranges (including the cloud metadata endpoint).
func IsSpecialUseIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, r := range specialUseIPNets {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// SSRFGuardedTransport clones base and hardens it so requests cannot reach
// special-use addresses, for use whenever an authorization server fetches a URL
// supplied by a client (a client ID metadata document, a logo_uri, a JWKS URI).
//
// A pre-flight DNS check alone is not sufficient: the name can resolve to a
// public address when it is validated and to an internal one when the connection
// is actually made (DNS rebinding). The dialer's Control hook runs after
// resolution with the concrete address being dialed, so it closes that window,
// including on every hop of a redirect chain.
//
// Three settings on the base transport would otherwise defeat the guard and are
// therefore cleared:
//
//   - Proxy, because the dialer would connect to the proxy while the proxy
//     reaches the real destination, so the guard would only ever inspect the
//     proxy's address.
//   - DialTLS and DialTLSContext, because they bypass DialContext entirely.
//
// isSpecialUse may be nil, in which case IsSpecialUseIP is used.
//
// The guard works by installing a dialer, so it can only be applied to an
// *http.Transport. A base of any other type (an instrumentation wrapper such as
// otelhttp.Transport, say) hides the transport that actually dials, and there is
// no general way to reach inside it. Returning such a base unchanged would hand
// back something that looks guarded but is not, so this fails closed instead and
// guards a fresh transport derived from http.DefaultTransport.
//
// Wrappers must therefore be applied around the result, not to the input:
//
//	client.Transport = otelhttp.NewTransport(fosite.SSRFGuardedTransport(nil, nil))
//
// A nil base is guarded from http.DefaultTransport.
func SSRFGuardedTransport(base http.RoundTripper, isSpecialUse SpecialUseIPChecker) http.RoundTripper {
	if isSpecialUse == nil {
		isSpecialUse = IsSpecialUseIP
	}

	var transport *http.Transport
	switch t := base.(type) {
	case SSRFGuardExempt:
		// Explicitly declared not to dial anything, so there is nothing to guard.
		return t
	case *http.Transport:
		transport = t.Clone()
	default:
		// Includes a nil base and any wrapper we cannot introspect.
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			// http.DefaultTransport is always an *http.Transport in the standard
			// library; if that ever stops holding, guard an empty transport rather
			// than returning an unguarded one.
			transport = &http.Transport{}
		} else {
			transport = defaultTransport.Clone()
		}
	}

	// A proxy would hide the final destination from the guarded dialer.
	transport.Proxy = nil
	// Custom TLS dialers bypass DialContext, so the guarded transport must
	// perform the TLS handshake itself.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	// A pooled connection could have been established before this guard was
	// installed, so connections are made fresh.
	transport.DisableKeepAlives = true

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("could not parse dialed address %q", address)
			}
			if isSpecialUse(ip) {
				return ErrSpecialUseAddressBlocked
			}
			return nil
		},
	}
	transport.DialContext = dialer.DialContext

	return transport
}
