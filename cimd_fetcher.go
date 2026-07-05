// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Default limits for fetching Client ID Metadata Documents. They follow the
// recommendations in draft-ietf-oauth-client-id-metadata-document.
const (
	DefaultCIMDMaxSize      = 5 * 1024 // 5 KiB (draft recommendation)
	DefaultCIMDFetchTimeout = 15 * time.Second
	DefaultCIMDMinCacheTTL  = 5 * time.Minute
	DefaultCIMDMaxCacheTTL  = 24 * time.Hour
	DefaultCIMDCacheTTL     = 1 * time.Hour
)

// cgnatIPNet is the RFC 6598 shared address space (100.64.0.0/10), which
// net.IP.IsPrivate does not cover. It is treated as private to block SSRF.
var cgnatIPNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// CIMDFetcher retrieves and validates the Client ID Metadata Document located
// at a client_id URL.
type CIMDFetcher interface {
	// Fetch retrieves the metadata document at clientID (an https URL), validates
	// it, and returns a parsed document along with the cache lifetime derived
	// from the response's Cache-Control header.
	Fetch(ctx context.Context, clientID string) (doc *ClientMetadataDocument, ttl time.Duration, err error)
}

// DefaultCIMDFetcher is the default CIMDFetcher. It blocks requests to private
// IP addresses (SSRF), refuses redirects, caps the response body size, and
// requires a 200 response.
type DefaultCIMDFetcher struct {
	client        *http.Client
	baseTransport http.RoundTripper
	userAgent     string

	maxSize    int64
	timeout    time.Duration
	minTTL     time.Duration
	maxTTL     time.Duration
	defaultTTL time.Duration

	allowPrivateIPs    bool
	resolver           *net.Resolver
	extraPrivateRanges []*net.IPNet
}

// CIMDFetcherOption configures a DefaultCIMDFetcher.
type CIMDFetcherOption func(*DefaultCIMDFetcher)

// WithCIMDTransport sets the base HTTP transport used for fetches. When it is
// nil or an *http.Transport, the fetcher clones it and installs a connect-time
// SSRF guard (unless private IPs are allowed); any other RoundTripper is used
// as-is (for example a test mock), relying on a resolution-time SSRF check.
func WithCIMDTransport(rt http.RoundTripper) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.baseTransport = rt }
}

// WithCIMDUserAgent sets the User-Agent header sent when fetching.
func WithCIMDUserAgent(ua string) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.userAgent = ua }
}

// WithCIMDMaxSize sets the maximum accepted response body size in bytes.
func WithCIMDMaxSize(n int64) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.maxSize = n }
}

// WithCIMDCacheTTLBounds sets the minimum, maximum, and default cache
// lifetimes applied to the max-age directive of a fetched document.
func WithCIMDCacheTTLBounds(minTTL, maxTTL, defaultTTL time.Duration) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) {
		f.minTTL, f.maxTTL, f.defaultTTL = minTTL, maxTTL, defaultTTL
	}
}

// WithCIMDAllowPrivateIPs disables SSRF protection, allowing documents to be
// fetched from private, loopback, or link-local addresses.
func WithCIMDAllowPrivateIPs(allow bool) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.allowPrivateIPs = allow }
}

// WithCIMDResolver sets the resolver used for resolution-time SSRF checks.
func WithCIMDResolver(r *net.Resolver) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.resolver = r }
}

// WithCIMDExtraPrivateRanges adds CIDR ranges that are treated as private.
func WithCIMDExtraPrivateRanges(ranges []*net.IPNet) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.extraPrivateRanges = ranges }
}

// NewDefaultCIMDFetcher returns a DefaultCIMDFetcher configured with the given
// options and package defaults.
func NewDefaultCIMDFetcher(opts ...CIMDFetcherOption) *DefaultCIMDFetcher {
	f := &DefaultCIMDFetcher{
		userAgent:  "fosite/oidc-client-metadata-fetcher",
		maxSize:    DefaultCIMDMaxSize,
		timeout:    DefaultCIMDFetchTimeout,
		minTTL:     DefaultCIMDMinCacheTTL,
		maxTTL:     DefaultCIMDMaxCacheTTL,
		defaultTTL: DefaultCIMDCacheTTL,
		resolver:   net.DefaultResolver,
	}
	for _, o := range opts {
		o(f)
	}
	f.client = f.buildHTTPClient()
	return f
}

var _ CIMDFetcher = (*DefaultCIMDFetcher)(nil)

// buildHTTPClient constructs the HTTP client used for fetching. It always refuses
// redirects. When the base transport is nil or an *http.Transport, it installs a
// connect-time SSRF guard that rejects connections to private IPs.
func (f *DefaultCIMDFetcher) buildHTTPClient() *http.Client {
	c := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not allowed when fetching client metadata")
		},
	}

	switch base := f.baseTransport.(type) {
	case nil:
		tr, _ := http.DefaultTransport.(*http.Transport)
		c.Transport = f.guardTransport(tr)
	case *http.Transport:
		c.Transport = f.guardTransport(base)
	default:
		c.Transport = base
	}
	return c
}

// guardTransport clones tr and, unless private IPs are allowed, installs a
// connect-time SSRF check via the dialer's Control hook.
func (f *DefaultCIMDFetcher) guardTransport(tr *http.Transport) http.RoundTripper {
	if tr == nil {
		tr = &http.Transport{}
	} else {
		tr = tr.Clone()
	}
	if f.allowPrivateIPs {
		return tr
	}
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
			if f.isPrivateIP(ip) {
				return errors.New("private IP addresses are not allowed")
			}
			return nil
		},
	}
	tr.DialContext = dialer.DialContext
	return tr
}

func (f *DefaultCIMDFetcher) Fetch(ctx context.Context, clientID string) (*ClientMetadataDocument, time.Duration, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, 0, err
	}
	if err := ValidateCIMDURL(u); err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	if !f.allowPrivateIPs {
		private, err := f.isPrivateURL(ctx, u)
		if err != nil {
			return nil, 0, err
		}
		if private {
			return nil, 0, errors.New("private IP addresses are not allowed")
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("unexpected status %d fetching client metadata", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(body)) > f.maxSize {
		return nil, 0, errors.New("client metadata document exceeds maximum size")
	}

	var doc ClientMetadataDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("invalid client metadata JSON: %w", err)
	}
	if err := doc.Validate(clientID); err != nil {
		return nil, 0, err
	}

	return &doc, f.parseCacheTTL(resp.Header.Get("Cache-Control")), nil
}

// parseCacheTTL derives the cache lifetime from a Cache-Control header value,
// clamping the max-age directive into [minTTL, maxTTL] and falling back to
// defaultTTL when no usable directive is present.
func (f *DefaultCIMDFetcher) parseCacheTTL(cacheControl string) time.Duration {
	for part := range strings.SplitSeq(cacheControl, ",") {
		v, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age=")
		if !ok {
			continue
		}
		secs, err := strconv.Atoi(v)
		if err != nil {
			continue
		}
		d := time.Duration(secs) * time.Second
		switch {
		case d < f.minTTL:
			return f.minTTL
		case d > f.maxTTL:
			return f.maxTTL
		default:
			return d
		}
	}
	return f.defaultTTL
}

// isPrivateURL resolves the host of u and reports if any address is private.
func (f *DefaultCIMDFetcher) isPrivateURL(ctx context.Context, u *url.URL) (bool, error) {
	ips, err := f.resolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return false, errors.New("cannot resolve hostname")
	}
	for _, addr := range ips {
		if f.isPrivateIP(addr.IP) {
			return true, nil
		}
	}
	return false, nil
}

// isPrivateIP reports whether ip is one of: loopback, RFC 1918 / ULA private,
// link-local, unspecified, RFC 6598 CGNAT space, or in an extra private range.
func (f *DefaultCIMDFetcher) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if cgnatIPNet.Contains(ip) {
		return true
	}
	for _, r := range f.extraPrivateRanges {
		if r != nil && r.Contains(ip) {
			return true
		}
	}
	return false
}
