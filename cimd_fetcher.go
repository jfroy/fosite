// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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

// specialUseIPNets contains special-purpose ranges that net.IP does not reject
// through its built-in private, loopback, link-local, or unspecified checks.
var specialUseIPNets = parseCIMDSpecialUseRanges([]string{
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"100:0:0:1::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"2620:4f:8000::/48",
	"3fff::/20",
	"5f00::/16",
	"ff00::/8",
})

// CIMDFetcher retrieves and validates the Client ID Metadata Document located
// at a client_id URL.
type CIMDFetcher interface {
	// Fetch retrieves the metadata document at clientID (an https URL), validates
	// it, and returns a parsed document along with the cache lifetime derived
	// from the response's Cache-Control header.
	Fetch(ctx context.Context, clientID string) (doc *ClientMetadataDocument, ttl time.Duration, err error)
}

// CIMDSecureHTTPClientProvider exposes the guarded client for fetching URLs referenced by a metadata document.
type CIMDSecureHTTPClientProvider interface {
	ValidateFetchURL(context.Context, string) error
	CIMDHTTPClient() *http.Client
}

// DefaultCIMDFetcher is the default CIMDFetcher. It blocks requests to private
// IP addresses (SSRF), refuses redirects, caps the response body size, and
// requires a 200 response.
type DefaultCIMDFetcher struct {
	client        *http.Client
	baseTransport http.RoundTripper
	decorate      func(http.RoundTripper) http.RoundTripper
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

// WithCIMDTransport sets the base HTTP transport used for fetches.
//
// A nil or *http.Transport value receives both resolution-time and connect-time
// SSRF protection. Other RoundTripper implementations are intended for tests or
// transports that already enforce equivalent connect-time protection.
func WithCIMDTransport(rt http.RoundTripper) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.baseTransport = rt }
}

// WithCIMDTransportDecorator wraps the guarded transport without hiding its dialer from the fetcher.
//
// This is the preferred option for tracing, metrics, and other middleware.
func WithCIMDTransportDecorator(decorate func(http.RoundTripper) http.RoundTripper) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.decorate = decorate }
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
var _ CIMDSecureHTTPClientProvider = (*DefaultCIMDFetcher)(nil)

// buildHTTPClient constructs the HTTP client used for fetching.
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
	if f.decorate != nil {
		if decorated := f.decorate(c.Transport); decorated != nil {
			c.Transport = decorated
		}
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
			if f.isSpecialUseIP(ip) {
				return errors.New("special-use IP addresses are not allowed")
			}
			return nil
		},
	}
	tr.DialContext = dialer.DialContext
	return tr
}

func (f *DefaultCIMDFetcher) Fetch(ctx context.Context, clientID string) (*ClientMetadataDocument, time.Duration, error) {
	u, err := ParseCIMDURL(clientID)
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	if err := f.validateResolvedURL(ctx, u); err != nil {
		return nil, 0, err
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
	if err := validateCIMDContentType(resp.Header.Get("Content-Type")); err != nil {
		return nil, 0, err
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

// parseCacheTTL honors explicit no-cache directives before applying a bounded max-age value
// and falls back to the configured default when the header has no usable directive
func (f *DefaultCIMDFetcher) parseCacheTTL(cacheControl string) time.Duration {
	// Check bypass directives first so they take precedence regardless of header order
	for part := range strings.SplitSeq(cacheControl, ",") {
		directive, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(directive, "no-store") || strings.EqualFold(directive, "no-cache") {
			return 0
		}
	}
	// Use the first valid max-age value and clamp it to the configured cache bounds
	for part := range strings.SplitSeq(cacheControl, ",") {
		directive, value, hasValue := strings.Cut(strings.TrimSpace(part), "=")
		if !hasValue || !strings.EqualFold(directive, "max-age") {
			continue
		}
		v := strings.Trim(value, `"`)
		secs, err := strconv.ParseInt(v, 10, 64)
		if err != nil || secs < 0 {
			continue
		}
		if secs == 0 {
			return 0
		}
		if secs > int64(f.maxTTL/time.Second) {
			return f.maxTTL
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

// ValidateFetchURL checks whether an HTTP URL referenced by a metadata document is safe to fetch.
func (f *DefaultCIMDFetcher) ValidateFetchURL(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid metadata URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("metadata URL must use the https scheme")
	}
	if u.Hostname() == "" {
		return errors.New("metadata URL must have a host")
	}
	if u.User != nil {
		return errors.New("metadata URL must not contain userinfo")
	}
	return f.validateResolvedURL(ctx, u)
}

// CIMDHTTPClient returns a copy of the guarded HTTP client for fetching referenced metadata URLs.
func (f *DefaultCIMDFetcher) CIMDHTTPClient() *http.Client {
	client := *f.client
	client.Timeout = f.timeout
	return &client
}

// validateResolvedURL rejects every special-use address returned for the URL host.
func (f *DefaultCIMDFetcher) validateResolvedURL(ctx context.Context, u *url.URL) error {
	if f.allowPrivateIPs {
		return nil
	}
	special, err := f.isSpecialUseURL(ctx, u)
	if err != nil {
		return err
	}
	if special {
		return errors.New("special-use IP addresses are not allowed")
	}
	return nil
}

// validateCIMDContentType accepts the standard JSON media type and structured JSON suffixes.
func validateCIMDContentType(value string) error {
	if value == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return fmt.Errorf("invalid client metadata content type: %w", err)
	}
	if mediaType != "application/json" && !(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json")) {
		return fmt.Errorf("client metadata response has unsupported content type %q", mediaType)
	}
	return nil
}

// isSpecialUseURL resolves the host of u and reports if any address is special-use.
func (f *DefaultCIMDFetcher) isSpecialUseURL(ctx context.Context, u *url.URL) (bool, error) {
	ips, err := f.resolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return false, errors.New("cannot resolve hostname")
	}
	for _, addr := range ips {
		if f.isSpecialUseIP(addr.IP) {
			return true, nil
		}
	}
	return false, nil
}

// isSpecialUseIP reports whether ip is unusable as a public CIMD fetch destination.
func (f *DefaultCIMDFetcher) isSpecialUseIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, r := range specialUseIPNets {
		if r.Contains(ip) {
			return true
		}
	}
	for _, r := range f.extraPrivateRanges {
		if r != nil && r.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIMDSpecialUseRanges(cidrs []string) []*net.IPNet {
	ranges := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		ranges = append(ranges, ipNet)
	}
	return ranges
}
