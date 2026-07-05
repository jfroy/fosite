// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// LooksLikeCIMDURL reports whether clientID looks like a CIMD URL. Detection
// is intentionally cheap and imprecise.
func LooksLikeCIMDURL(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}

// ValidateCIMDURL enforces the client_id URL rules from
// draft-ietf-oauth-client-id-metadata-document §2.
func ValidateCIMDURL(u *url.URL) error {
	if u.Scheme != "https" {
		return errors.New("client_id URL must use the https scheme")
	}
	if u.Host == "" {
		return errors.New("client_id URL must have a host")
	}
	if u.User != nil {
		return errors.New("client_id URL must not contain userinfo")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return errors.New("client_id URL must not contain a fragment")
	}
	if u.RawQuery != "" {
		return errors.New("client_id URL must not contain a query string")
	}
	if u.Path == "" || u.Path == "/" {
		return errors.New("client_id URL must contain a path component")
	}
	// url.Parse preserves dot segments in Path (it does not clean them), so this catches them.
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("client_id URL must not contain %q path segments", seg)
		}
	}
	return nil
}

// ClientMetadataDocument is the subset of RFC 7591 client metadata that a Client
// ID Metadata Document consumer reads. Unknown members are ignored (the draft
// permits additional members).
type ClientMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	JwksURI                 string   `json:"jwks_uri"`
	LogoURI                 string   `json:"logo_uri"`

	// Presence of these is forbidden by the draft; pointers detect presence.
	ClientSecret          *string `json:"client_secret"`
	ClientSecretExpiresAt *int64  `json:"client_secret_expires_at"`
}

// Validate checks the document against the client_id URL it was fetched from, per
// draft-ietf-oauth-client-id-metadata-document §3: the document's client_id must
// equal the URL it was retrieved from, and it must not carry a client secret.
func (d *ClientMetadataDocument) Validate(clientID string) error {
	if d.ClientID != clientID {
		return fmt.Errorf("client_id %q does not match document URL %q", d.ClientID, clientID)
	}
	if d.ClientSecret != nil || d.ClientSecretExpiresAt != nil {
		return errors.New("client metadata document must not contain a client secret")
	}
	return nil
}
