// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"net/url"

	"github.com/ory/x/errorsx"
)

// ValidateRegistrationRedirectURIs applies the redirect_uri rules an authorization
// server must enforce on an OpenID Connect Dynamic Client Registration request
// (RFC 7591 section 2, RFC 7592 section 2.2).
//
// A registration request comes from an untrusted caller, so these checks do not
// depend on the deployment configuring a sufficiently narrow allowlist:
//
//   - At least one redirect_uri must be present.
//   - Each must be an absolute URI without a fragment (RFC 6749 section 3.1.2).
//   - Each must not use an active-content scheme (see IsActiveContentRedirectURI),
//     which would make the redirect an XSS or local-file-disclosure primitive.
//
// Private-use (custom) schemes stay valid so native apps following RFC 8252 can
// register. Any additional, deployment-specific restriction (such as an operator
// allowlist of permitted hosts) is layered on top by the authorization server.
func ValidateRegistrationRedirectURIs(redirectURIs []string) error {
	if len(redirectURIs) == 0 {
		return errorsx.WithStack(ErrInvalidRedirectURI.
			WithHint("At least one redirect_uri is required."))
	}

	for _, raw := range redirectURIs {
		parsed, err := url.Parse(raw)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRedirectURI.
				WithHintf("The redirect_uri '%s' is not a valid URI.", raw))
		}

		if parsed.Scheme == "" {
			return errorsx.WithStack(ErrInvalidRedirectURI.
				WithHintf("The redirect_uri '%s' must be an absolute URI.", raw))
		}

		if parsed.Fragment != "" {
			return errorsx.WithStack(ErrInvalidRedirectURI.
				WithHintf("The redirect_uri '%s' must not include a fragment.", raw))
		}

		if IsActiveContentRedirectURI(parsed) {
			return errorsx.WithStack(ErrInvalidRedirectURI.
				WithHintf("The redirect_uri '%s' uses a scheme that is not allowed.", raw))
		}
	}

	return nil
}
