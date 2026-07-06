// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/ory/x/errorsx"
)

// GetResourceIndicator extracts a single RFC 8707 resource value from a form.
func GetResourceIndicator(form url.Values) (string, error) {
	values := form["resource"]
	if len(values) > 1 {
		return "", errorsx.WithStack(ErrInvalidTarget.WithHint("Only a single 'resource' parameter is supported."))
	}
	if len(values) == 0 {
		return "", nil
	}
	return values[0], nil
}

// ValidateResourceIndicator validates and returns the single RFC 8707 resource value from a form.
func ValidateResourceIndicator(form url.Values) (string, error) {
	resource, err := GetResourceIndicator(form)
	if err != nil {
		return "", err
	}
	if resource == "" {
		return "", nil
	}
	if !IsValidResourceIndicatorURI(resource) {
		return "", errorsx.WithStack(ErrInvalidTarget.WithHintf("The requested resource '%s' is invalid, missing, unknown, or malformed.", resource))
	}

	return resource, nil
}

// IsValidResourceIndicatorURI reports whether raw is an absolute RFC 8707 resource URI without a fragment component.
func IsValidResourceIndicatorURI(raw string) bool {
	if raw == "" || strings.Contains(raw, "#") || strings.ContainsFunc(raw, unicode.IsSpace) {
		return false
	}

	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	return u.IsAbs()
}

// IsValidScopeToken reports whether scope is a valid RFC 6749 scope-token.
func IsValidScopeToken(scope string) bool {
	if scope == "" {
		return false
	}

	for i := 0; i < len(scope); i++ {
		c := scope[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) {
			continue
		}
		return false
	}

	return true
}
