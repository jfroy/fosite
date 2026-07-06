// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"strings"

	"github.com/ory/x/errorsx"
)

// ScopeStrategy is a strategy for matching scopes.
type ScopeStrategy func(haystack []string, needle string) bool

// FilterRequestedScopes validates the requested scopes against the client's registered scopes using
// the given strategy. If ignoreUnknown is true, scope values the client is not allowed to request are
// removed from the returned list, as recommended by OpenID Connect Core 1.0 Section 3.1.2.1 for scope
// values that are not understood; otherwise the first such scope value fails with ErrInvalidScope.
func FilterRequestedScopes(strategy ScopeStrategy, client Client, requested Arguments, ignoreUnknown bool) (Arguments, error) {
	if !ignoreUnknown {
		for _, scope := range requested {
			if !strategy(client.GetScopes(), scope) {
				return nil, errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
			}
		}
		return requested, nil
	}

	scopes := make(Arguments, 0, len(requested))
	for _, scope := range requested {
		if strategy(client.GetScopes(), scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}

func HierarchicScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		// foo == foo -> true
		if this == needle {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(this) > len(needle) {
			continue
		}

		needles := strings.Split(needle, ".")
		haystack := strings.Split(this, ".")
		haystackLen := len(haystack) - 1
		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				break
			}
		}
	}

	return false
}

func ExactScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}

func WildcardScopeStrategy(matchers []string, needle string) bool {
	needleParts := strings.Split(needle, ".")
	for _, matcher := range matchers {
		matcherParts := strings.Split(matcher, ".")
		if len(matcherParts) > len(needleParts) {
			continue
		}

		var noteq bool
		for k, c := range matcherParts {
			// this is the last item and the lengths are different
			if k == len(matcherParts)-1 && len(matcherParts) != len(needleParts) {
				if c != "*" {
					noteq = true
					break
				}
			}

			if c == "*" && len(needleParts[k]) > 0 {
				// pass because this satisfies the requirements
				continue
			} else if c != needleParts[k] {
				noteq = true
				break
			}
		}

		if !noteq {
			return true
		}
	}

	return false
}
