# Pocket ID fosite fork — changes vs. upstream

This repository is [Pocket ID](https://github.com/pocket-id/pocket-id)'s fork of
[ory/fosite](https://github.com/ory/fosite). All custom work lives as a **linear
series of commits on top of upstream `master`**, so the full delta is always
visible with:

```sh
git log --oneline <upstream-master>..main
```

The module path intentionally remains `github.com/ory/fosite`; Pocket ID
consumes the fork via a `replace` directive, so no import paths need to change
and rebasing onto upstream stays trivial.

## Commits on `main`

### 1. `chore: upgrade deps`

Upgrades Go and the project's dependencies to the latest versions.

### 2. `chore: update copyright`

Bump of the license header (`Copyright © 2025 Ory Corp` → `© 2026 Ory Corp`).

### 3. `ci/cd: adapt actions for Pocket ID use`

Deletes GitHub Actions that only make sense in the ory org: stale-issue bot,
label sync, closed-reference notifier, and the two OIDC-conformity workflows
(they test against ory/hydra's conformance harness and cannot run for the fork).
Trims `licenses.yml` (no more auto-commit as ory-bot).

### 4. `feat: replace ory with pocket-id prefix`

Changes the opaque-token vendor prefixes from `ory_*_` to `pocket_id_*_`: access
tokens (`pocket_id_at_`), refresh tokens (`pocket_id_rt_`), authorize codes
(`pocket_id_ac_`) and RFC 8628 device codes (`pocket_id_dc_`).

### 5. `feat: validate OIDC prompt in authorize requests`

Validates the OIDC `prompt` parameter early, in `NewAuthorizeRequest` (and PAR),
instead of only in the openid handler at response time. For requests with the
`openid` scope: unknown prompt values (outside `Config.GetAllowedPrompts`,
default `login none consent select_account`) and `none` combined with other
values are rejected with `invalid_request`. The check runs after redirect-URI
validation, so the error is **redirected to the client** rather than rendered as
JSON. Pocket ID needs this so invalid prompts fail before its login/consent UI
runs.

### 6. `fix: redirect unsupported request object errors`

When OIDC request-object processing fails early (e.g. a `request` parameter sent
to a client that isn't an `OpenIDConnectClient`, an invalid `request_uri`, a
malformed request object), fosite used to render a raw JSON error because the
redirect URI had not been validated yet. A new helper
(`prepareAuthorizeRequestForErrorRedirect`) validates the `redirect_uri` against
the client on that error path and sets the response mode, so these errors are
now redirected per RFC 6749 §4.1.2.1. Errors are still never redirected to
unvalidated URIs (JSON fallback remains).

### 7. `feat: add configurable redirect URI matcher`

Makes redirect-URI matching pluggable. New `fosite.RedirectURIMatcher` func
type, `RedirectURIMatcherProvider` interface, and `Config.RedirectURIMatcher`
option (default: upstream's exact matcher
`MatchRedirectURIWithClientRedirectURIs`). The matcher is stamped onto each
`AuthorizeRequest` (never persisted, re-applied on PAR continuation) and used by
both the authorize and PAR endpoints.

### 8. `feat: include wrong redirect uri in error message`

The `invalid_request` hint for an unregistered `redirect_uri` now echoes the
offending value ("The redirect_uri 'https://…' is not registered for this
client.") instead of the generic upstream message. Pocket ID shows fosite hints
on its error page, so this makes misconfigured clients much easier to debug.

### 9. `feat: add RFC 8707 resource indicator support`

Adds Resource Indicators (RFC 8707):

- New `invalid_target` error (`fosite.ErrInvalidTarget`, HTTP 400).
- The `resource` parameter is syntactically validated at all three entry points
  (authorize/PAR, token, device authorization): it must be a single absolute URI
  without fragment or whitespace.
- `Requester` gains `GetResource()`, plus the `IsValidScopeToken` (RFC 6749
  scope-token grammar) helper for consumers.

Resolving a resource to an audience and grantable scopes is application policy
and lives in Pocket ID itself.

### 10. `feat: ignore the "audience" request parameter`

Stops parsing the non-standard `audience` request parameter (an ory/Auth0-style
extension; only RFC 8693 token exchange standardizes it) at the authorize, token
and device endpoints, and removes the upstream `fosite.GetAudiences` helper and
`validateAudience` check. Audience handling is now driven exclusively by RFC
8707 resource indicators (commit 9) or programmatic
`SetRequestedAudience`/`GrantAudience`. A request with an unknown `audience`
value now simply succeeds without an `aud` claim instead of failing. The
`AudienceMatchingStrategy` config and the per-flow audience checks remain intact
for programmatic use.

### 11. `feat: add option to ignore unknown scopes`

Adds `Config.IgnoreUnknownScopes` (plus the exported
`fosite.FilterRequestedScopes` helper): when enabled, requested scopes the
client is not registered for are dropped from authorize (incl. PAR) and device
requests instead of failing with `invalid_scope`, per OIDC Core 1.0 §3.1.2.1.
The effective scopes are still reported via the `scope` response parameter.
Filtering runs before the OIDC redirect-URI and prompt checks. Token-endpoint
grants (`client_credentials`, `password`) and the refresh flow stay strict.
Defaults to `false`. Lets MCP clients that blindly request scopes like `phone`
or `offline_access` still authenticate.
