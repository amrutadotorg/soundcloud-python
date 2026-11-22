# Coding Standards — soundcloud-python

## Style

- Python 3.14+ syntax (type-union annotations `str | None`, no `object` base classes, use `super()`, f-strings, raw-string regexes, PEP 649 deferred annotations) — the repo was modernized from Python 2 legacy code
- Formatted with `ruff format`, linted with `ruff check` (default rule set), type-checked with `pyright` — all enforced in CI
- No comments unless they clarify non-obvious API behavior
- Keep public API stable: `soundcloud.Client` is the main entry point, re-exported in `soundcloud/__init__.py`
- Version lives ONLY in `soundcloud/__init__.py` (`__version__`); hatchling parses it — never bump in two places

## Client

- `client.get(path, **params)` — the primary method; always returns wrapped `Resource` objects (via `wrapped_resource`)
- OAuth 2.1 / PKCE flow: `Client(client_id=..., client_secret=..., redirect_uri=...)`, `client.authorize_url()`, `client.exchange_token(code)`
- Public resources (no user session): `client.client_credentials_token()` — requires `client_id` + `client_secret` (HTTP Basic auth, per SoundCloud docs)
- Refresh tokens are **single-use** (rotated on every refresh); the new token lands in `client.options["refresh_token"]` — persist it
- `client_id` must never leak into signed request URLs (see git history for the client_id leak fix)
- `AuthFlow.from_options(options)` (in `soundcloud/auth.py`) picks the OAuth flow; each flow's `resolve(client)` returns a `Credential` (`AccessTokenCredential` for Bearer, `ClientIdCredential` for public `client_id`) — every token-setting path goes through `Client._set_token()`, so the request credential is always the single source of auth truth

## Tests

- Unit tests: no external network calls — use `MockResponse` from `soundcloud/tests/utils.py` (mock `requests` via the request layer)
- Add a test for every new client method or param-encoding edge case
- Integration tests (`soundcloud/tests/test_integration.py`, marker `integration`) hit the live API; they **skip automatically** when `SOUNDCLOUD_CLIENT_ID` is not set, so the default suite never needs network or secrets

Integration-test env vars and the `.sc_refresh_token` rotation file: [integration-credentials](integration-credentials.md).
