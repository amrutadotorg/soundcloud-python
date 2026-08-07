# Project Context & Rules for AI Agents

## Overview

Community-maintained fork of the deprecated *soundcloud-python* library — a friendly Python wrapper around the SoundCloud API. Adds support for **SoundCloud API v2**, **OAuth 2.1**, and **PKCE** (Proof Key for Code Exchange). Not affiliated with SoundCloud Ltd.

## GitHub Repository

- **URL**: https://github.com/amrutadotorg/soundcloud-python
- **Default branch**: `master`
- **Clone**: `git clone git@github.com:amrutadotorg/soundcloud-python.git`

## Tech Stack

| Category | Technology |
|---|---|
| Language | Python 3.14+ (managed by uv) |
| HTTP | requests (>=2.0.0) |
| Testing | pytest (>=7.0.0) |
| Linting | ruff (check + format) |
| Type Checking | pyright |
| Packaging | hatchling (`pyproject.toml`, version parsed from `soundcloud/__init__.py`) |
| CI | GitHub Actions (`.github/workflows/tests.yml`) |

## Directory Structure

```
├── pyproject.toml               # Packaging + deps (version parsed from soundcloud/__init__.py)
├── uv.lock                      # Lockfile (managed by uv)
├── .python-version              # Dev Python: 3.14
├── README.rst                   # Usage docs (API v2, OAuth 2.1 / PKCE)
├── soundcloud/
│   ├── __init__.py              # __version__, USER_AGENT, re-exports Client
│   ├── auth.py                  # AuthFlow.from_options factory + Credential seam
│   ├── client.py                # Client class (OAuth 2.1 / PKCE, request helpers)
│   ├── request.py               # make_request low-level HTTP
│   ├── resource.py              # Resource, ResourceList, wrapped_resource
│   ├── hashconversions.py       # to_params / normalize_param query builders
│   └── tests/
│       ├── utils.py             # MockResponse helper
│       ├── test_client.py       # Client tests
│       ├── test_encoding.py     # Param encoding tests
│       ├── test_integration.py  # Live API tests (opt-in, marker: integration)
│       ├── test_oauth.py        # OAuth 2.1 / PKCE tests
│       ├── test_requests.py     # Request tests
│       └── test_resource.py     # Resource wrapping tests
└── .github/workflows/tests.yml  # CI: lint + pyright + tests (Python 3.14)
└── .github/workflows/integration.yml  # CI: live API tests (manual workflow_dispatch)
```

## Commands

```bash
# Install deps (creates .venv)
uv sync

# Run the test suite (same as CI)
uv run pytest

# Single test file
uv run pytest soundcloud/tests/test_resource.py

# With verbose output
uv run pytest -v

# Lint / format / type check (same as CI)
uv run ruff check .
uv run ruff format --check .
uv run pyright

# Live API integration tests (opt-in, needs credentials — see below)
SOUNDCLOUD_CLIENT_ID=... uv run pytest -m integration -v -s
```

### Git Workflow

- Work directly on `master`
- Commit messages prefixed with scope where applicable: `client:`, `resource:`, `chore:`, `docs:`
- Always `git pull --rebase origin master` before pushing
- Push directly: `git push origin master`

## Coding Guidelines

### Style
- Python 3.14+ syntax (type-union annotations `str | None`, no `object` base classes, use `super()`, f-strings, raw-string regexes, PEP 649 deferred annotations) — the repo was modernized from Python 2 legacy code
- Formatted with `ruff format`, linted with `ruff check` (default rule set), type-checked with `pyright` — all enforced in CI
- No comments unless they clarify non-obvious API behavior
- Keep public API stable: `soundcloud.Client` is the main entry point, re-exported in `soundcloud/__init__.py`
- Version lives ONLY in `soundcloud/__init__.py` (`__version__`); hatchling parses it — never bump in two places

### Client
- `client.get(path, **params)` — the primary method; always returns wrapped `Resource` objects (via `wrapped_resource`)
- OAuth 2.1 / PKCE flow: `Client(client_id=..., client_secret=..., redirect_uri=...)`, `client.authorize_url()`, `client.exchange_token(code)`
- Public resources (no user session): `client.client_credentials_token()` — requires `client_id` + `client_secret` (HTTP Basic auth, per SoundCloud docs)
- Refresh tokens are **single-use** (rotated on every refresh); the new token lands in `client.options["refresh_token"]` — persist it
- `client_id` must never leak into signed request URLs (see git history for the client_id leak fix)
- `AuthFlow.from_options(options)` (in `soundcloud/auth.py`) picks the OAuth flow; each flow's `resolve(client)` returns a `Credential` (`AccessTokenCredential` for Bearer, `ClientIdCredential` for public `client_id`) — every token-setting path goes through `Client._set_token()`, so the request credential is always the single source of auth truth

### Tests
- Unit tests: no external network calls — use `MockResponse` from `soundcloud/tests/utils.py` (mock `requests` via the request layer)
- Add a test for every new client method or param-encoding edge case
- Integration tests (`soundcloud/tests/test_integration.py`, marker `integration`) hit the live API; they **skip automatically** when `SOUNDCLOUD_CLIENT_ID` is not set, so the default suite never needs network or secrets

### Integration Test Credentials
Never commit credentials — pass them via env vars:

| Env var | Used by | Notes |
|---|---|---|
| `SOUNDCLOUD_CLIENT_ID` | all integration tests | mandatory; without it everything skips |
| `SOUNDCLOUD_CLIENT_SECRET` | most integration tests | all clients are confidential — secret is required for every flow |
| `SOUNDCLOUD_REDIRECT_URI` | `test_authorize_url_pkce`, `test_exchange_token` | must match the registered app callback |
| `SOUNDCLOUD_USER_PERMALINK` | `test_me_endpoint`, `test_client_credentials_public_resources` | default: `nirmala-vidya-portal` |
| `SOUNDCLOUD_REFRESH_TOKEN` | user-token tests | optional — otherwise read from `.sc_refresh_token` (see below) |
| `SOUNDCLOUD_AUTH_CODE` | `test_exchange_token` | optional: skip interactive prompt |
| `SOUNDCLOUD_VERIFIER` | `test_exchange_token` | optional: pin PKCE verifier to reuse a captured code (43–128 chars) |

User-token tests persist the **rotated** refresh token to `.sc_refresh_token`
in the repo root (gitignored) and read it back on the next run — refresh
tokens are single-use, so the file keeps the suite repeatable.

`test_exchange_token` is semi-interactive: it prints the `authorize_url` — open it in a browser, approve, and paste the `code` from the redirect URL (run with `-s`). The code is bound to the code_verifier, so to reuse a captured code across runs you must pin `SOUNDCLOUD_VERIFIER` (set it before generating the URL).

## Verification Workflow

Before considering any change complete:

```bash
uv run ruff check .          # 1. Lint must pass
uv run ruff format --check . # 2. Format must pass
uv run pyright               # 3. Type check must pass
uv run pytest -v             # 4. Full test suite must pass
```

CI (GitHub Actions) runs steps 1–3 and the test suite on Python 3.14 on every push/PR. Live API tests are opt-in via the `integration` workflow (manual `workflow_dispatch`, uses GitHub Secrets `SOUNDCLOUD_*`).

## Do Not Touch

- `.DS_Store` (check for accidental commits)
- `.pytest_cache/`, `__pycache__/` — gitignored
- `uv.lock` — only update via `uv add`/`uv remove`/`uv lock`
