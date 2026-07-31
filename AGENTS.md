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
| Language | Python 3.11+ (managed by uv) |
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
├── .python-version              # Dev Python: 3.11
├── README.rst                   # Usage docs (API v2, OAuth 2.1 / PKCE)
├── soundcloud/
│   ├── __init__.py              # __version__, USER_AGENT, re-exports Client
│   ├── client.py                # Client class (OAuth 2.1 / PKCE, request helpers)
│   ├── request.py               # make_request low-level HTTP
│   ├── resource.py              # Resource, ResourceList, wrapped_resource
│   ├── hashconversions.py       # to_params / normalize_param query builders
│   └── tests/
│       ├── utils.py             # MockResponse helper
│       ├── test_client.py       # Client tests
│       ├── test_encoding.py     # Param encoding tests
│       ├── test_oauth.py        # OAuth 2.1 / PKCE tests
│       ├── test_requests.py     # Request tests
│       └── test_resource.py     # Resource wrapping tests
└── .github/workflows/tests.yml  # CI: lint + pyright + tests (Python 3.11–3.12)
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
```

### Git Workflow

- Work directly on `master`
- Commit messages prefixed with scope where applicable: `client:`, `resource:`, `chore:`, `docs:`
- Always `git pull --rebase origin master` before pushing
- Push directly: `git push origin master`

## Coding Guidelines

### Style
- Python 3.11+ syntax (type-union annotations `str | None`, no `object` base classes, use `super()`, f-strings, raw-string regexes) — the repo was modernized from Python 2 legacy code
- Formatted with `ruff format`, linted with `ruff check` (default rule set), type-checked with `pyright` — all enforced in CI
- No comments unless they clarify non-obvious API behavior
- Keep public API stable: `soundcloud.Client` is the main entry point, re-exported in `soundcloud/__init__.py`
- Version lives ONLY in `soundcloud/__init__.py` (`__version__`); hatchling parses it — never bump in two places

### Client
- `client.get(path, **params)` — the primary method; always returns wrapped `Resource` objects (via `wrapped_resource`)
- OAuth 2.1 / PKCE flow: `Client(client_id=..., client_secret=..., redirect_uri=...)`, `client.authorize_url()`, `client.exchange_token(code)`
- `client_id` must never leak into signed request URLs (see git history for the client_id leak fix)

### Tests
- No external network calls — use `MockResponse` from `soundcloud/tests/utils.py`
- All tests are pure unit tests (mock `requests` via the request layer)
- Add a test for every new client method or param-encoding edge case

## Verification Workflow

Before considering any change complete:

```bash
uv run ruff check .          # 1. Lint must pass
uv run ruff format --check . # 2. Format must pass
uv run pyright               # 3. Type check must pass
uv run pytest -v             # 4. Full test suite must pass
```

CI (GitHub Actions) runs steps 1–3 on Python 3.11 and the test suite across Python 3.11–3.12 on every push/PR.

## Do Not Touch

- `.DS_Store` (check for accidental commits)
- `.pytest_cache/`, `__pycache__/` — gitignored
- `uv.lock` — only update via `uv add`/`uv remove`/`uv lock`
