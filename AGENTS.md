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
| Language | Python 3.8+ |
| HTTP | requests (>=2.0.0) |
| Testing | pytest (>=7.0.0) |
| Packaging | setuptools (`setup.py`, version read from `soundcloud/__init__.py`) |
| CI | GitHub Actions (`.github/workflows/tests.yml`) |

## Directory Structure

```
├── setup.py                     # Packaging (version parsed from soundcloud/__init__.py)
├── requirements.txt             # Deps: requests, pytest
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
└── .github/workflows/tests.yml  # CI: Python 3.8–3.12 matrix
```

## Commands

```bash
# Run the test suite (same as CI)
pytest

# Single test file
pytest soundcloud/tests/test_resource.py

# With verbose output
pytest -v
```

### Git Workflow

- Work directly on `master`
- Commit messages prefixed with scope where applicable: `client:`, `resource:`, `chore:`, `docs:`
- Always `git pull --rebase origin master` before pushing
- Push directly: `git push origin master`

## Coding Guidelines

### Style
- Python 3 syntax only (no `object` base classes, use `super()`, f-strings, raw-string regexes) — the repo was modernized from Python 2 legacy code
- No comments unless they clarify non-obvious API behavior
- Keep public API stable: `soundcloud.Client` is the main entry point, re-exported in `soundcloud/__init__.py`
- Version lives ONLY in `soundcloud/__init__.py` (`__version__`); `setup.py` parses it — never bump in two places

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
pytest -v            # 1. Full test suite must pass
```

CI (GitHub Actions) runs the same suite on every push/PR across Python 3.8–3.12.

## Do Not Touch

- `.DS_Store` (check for accidental commits)
- `.pytest_cache/`, `__pycache__/` — gitignored
- `requirements.txt` — only update via deliberate dependency bumps
