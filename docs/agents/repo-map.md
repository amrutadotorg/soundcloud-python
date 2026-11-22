# Repo Map — soundcloud-python

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
| CI | GitHub Actions — `.github/workflows/tests.yml` (push/PR) and `.github/workflows/integration.yml` (manual, live API) |

## Directory Structure

```text
├── pyproject.toml               # Packaging + deps (version parsed from soundcloud/__init__.py)
├── uv.lock                      # Lockfile (managed by uv)
├── .travis.yml                  # Legacy Travis CI (Python 2.7–3.5, nosetests) — real CI is GitHub Actions
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
│       ├── __init__.py          # Empty package marker
│       ├── utils.py             # MockResponse helper
│       ├── test_client.py       # Client tests
│       ├── test_encoding.py     # Param encoding tests
│       ├── test_integration.py  # Live API tests (opt-in, marker: integration)
│       ├── test_oauth.py        # OAuth 2.1 / PKCE tests
│       ├── test_requests.py     # Request tests
│       └── test_resource.py     # Resource wrapping tests
├── .github/workflows/tests.yml  # CI: lint + pyright + tests (Python 3.14)
└── .github/workflows/integration.yml  # CI: live API tests (manual workflow_dispatch)
```

Also tracked but not shown above: `LICENSE`, `.gitignore`, `.github/dependabot.yml`. The tree is a map, not an exhaustive listing.
