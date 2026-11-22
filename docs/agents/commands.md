# Commands — soundcloud-python

All commands run through **uv** from the repo root.

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

# Live API integration tests (opt-in, needs credentials — see integration-credentials.md)
SOUNDCLOUD_CLIENT_ID=... uv run pytest -m integration -v -s
```

Credentials for the live-API run: [integration-credentials](integration-credentials.md).
