# Verification Workflow — soundcloud-python

Before considering any change complete:

```bash
uv run ruff check .          # 1. Lint must pass
uv run ruff format --check . # 2. Format must pass
uv run pyright               # 3. Type check must pass
uv run pytest -v             # 4. Full test suite must pass
```

CI (GitHub Actions) runs steps 1–3 and the test suite on Python 3.14 on every push/PR. Live API tests are opt-in via the `integration` workflow (manual `workflow_dispatch`, uses GitHub Secrets `SOUNDCLOUD_*`).

Integration-test credentials: [integration-credentials](integration-credentials.md).
