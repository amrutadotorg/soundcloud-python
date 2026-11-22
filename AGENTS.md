# AGENTS.md — soundcloud-python

Community-maintained fork of the deprecated *soundcloud-python* library — a friendly Python wrapper around the **SoundCloud API v2** with **OAuth 2.1** and **PKCE** support. Python 3.14+ managed by **uv** — never pip or npm. Not affiliated with SoundCloud Ltd.

Commands run from the repo root; every tool invocation goes through `uv run`.

## Commands used on nearly every task

| Task | Command |
|---|---|
| Install deps (creates `.venv`) | `uv sync` |
| Full test suite (same as CI) | `uv run pytest` |
| Single test file | `uv run pytest soundcloud/tests/test_resource.py` |
| Lint · format · types (same as CI) | `uv run ruff check .` · `uv run ruff format --check .` · `uv run pyright` |

## Done means

`uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` and the full `uv run pytest` suite all green. CI runs the same four on Python 3.14 on every push/PR; live-API tests are opt-in and skip without credentials ([verification](docs/agents/verification.md)).

## Rules that apply to every task

- Version lives ONLY in `soundcloud/__init__.py` (`__version__`); hatchling parses it — never bump in two places.
- `uv.lock` changes only via `uv add` / `uv remove` / `uv lock` — never hand-edit it ([do-not-touch](docs/agents/do-not-touch.md)).
- Keep the public API stable: `soundcloud.Client` is the main entry point ([style](docs/agents/coding-standards.md#style)).

## Read on demand

| Document | Reach for it when |
|---|---|
| [repo-map](docs/agents/repo-map.md) | Orienting: repo URL/branch, tech stack, what lives in each file, CI workflows |
| [commands](docs/agents/commands.md) | The full annotated command block: setup, tests, lint, opt-in live-API runs |
| [git-workflow](docs/agents/git-workflow.md) | Committing/pushing: `master`, scope-prefixed messages, `pull --rebase` |
| [coding-standards](docs/agents/coding-standards.md) | Writing code: style rules, client API contract, OAuth/token rules, test conventions |
| [integration-credentials](docs/agents/integration-credentials.md) | Running live-API tests: `SOUNDCLOUD_*` env vars, `.sc_refresh_token`, the semi-interactive exchange |
| [verification](docs/agents/verification.md) | The exact pre-done checklist and what CI enforces |
| [do-not-touch](docs/agents/do-not-touch.md) | `.DS_Store`, caches, `uv.lock` — what stays untouched |
