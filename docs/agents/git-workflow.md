# Git Workflow — soundcloud-python

- Work directly on `master`
- Commit messages follow the repo's actual practice (131-commit history): `feat:`, `fix:`, `refactor:`, `test:`, `chore:`, `release:` — the previously documented `client:`/`resource:` prefixes were never used and are dropped
- Always `git pull --rebase origin master` before pushing
- Push directly: `git push origin master`

CI runs on every push/PR — see [verification](verification.md).
