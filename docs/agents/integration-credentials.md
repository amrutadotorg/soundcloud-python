# Integration Test Credentials — soundcloud-python

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
