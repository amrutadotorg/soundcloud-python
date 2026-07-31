"""Integration tests against the live SoundCloud API (opt-in).

These tests are skipped unless the ``SOUNDCLOUD_CLIENT_ID`` environment
variable is set. Credentials must never be committed; pass them via env::

    SOUNDCLOUD_CLIENT_ID=... uv run pytest -m integration -v

The ``test_exchange_token`` test is semi-interactive: it prints the
authorization URL, which you open in a browser and approve, then pastes the
code from the redirect URL back into the terminal (run with ``-s``).
"""

import os
from unittest import mock

import pytest

import soundcloud

VERIFIER_MIN = 43
VERIFIER_MAX = 128


@pytest.fixture()
def client_id():
    client_id = os.environ.get("SOUNDCLOUD_CLIENT_ID")
    if not client_id:
        pytest.skip("SOUNDCLOUD_CLIENT_ID not set")
    return client_id


@pytest.fixture()
def client_secret():
    return os.environ.get("SOUNDCLOUD_CLIENT_SECRET")


@pytest.fixture()
def redirect_uri():
    redirect_uri = os.environ.get("SOUNDCLOUD_REDIRECT_URI")
    if not redirect_uri:
        pytest.skip("SOUNDCLOUD_REDIRECT_URI not set")
    return redirect_uri


def _new_client(client_id, **kwargs):
    """Build a client, optionally pinning the PKCE verifier via env."""
    verifier = os.environ.get("SOUNDCLOUD_VERIFIER")
    if verifier:
        if not (VERIFIER_MIN <= len(verifier) <= VERIFIER_MAX):
            pytest.skip(
                f"SOUNDCLOUD_VERIFIER must be {VERIFIER_MIN}-{VERIFIER_MAX} chars"
            )
        with mock.patch("secrets.token_urlsafe", return_value=verifier):
            return soundcloud.Client(client_id=client_id, **kwargs)
    return soundcloud.Client(client_id=client_id, **kwargs)


@pytest.mark.integration
def test_public_tracks(client_id):
    """A plain public listing is wrapped and returns track data."""
    tracks = _new_client(client_id).get("/tracks", limit=3)
    assert len(tracks.collection) <= 3
    for track in tracks.collection:
        assert track.id
        assert track.title


@pytest.mark.integration
def test_limit_param_applied(client_id):
    """The limit query param is actually sent and honored by the API."""
    tracks = _new_client(client_id).get("/tracks", limit=2)
    assert len(tracks.collection) == 2


@pytest.mark.integration
def test_user_tracks_by_permalink(client_id):
    """Resolve a profile permalink, then fetch that user's tracks."""
    permalink = os.environ.get("SOUNDCLOUD_USER_PERMALINK", "nirmala-vidya-portal")
    client = _new_client(client_id)
    user = client.get("/resolve", url=f"https://soundcloud.com/{permalink}")
    assert user.id
    tracks = client.get(f"/users/{user.id}/tracks", limit=3)
    assert len(tracks.collection) <= 3
    for track in tracks.collection:
        assert track.id


@pytest.mark.integration
def test_authorize_url_pkce(client_id, redirect_uri):
    """The real client builds an authorize URL with PKCE parameters."""
    client = _new_client(client_id, redirect_uri=redirect_uri)
    url = client.authorize_url()
    assert url is not None
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "response_type=code" in url


@pytest.mark.integration
def test_exchange_token(client_id, client_secret, redirect_uri):
    """Full PKCE exchange. Semi-interactive: approve in the browser, paste code.

    To make the flow repeatable, set ``SOUNDCLOUD_VERIFIER`` before generating
    the URL, then reuse it (with the captured ``SOUNDCLOUD_AUTH_CODE``) on the
    next run — the code is bound to the verifier.
    """
    if not client_secret:
        pytest.skip("SOUNDCLOUD_CLIENT_SECRET not set")
    client = _new_client(
        client_id, client_secret=client_secret, redirect_uri=redirect_uri
    )
    url = client.authorize_url()
    assert url is not None
    print(f"\n1. Open and approve: {url}")
    print("2. Copy the 'code' parameter from the redirect URL.")
    code = os.environ.get("SOUNDCLOUD_AUTH_CODE")
    if not code:
        try:
            code = input("3. Paste the authorization code: ").strip()
        except EOFError:
            pytest.skip("No interactive terminal and SOUNDCLOUD_AUTH_CODE not set")

    token = client.exchange_token(code)
    assert token.access_token
    assert client.access_token == token.access_token
    refresh_token = getattr(token, "refresh_token", None)
    if refresh_token:
        print(f"\nRefresh token (export as SOUNDCLOUD_REFRESH_TOKEN): {refresh_token}")


@pytest.mark.integration
def test_refresh_token_flow(client_id, client_secret):
    """Token refresh against the live API (no browser needed)."""
    if not client_secret:
        pytest.skip("SOUNDCLOUD_CLIENT_SECRET not set")
    refresh_token = os.environ.get("SOUNDCLOUD_REFRESH_TOKEN")
    if not refresh_token:
        pytest.skip(
            "SOUNDCLOUD_REFRESH_TOKEN not set (see output of test_exchange_token)"
        )
    client = _new_client(
        client_id, client_secret=client_secret, refresh_token=refresh_token
    )
    assert client.access_token
    assert client.token is not None
    assert client.token.access_token == client.access_token
