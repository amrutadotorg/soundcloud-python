"""Integration tests against the live SoundCloud API (opt-in).

These tests are skipped unless credentials are provided via env vars; nothing
is committed. SoundCloud now treats all clients as confidential: public
resources require the ``client_credentials`` flow, user resources require a
user OAuth session (``SOUNDCLOUD_REFRESH_TOKEN``).

Refresh tokens are single-use (rotation), so user-token tests persist the
rotated token to ``.sc_refresh_token`` in the repo root (gitignored) and read
it back on the next run.

Run with::

    SOUNDCLOUD_CLIENT_ID=... SOUNDCLOUD_CLIENT_SECRET=... uv run pytest -m integration -v -s

``test_exchange_token`` is semi-interactive: it prints the authorization URL —
open it in a browser, approve, and paste the code from the redirect URL.
"""

import os
from pathlib import Path
from unittest import mock

import pytest

import soundcloud
from soundcloud.resource import Resource, ResourceList

REPO_ROOT = Path(__file__).resolve().parents[2]
REFRESH_TOKEN_FILE = REPO_ROOT / ".sc_refresh_token"
VERIFIER_MIN = 43
VERIFIER_MAX = 128

_input_refresh_token: str | None = None


def _items(resource) -> list:
    """Return the list of items whether the API answered a bare array or
    a ``{"collection": [...]}`` object."""
    if isinstance(resource, ResourceList):
        return list(resource)
    if isinstance(resource, Resource):
        collection = getattr(resource, "collection", None)
        if isinstance(collection, (ResourceList, list)):
            return list(collection)
    return []


@pytest.fixture(scope="session")
def client_id():
    client_id = os.environ.get("SOUNDCLOUD_CLIENT_ID")
    if not client_id:
        pytest.skip("SOUNDCLOUD_CLIENT_ID not set")
    return client_id


@pytest.fixture(scope="session")
def client_secret():
    client_secret = os.environ.get("SOUNDCLOUD_CLIENT_SECRET")
    if not client_secret:
        pytest.skip("SOUNDCLOUD_CLIENT_SECRET not set")
    return client_secret


@pytest.fixture()
def redirect_uri():
    redirect_uri = os.environ.get("SOUNDCLOUD_REDIRECT_URI")
    if not redirect_uri:
        pytest.skip("SOUNDCLOUD_REDIRECT_URI not set")
    return redirect_uri


def _stored_refresh_token():
    if REFRESH_TOKEN_FILE.exists():
        return REFRESH_TOKEN_FILE.read_text().strip()
    return None


def _store_refresh_token(refresh_token):
    if refresh_token:
        REFRESH_TOKEN_FILE.write_text(refresh_token)


@pytest.fixture(scope="session")
def user_client(client_id, client_secret):
    """A client with a valid user access token; refreshes once per run."""
    global _input_refresh_token
    _input_refresh_token = (
        os.environ.get("SOUNDCLOUD_REFRESH_TOKEN") or _stored_refresh_token()
    )
    if not _input_refresh_token:
        pytest.skip(
            "SOUNDCLOUD_REFRESH_TOKEN not set (see output of test_exchange_token)"
        )
    client = soundcloud.Client(
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=_input_refresh_token,
    )
    _store_refresh_token(client.options["refresh_token"])
    return client


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
def test_authorize_url_pkce(client_id, redirect_uri):
    """The real client builds an authorize URL with PKCE parameters."""
    client = _new_client(client_id, redirect_uri=redirect_uri)
    url = client.authorize_url()
    assert url is not None
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "response_type=code" in url


@pytest.mark.integration
def test_client_credentials_public_resources(client_id, client_secret):
    """Public resources (search/playback/resolve) work with an app token."""
    client = soundcloud.Client(client_id=client_id, client_secret=client_secret)
    app_token = client.client_credentials_token()
    assert app_token.access_token
    assert client.options["refresh_token"]

    tracks = client.get("/tracks", limit=3)
    assert len(_items(tracks)) <= 3
    for track in _items(tracks):
        assert track.id
        assert track.title

    permalink = os.environ.get("SOUNDCLOUD_USER_PERMALINK", "nirmala-vidya-portal")
    user = client.get("/resolve", url=f"https://soundcloud.com/{permalink}")
    assert user.id
    assert user.permalink == permalink


@pytest.mark.integration
def test_exchange_token(client_id, client_secret, redirect_uri):
    """Full PKCE exchange. Semi-interactive: approve in the browser, paste code.

    To make the flow repeatable, set ``SOUNDCLOUD_VERIFIER`` before generating
    the URL, then reuse it (with the captured ``SOUNDCLOUD_AUTH_CODE``) on the
    next run — the code is bound to the verifier.
    """
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
        except EOFError, OSError:
            pytest.skip("No interactive terminal and SOUNDCLOUD_AUTH_CODE not set")

    token = client.exchange_token(code)
    assert token.access_token
    assert client.access_token == token.access_token
    refresh_token = getattr(token, "refresh_token", None)
    if refresh_token:
        _store_refresh_token(refresh_token)
        print(f"\nRefresh token stored in {REFRESH_TOKEN_FILE.name}")


@pytest.mark.integration
def test_refresh_token_flow(user_client):
    """The session client refreshed once per run; the rotated token is kept."""
    assert user_client.access_token
    assert user_client.token is not None
    assert user_client.token.access_token == user_client.access_token
    rotated = user_client.options["refresh_token"]
    assert rotated
    assert rotated != _input_refresh_token
    assert _stored_refresh_token() == rotated


@pytest.mark.integration
def test_me_endpoint(user_client):
    """The authenticated /me endpoint returns the user profile."""
    me = user_client.get("/me")
    assert me.id
    assert me.username
    assert me.permalink == os.environ.get(
        "SOUNDCLOUD_USER_PERMALINK", "nirmala-vidya-portal"
    )


@pytest.mark.integration
def test_user_tracks_and_playlists(user_client):
    """User tracks and playlists are wrapped correctly (bare arrays too)."""
    me = user_client.get("/me")
    tracks = user_client.get(f"/users/{me.id}/tracks", limit=3)
    assert len(_items(tracks)) <= 3
    for track in _items(tracks):
        assert track.id
        assert track.title

    playlists = _items(user_client.get("/me/playlists", limit=5))
    assert len(playlists) >= 1
    playlist = user_client.get(f"/playlists/{playlists[0].id}")
    assert playlist.id == playlists[0].id
    assert playlist.title
