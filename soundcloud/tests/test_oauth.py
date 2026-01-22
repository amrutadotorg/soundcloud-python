import base64
import hashlib
from contextlib import contextmanager
from unittest import mock

import pytest

import soundcloud
from soundcloud.tests.utils import MockResponse

# Fixed test values for PKCE
MOCK_VERIFIER = "test-verifier-1234567890-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def get_mock_challenge(verifier):
    """Helper function to calculate expected challenge in tests."""
    sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
    return (
        base64.urlsafe_b64encode(sha256_hash)
        .decode("ascii")
        .rstrip("=")
    )


@contextmanager
def non_expiring_token_response(mock_post):
    response = MockResponse(
        '{"access_token":"access-1234","scope":"non-expiring"}'
    )
    mock_post.return_value = response
    yield


@contextmanager
def expiring_token_response(mock_post):
    response = MockResponse(
        '{"access_token":"access-1234","expires_in":12345,"scope":"*",'
        '"refresh_token":"refresh-1234"}'
    )
    mock_post.return_value = response
    yield


@contextmanager
def refresh_token_response_with_rotation(mock_post):
    """OAuth 2.1: Refresh token rotation - new refresh token returned."""
    response = MockResponse(
        '{"access_token":"access-2345","expires_in":21599,"scope":"*",'
        '"refresh_token":"refresh-2345"}'
    )
    mock_post.return_value = response
    yield


@mock.patch("secrets.token_urlsafe")
def test_authorize_url_construction(mock_secrets):
    """Test dynamic authorization URL generation with PKCE parameters."""
    mock_secrets.return_value = MOCK_VERIFIER

    client = soundcloud.Client(
        client_id="foo",
        client_secret="bar",
        redirect_uri="https://example.com/callback",
    )

    expected_challenge = get_mock_challenge(MOCK_VERIFIER)
    auth_url = client.authorize_url()

    assert auth_url.startswith("https://secure.soundcloud.com/authorize?")
    assert f"code_challenge={expected_challenge}" in auth_url
    assert "code_challenge_method=S256" in auth_url
    assert "client_id=foo" in auth_url
    assert "response_type=code" in auth_url
    assert "redirect_uri=" in auth_url


@mock.patch("secrets.token_urlsafe")
def test_code_verifier_length_validation(mock_secrets):
    """Test that code_verifier meets RFC 7636 length requirements (43-128 chars)."""
    mock_secrets.return_value = MOCK_VERIFIER

    client = soundcloud.Client(
        client_id="foo",
        client_secret="bar",
        redirect_uri="https://example.com/callback",
    )

    assert client.MIN_VERIFIER_LENGTH <= len(client.code_verifier) <= client.MAX_VERIFIER_LENGTH


@mock.patch("secrets.token_urlsafe")
@mock.patch("requests.post")
def test_exchange_code_non_expiring(mock_post, mock_secrets):
    """Test code exchange for non-expiring token with code_verifier."""
    # Note: Decorators are applied bottom-up, so arguments are injected (mock_post, mock_secrets)
    mock_secrets.return_value = MOCK_VERIFIER

    with non_expiring_token_response(mock_post):
        client = soundcloud.Client(
            client_id="foo",
            client_secret="bar",
            redirect_uri="https://example.com/callback",
        )

        verifier_before = client.code_verifier
        assert verifier_before is not None

        token = client.exchange_token("this-is-a-code")

        assert token.access_token == "access-1234"
        assert token.scope == "non-expiring"
        assert client.access_token == "access-1234"

        # OAuth 2.1 best practice: Verifier should be cleared after use
        assert client.code_verifier is None


@mock.patch("secrets.token_urlsafe")
@mock.patch("requests.post")
def test_exchange_code_expiring(mock_post, mock_secrets):
    """Test full flow with expiring token and PKCE."""
    mock_secrets.return_value = MOCK_VERIFIER

    with expiring_token_response(mock_post):
        client = soundcloud.Client(
            client_id="foo",
            client_secret="bar",
            redirect_uri="https://example.com/callback",
            scope="*",
        )

        expected_challenge = get_mock_challenge(MOCK_VERIFIER)
        auth_url = client.authorize_url()

        assert f"code_challenge={expected_challenge}" in auth_url
        # Check for encoded or unencoded scope
        assert "scope=%2A" in auth_url or "scope=*" in auth_url

        token = client.exchange_token("this-is-a-code")
        assert token.access_token == "access-1234"
        assert token.refresh_token == "refresh-1234"


@mock.patch("secrets.token_urlsafe")
@mock.patch("requests.post")
def test_refresh_token_flow_with_rotation(mock_post, mock_secrets):
    """
    Test refresh token flow with token rotation.
    OAuth 2.1: Refresh tokens should be rotated when refreshed.
    """
    mock_secrets.return_value = MOCK_VERIFIER

    with refresh_token_response_with_rotation(mock_post):
        client = soundcloud.Client(
            client_id="foo",
            client_secret="bar",
            refresh_token="refresh-1234",
        )

        assert client.token.access_token == "access-2345"
        assert client.options["refresh_token"] == "refresh-2345"
        assert client.code_verifier is None

@mock.patch("secrets.token_urlsafe")
@mock.patch("requests.post")  # <--- DODANO: Mockowanie zapytań HTTP
def test_refresh_token_without_verifier(mock_post, mock_secrets):
    """Test that refresh token flow does NOT use code_verifier."""
    mock_secrets.return_value = MOCK_VERIFIER

    # Używamy pomocniczej funkcji, aby zwrócić poprawną odpowiedź (status 200 OK)
    # dzięki temu konstruktor Client zakończy się sukcesem
    with refresh_token_response_with_rotation(mock_post):
        client = soundcloud.Client(
            client_id="foo",
            client_secret="bar",
            refresh_token="refresh-token",
        )

    assert client.code_verifier is None


def test_password_credentials_flow_deprecated():
    """
    OAuth 2.1: Resource Owner Password Credentials flow is removed.
    """
    with pytest.raises(DeprecationWarning):
        soundcloud.Client(
            client_id="foo",
            client_secret="bar",
            username="user",
            password="pass",
        )


@mock.patch("secrets.token_urlsafe")
def test_redirect_uri_https_validation(mock_secrets):
    """
    OAuth 2.1: Non-loopback redirect URIs must use HTTPS.
    """
    mock_secrets.return_value = MOCK_VERIFIER

    client = soundcloud.Client(
        client_id="foo",
        redirect_uri="https://example.com/callback",
    )
    assert client.authorize_url() is not None

    client_loopback = soundcloud.Client(
        client_id="foo",
        redirect_uri="http://localhost:8080/callback",
    )
    assert client_loopback.authorize_url() is not None

    with pytest.raises(ValueError):
        client_http = soundcloud.Client(
            client_id="foo",
            redirect_uri="http://example.com/callback",
        )
        client_http._redirect_uri()


@mock.patch("secrets.token_urlsafe")
def test_missing_redirect_uri_error(mock_secrets):
    """Test that missing redirect_uri raises appropriate error."""
    mock_secrets.return_value = MOCK_VERIFIER

    with pytest.raises(ValueError):
        client = soundcloud.Client(client_id="foo")
        client._redirect_uri()


@mock.patch("secrets.token_urlsafe")
def test_code_challenge_generation(mock_secrets):
    """Test S256 code challenge generation."""
    mock_secrets.return_value = MOCK_VERIFIER

    client = soundcloud.Client(
        client_id="foo",
        redirect_uri="https://example.com/callback",
    )

    expected_challenge = get_mock_challenge(MOCK_VERIFIER)
    actual_challenge = client._generate_code_challenge(MOCK_VERIFIER)

    assert expected_challenge == actual_challenge
    assert "=" not in actual_challenge


def test_exchange_without_verifier_raises_error():
    """Test that exchanging code without verifier raises error."""
    client = soundcloud.Client(
        client_id="foo",
        client_secret="bar",
        access_token="existing-token",
    )

    # Forcefully unset verifier to simulate invalid state
    client.code_verifier = None

    with pytest.raises(ValueError):
        client.exchange_token("some-code")


@mock.patch("secrets.token_urlsafe")
def test_state_parameter_inclusion(mock_secrets):
    """Test optional state parameter for CSRF protection."""
    mock_secrets.return_value = MOCK_VERIFIER

    client = soundcloud.Client(
        client_id="foo",
        redirect_uri="https://example.com/callback",
        state="random-state-value",
    )

    auth_url = client.authorize_url()
    assert "state=random-state-value" in auth_url


@mock.patch("secrets.token_urlsafe")
def test_client_secret_optional_for_public_clients(mock_secrets):
    """
    OAuth 2.1: Public clients don't have secrets but still use PKCE.
    """
    mock_secrets.return_value = MOCK_VERIFIER

    client = soundcloud.Client(
        client_id="foo",
        redirect_uri="https://example.com/callback",
    )

    assert client.authorize_url() is not None
    assert client.code_verifier == MOCK_VERIFIER


@mock.patch("secrets.token_urlsafe")
@mock.patch("requests.post")
def test_confidential_client_includes_secret(mock_post, mock_secrets):
    """
    OAuth 2.1: Confidential clients must authenticate.
    """
    mock_secrets.return_value = MOCK_VERIFIER

    with non_expiring_token_response(mock_post):
        client = soundcloud.Client(
            client_id="foo",
            client_secret="bar",
            redirect_uri="https://example.com/callback",
        )

        token = client.exchange_token("auth-code")
        assert token is not None
