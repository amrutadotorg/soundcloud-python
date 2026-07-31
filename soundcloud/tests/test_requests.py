from contextlib import contextmanager
from unittest import mock

import pytest
import requests

import soundcloud
from soundcloud.request import _extract_transport_kwargs, make_request
from soundcloud.tests.utils import MockResponse


class MockRaw:
    """Simple mock for the raw response in requests model."""

    def __init__(self):
        self.reason = "foo"


@contextmanager
def response_status(mock_http_request, status):
    response = MockResponse("{}", status_code=status)
    response.raw = MockRaw()
    mock_http_request.return_value = response
    yield


@mock.patch("requests.get")
def test_bad_responses(mock_get):
    """Anything in the 400 or 500 range should raise an exception."""
    client = soundcloud.Client(client_id="foo", client_secret="foo")

    for status in range(400, 423):
        with (
            response_status(mock_get, status),
            pytest.raises(requests.exceptions.HTTPError),
        ):
            client.get("/me")

    for status in (500, 501, 502, 503, 504, 505):
        with (
            response_status(mock_get, status),
            pytest.raises(requests.exceptions.HTTPError),
        ):
            client.get("/me")


@mock.patch("requests.get")
def test_ok_response(mock_get):
    """A 200 range response should be fine."""
    client = soundcloud.Client(client_id="foo", client_secret="foo")
    for status in (200, 201, 202, 203, 204, 205, 206):
        with response_status(mock_get, status):
            client.get("/me")


def test_make_request_does_not_mutate_params():
    """make_request must leave the caller's params dict untouched."""
    params = {
        "client_id": "foo",
        "limit": 5,
        "verify_ssl": True,
        "proxies": None,
    }
    with mock.patch("requests.get") as mock_get:
        mock_get.return_value = MockResponse("{}")
        make_request("get", "https://api.soundcloud.com/tracks", params)

    assert params == {
        "client_id": "foo",
        "limit": 5,
        "verify_ssl": True,
        "proxies": None,
    }


def test_extract_transport_kwargs_pure():
    """Transport/auth options are split off without touching the input."""
    params = {
        "client_id": "foo",
        "verify_ssl": False,
        "proxies": {"http": "proxy:1234"},
        "allow_redirects": False,
        "oauth_token": "tok",
    }
    transport, remaining = _extract_transport_kwargs(params)

    assert transport == {
        "allow_redirects": False,
        "verify": False,
        "proxies": {"http": "proxy:1234"},
        "headers": {"Authorization": "Bearer tok"},
    }
    assert remaining == {"client_id": "foo"}
    assert params["oauth_token"] == "tok"


def test_extract_transport_kwargs_drops_empty_values():
    """None values are dropped; verify_ssl=True stays out of kwargs."""
    transport, remaining = _extract_transport_kwargs(
        {"client_id": "foo", "limit": None, "verify_ssl": True, "proxies": None}
    )

    assert transport == {"allow_redirects": True}
    assert remaining == {"client_id": "foo"}
