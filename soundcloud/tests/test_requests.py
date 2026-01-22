from contextlib import contextmanager
from unittest import mock

import pytest
import requests

import soundcloud
from soundcloud.tests.utils import MockResponse


class MockRaw:
    """Simple mock for the raw response in requests model."""
    def __init__(self):
        self.reason = "foo"


@contextmanager
def response_status(mock_http_request, status):
    response = MockResponse('{}', status_code=status)
    response.raw = MockRaw()
    mock_http_request.return_value = response
    yield


@mock.patch('requests.get')
def test_bad_responses(mock_get):
    """Anything in the 400 or 500 range should raise an exception."""
    client = soundcloud.Client(client_id='foo', client_secret='foo')

    for status in range(400, 423):
        with response_status(mock_get, status):
            with pytest.raises(requests.exceptions.HTTPError):
                client.get('/me')
                
    for status in (500, 501, 502, 503, 504, 505):
        with response_status(mock_get, status):
            with pytest.raises(requests.exceptions.HTTPError):
                client.get('/me')


@mock.patch('requests.get')
def test_ok_response(mock_get):
    """A 200 range response should be fine."""
    client = soundcloud.Client(client_id='foo', client_secret='foo')
    for status in (200, 201, 202, 203, 204, 205, 206):
        with response_status(mock_get, status):
            client.get('/me')

