import urllib.parse
from unittest import mock

import pytest

import soundcloud
from soundcloud.tests.utils import MockResponse


def test_kwargs_parsing_valid():
    """Test that valid kwargs are stored as properties on the client."""
    client = soundcloud.Client(client_id='foo', client_secret='foo')
    assert isinstance(client, soundcloud.Client)
    assert client.client_id == 'foo'
    client = soundcloud.Client(client_id='foo', client_secret='bar',
                               access_token='baz', username='you',
                               password='secret', redirect_uri='https://example.com/callback')
    assert client.client_id == 'foo'
    assert client.access_token == 'baz'


def test_kwargs_parsing_invalid():
    """Test that unknown kwargs are ignored."""
    client = soundcloud.Client(foo='bar', client_id='bar')
    with pytest.raises(AttributeError):
        client.foo


def test_url_creation():
    """Test that resources are turned into urls properly."""
    client = soundcloud.Client(client_id='foo')
    url = client._resolve_resource_name('tracks')
    assert url == 'https://api.soundcloud.com/tracks'
    url = client._resolve_resource_name('/tracks/')
    assert url == 'https://api.soundcloud.com/tracks'


def test_url_creation_options():
    """Test that resource resolving works with different options."""
    client = soundcloud.Client(client_id='foo', use_ssl=False)
    client.host = 'soundcloud.dev'
    url = client._resolve_resource_name('apps/132445')
    assert url == 'http://soundcloud.dev/apps/132445'


def test_method_dispatching():
    """Test that getattr is doing right by us."""
    client = soundcloud.Client(client_id='foo')
    for method in ('get', 'post', 'put', 'delete', 'head'):
        p = getattr(client, method)
        assert p.args == (method,)
        assert p.func.__name__ == '_request'


def test_host_config():
    """We should be able to set the host on the client."""
    client = soundcloud.Client(client_id='foo', host='api.soundcloud.dev')
    assert client.host == 'api.soundcloud.dev'
    client = soundcloud.Client(client_id='foo')
    assert client.host == 'api.soundcloud.com'


@mock.patch('requests.get')
def test_disabling_ssl_verification(mock_get):
    """We should be able to disable ssl verification when we are in dev mode"""
    client = soundcloud.Client(client_id='foo', host='api.soundcloud.dev',
                               verify_ssl=False)
    expected_url = '%s?%s' % (
        client._resolve_resource_name('tracks'),
        urllib.parse.urlencode({
            'limit': 5,
            'client_id': 'foo'
        }))
    headers = {
        'User-Agent': soundcloud.USER_AGENT,
        'Accept': 'application/json'
    }
    mock_get.return_value = MockResponse("{}")
    
    client.get('tracks', limit=5)
    
    mock_get.assert_called_with(expected_url,
                                headers=headers,
                                verify=False,
                                allow_redirects=True)


def test_method_dispatching_invalid_method():
    """Test that getattr raises an attributeerror if we give it garbage."""
    client = soundcloud.Client(client_id='foo')
    with pytest.raises(AttributeError):
        client.foo()


@mock.patch('requests.get')
def test_method_dispatching_get_request_readonly(mock_get):
    """Test that calling client.get() results in a proper call
    to the get function in the requests module with the provided
    kwargs as the querystring.
    """
    client = soundcloud.Client(client_id='foo')
    expected_url = '%s?%s' % (
        client._resolve_resource_name('tracks'),
        urllib.parse.urlencode({
            'limit': 5,
            'client_id': 'foo'
        }))
    headers = {
        'User-Agent': soundcloud.USER_AGENT,
        'Accept': 'application/json'
    }
    mock_get.return_value = MockResponse("{}")
    
    client.get('tracks', limit=5)
    
    mock_get.assert_called_with(expected_url, headers=headers, allow_redirects=True)


@mock.patch('requests.post')
def test_method_dispatching_post_request(mock_post):
    """Test that calling client.post() results in a proper call
    to the post function in the requests module.

    TODO: Revise once read/write support has been added.
    """
    client = soundcloud.Client(client_id='foo')
    expected_url = client._resolve_resource_name('tracks')
    data = {
        'client_id': 'foo'
    }
    headers = {
        'User-Agent': soundcloud.USER_AGENT
    }
    mock_post.return_value = MockResponse("{}")
    
    client.post('tracks')
    
    mock_post.assert_called_with(expected_url,
                                 data=data,
                                 headers=headers,
                                 allow_redirects=True)


@mock.patch('requests.get')
def test_proxy_servers(mock_get):
    """Test that providing a dictionary of proxy servers works."""
    proxies = {
        'http': 'myproxyserver:1234'
    }
    client = soundcloud.Client(client_id='foo', proxies=proxies)
    expected_url = "%s?%s" % (
        client._resolve_resource_name('me'),
        urllib.parse.urlencode({
            'client_id': 'foo'
        })
    )
    headers = {
        'User-Agent': soundcloud.USER_AGENT,
        'Accept': 'application/json'
    }
    mock_get.return_value = MockResponse("{}")
    
    client.get('/me')
    
    mock_get.assert_called_with(expected_url,
                                headers=headers,
                                proxies=proxies,
                                allow_redirects=True)
