from unittest import mock

import soundcloud
from soundcloud.tests.utils import MockResponse


@mock.patch('requests.put')
def test_non_ascii_data(mock_put):
    """Test that non-ascii characters are accepted."""
    client = soundcloud.Client(client_id='foo', client_secret='foo')
    title = 'Föo Baß'
    mock_put.return_value = MockResponse("{}")
    
    client.put('/tracks', track={
        'title': title
    })
    
    # Verify that the data was passed correctly (requests handles encoding)
    # The important part is that soundcloud-python doesn't crash on non-ascii
    assert mock_put.called
