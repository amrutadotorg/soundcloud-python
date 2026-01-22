import json

from soundcloud.resource import wrapped_resource, ResourceList, Resource
from soundcloud.tests.utils import MockResponse


def test_json_list():
    """Verify that a json list is wrapped in a ResourceList object."""
    resources = wrapped_resource(MockResponse(json.dumps([{'foo': 'bar'}]),
                                              encoding='utf-8'))
    assert isinstance(resources, ResourceList)
    assert len(resources) == 1
    assert resources[0].foo == 'bar'


def test_json_object():
    """Verify that a json object is wrapped in a Resource object."""
    resource = wrapped_resource(MockResponse(json.dumps({'foo': 'bar'}),
                                             encoding='utf-8'))
    assert isinstance(resource, Resource)
    assert resource.foo == 'bar'


def test_properties_copied():
    """Certain properties should be copied to the wrapped resource."""
    response = MockResponse(json.dumps({'foo': 'bar'}),
                            encoding='utf-8',
                            status_code=200,
                            reason='OK',
                            url='http://example.com')
    resource = wrapped_resource(response)
    assert resource.status_code == 200
    assert resource.reason == 'OK'
    assert resource.encoding == 'utf-8'
    assert resource.url == 'http://example.com'
