=================
soundcloud-python
=================

A friendly wrapper around the `Soundcloud API`_, updated for **OAuth 2.1 and PKCE**.

.. image:: https://travis-ci.org/soundcloud/soundcloud-python.svg
    :target: https://travis-ci.org/soundcloud/soundcloud-python

A friendly wrapper around the `Soundcloud API`_.

.. _Soundcloud API: http://developers.soundcloud.com/

Installation
------------

To install soundcloud-python, simply: ::

    pip install soundcloud

Or if you're not hip to the pip: ::

    easy_install soundcloud

Basic Use
---------

To use soundcloud-python, you must first create a `Client` instance,
passing at a minimum the client id you obtained when you `registered
your app`_: ::

    import soundcloud

    client = soundcloud.Client(client_id=YOUR_CLIENT_ID)

The client instance can then be used to fetch or modify resources: ::

    tracks = client.get('/tracks', limit=10)
    for track in tracks.collection:
        print track.title
    app = client.get('/apps/124')
    print app.permalink_url

.. _registered your app: http://soundcloud.com/you/apps/

Authentication
--------------

soundcloud-python supports **OAuth 2.1** with **PKCE** (Proof Key for Code Exchange).

If you only need read-only access to public resources, providing a client id is enough: ::

    import soundcloud

    client = soundcloud.Client(client_id=YOUR_CLIENT_ID)
    track = client.get('/tracks/30709985')
    print(track.title)

If you need to access private resources or modify a resource, use the **Authorization Code Flow with PKCE**.

**Authorization Code Flow (PKCE)**

1. Initialize the client with your credentials and a redirect URI. A ``code_verifier`` is automatically generated: ::

    import soundcloud

    client = soundcloud.Client(
        client_id=YOUR_CLIENT_ID,
        client_secret=YOUR_CLIENT_SECRET,  # Optional for public clients
        redirect_uri='https://yourapp.com/callback'
    )
    # Redirect the user to the authorization URL
    print(client.authorize_url())

2. After the user grants access and is redirected back to your URI, exchange the ``code`` for an access token: ::

    token = client.exchange_token(code=request.args.get('code'))
    print(token.access_token)
    print(client.get('/me').username)

**Refresh Token Flow**

If you have a refresh token, you can use it to obtain a new access token: ::

    client = soundcloud.Client(
        client_id=YOUR_CLIENT_ID,
        client_secret=YOUR_CLIENT_SECRET,
        refresh_token=YOUR_REFRESH_TOKEN
    )
    # The client will automatically refresh the token on initialization

**User Credentials Flow (DEPRECATED)**

The `User Credentials Flow` (password-based) is deprecated in OAuth 2.1 and will raise a ``DeprecationWarning``. It is recommended to use the Authorization Code Flow instead.

Examples
--------

Resolve a track and print its id: ::

    import soundcloud

    client = soundcloud.Client(client_id=YOUR_CLIENT_ID)

    track = client.get('/resolve', url='http://soundcloud.com/forss/flickermood')

    print track.id

Upload a track: ::

    import soundcloud

    client = soundcloud.Client(access_token="a valid access token")

    track = client.post('/tracks', track={
        'title': 'This is a sample track',
        'sharing': 'private',
        'asset_data': open('mytrack.mp4', 'rb')
    })

    print track.title

Start following a user: ::

    import soundcloud

    client = soundcloud.Client(access_token="a valid access token")
    user_id_to_follow = 123
    client.put('/me/followings/%d' % user_id_to_follow)

Update your profile description: ::

    import soundcloud

    client = soundcloud.Client(access_token="a valid access token")
    client.put('/me', user={
        'description': "a new description"
    })

Proxy Support
-------------

If you're behind a proxy, you can specify it when creating a client: ::

    import soundcloud

    proxies = {
        'http': 'example.com:8000'
    }
    client = soundcloud.Client(access_token="a valid access token",
                               proxies=proxies)

The proxies kwarg is a dictionary with protocols as keys and host:port as values.

Redirects
---------

By default, 301 or 302 redirects will be followed for idempotent methods. There are certain cases where you may want to disable this, for example: ::

    import soundcloud

    client = soundcloud.Client(access_token="a valid access token")
    track = client.get('/tracks/293/stream', allow_redirects=False)
    print track.location

Will print a tracks streaming URL. If ``allow_redirects`` was omitted, a binary stream would be returned instead.

Running Tests
-------------

Tests are written using `pytest`. To run them: ::

    $ pip install -r requirements.txt
    $ pytest

Contributing
------------

Contributions are awesome. You are most welcome to `submit issues`_,
or `fork the repository`_.

soundcloud-python is published under a `BSD License`_.

.. _`submit issues`: https://github.com/soundcloud/soundcloud-python/issues
.. _`fork the repository`: https://github.com/soundcloud/soundcloud-python
.. _`BSD License`: https://github.com/soundcloud/soundcloud-python/blob/master/README
