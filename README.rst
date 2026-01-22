=================
soundcloud-python
=================

⚠️ Community-maintained fork

This repository is a modernized fork of the original *soundcloud-python*
library, which has been deprecated for many years.

This fork adds support for **SoundCloud API v2**, **OAuth 2.1**, and **PKCE**
(Proof Key for Code Exchange), and is compatible with modern Python versions.

.. image:: https://github.com/amrutadotorg/soundcloud-python/actions/workflows/tests.yml/badge.svg
    :target: https://github.com/amrutadotorg/soundcloud-python/actions/workflows/tests.yml

Overview
--------

A friendly Python wrapper around the SoundCloud API, designed for
modern authentication flows and current API requirements.

This project is **not affiliated with SoundCloud Ltd.**

Requirements
------------

- Python 3.8+
- requests
- pytest (for running tests)

Installation
------------

Until an official PyPI release is published, install directly from GitHub: ::

    pip install git+https://github.com/amrutadotorg/soundcloud-python.git

Basic Usage
-----------

To use *soundcloud-python*, first create a ``Client`` instance.

If you only need access to public resources, a ``client_id`` is sufficient: ::

    import soundcloud

    client = soundcloud.Client(client_id=YOUR_CLIENT_ID)

    tracks = client.get('/tracks', limit=10)
    for track in tracks.collection:
        print(track.title)

Authentication
--------------

This fork supports **OAuth 2.1** with **PKCE** (Proof Key for Code Exchange).

Authorization Code Flow (PKCE)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Initialize the client with your credentials and redirect URI.
   A ``code_verifier`` is generated automatically: ::

    import soundcloud

    client = soundcloud.Client(
        client_id=YOUR_CLIENT_ID,
        client_secret=YOUR_CLIENT_SECRET,  # Optional for public clients
        redirect_uri='https://yourapp.com/callback'
    )

    print(client.authorize_url())

2. After the user authorizes your app and is redirected back,
   exchange the authorization ``code`` for an access token: ::

    token = client.exchange_token(code=AUTHORIZATION_CODE)
    print(token.access_token)

    me = client.get('/me')
    print(me.username)

Refresh Token Flow
~~~~~~~~~~~~~~~~~

If you already have a refresh token, you can use it to obtain
a new access token: ::

    client = soundcloud.Client(
        client_id=YOUR_CLIENT_ID,
        client_secret=YOUR_CLIENT_SECRET,
        refresh_token=YOUR_REFRESH_TOKEN
    )

    # The token is refreshed automatically on initialization

Deprecated Flows
~~~~~~~~~~~~~~~

The **User Credentials Flow** (password-based authentication) is deprecated
in OAuth 2.1 and will raise a ``DeprecationWarning``.

Use the Authorization Code Flow with PKCE instead.

Examples
--------

Resolve a track and print its ID: ::

    import soundcloud

    client = soundcloud.Client(client_id=YOUR_CLIENT_ID)

    track = client.get(
        '/resolve',
        url='https://soundcloud.com/forss/flickermood'
    )

    print(track.id)

Upload a track: ::

    import soundcloud

    client = soundcloud.Client(access_token="VALID_ACCESS_TOKEN")

    track = client.post('/tracks', track={
        'title': 'Sample Track',
        'sharing': 'private',
        'asset_data': open('mytrack.mp4', 'rb')
    })

    print(track.title)

Update your profile description: ::

    import soundcloud

    client = soundcloud.Client(access_token="VALID_ACCESS_TOKEN")

    client.put('/me', user={
        'description': "A new profile description"
    })

Proxy Support
-------------

If you are behind a proxy, you can specify it when creating a client: ::

    import soundcloud

    proxies = {
        'http': 'example.com:8000',
        'https': 'example.com:8000',
    }

    client = soundcloud.Client(
        access_token="VALID_ACCESS_TOKEN",
        proxies=proxies
    )

Redirect Handling
-----------------

By default, HTTP 301 and 302 redirects are followed for idempotent methods.
You can disable this behavior if needed: ::

    import soundcloud

    client = soundcloud.Client(access_token="VALID_ACCESS_TOKEN")

    response = client.get(
        '/tracks/293/stream',
        allow_redirects=False
    )

    print(response.location)

Running Tests
-------------

Tests are written using **pytest**.

To run them locally: ::

    pip install -r requirements.txt
    pytest

Contributing
------------

Contributions are welcome!

- Please submit issues on GitHub
- Fork the repository and open pull requests

License
-------

This project is published under the **BSD License**.

.. _SoundCloud API: https://developers.soundcloud.com/
.. _submit issues: https://github.com/amrutadotorg/soundcloud-python/issues
.. _fork the repository: https://github.com/amrutadotorg/soundcloud-python
.. _BSD License: https://github.com/amrutadotorg/soundcloud-python/blob/master/LICENSE
