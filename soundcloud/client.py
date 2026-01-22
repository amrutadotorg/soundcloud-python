import base64
import hashlib
import secrets
from functools import partial

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

from soundcloud.request import make_request
from soundcloud.resource import wrapped_resource


class Client(object):
    """A client for interacting with Soundcloud resources (OAuth 2.1 / PKCE)."""

    use_ssl = True
    host = 'api.soundcloud.com'  # Host for API calls (tracks, users, etc.)
    auth_host = 'secure.soundcloud.com' # Host for OAuth handshake
    
    # OAuth 2.1 constants
    MIN_VERIFIER_LENGTH = 43  # RFC 7636: minimum 43 characters
    MAX_VERIFIER_LENGTH = 128  # RFC 7636: maximum 128 characters

    def __init__(self, **kwargs):
        self.use_ssl = kwargs.get('use_ssl', self.use_ssl)
        self.host = kwargs.get('host', self.host)
        self.scheme = self.use_ssl and 'https://' or 'http://'
        self.options = kwargs
        self._authorize_url = None

        self.client_id = kwargs.get('client_id')
        
        # PKCE: Generate code_verifier on startup (only for auth code flow)
        self.code_verifier = None

        if 'access_token' in kwargs:
            self.access_token = kwargs.get('access_token')
            return

        if 'client_id' not in kwargs:
            raise TypeError("At least a client_id must be provided.")

        if 'scope' in kwargs:
            self.scope = kwargs.get('scope')

        if self._options_for_authorization_code_flow_present():
            # Generate verifier only for authorization code flow
            self.code_verifier = self._generate_code_verifier()
            self._authorization_code_flow()
        elif self._options_for_credentials_flow_present():
            # OAuth 2.1 deprecates this flow - raise warning
            raise DeprecationWarning(
                "Resource Owner Password Credentials flow is deprecated in OAuth 2.1. "
                "Use Authorization Code flow with PKCE instead."
            )
        elif self._options_for_token_refresh_present():
            self._refresh_token_flow()

    def _generate_code_verifier(self):
        """
        Generate a cryptographically random string for PKCE.
        RFC 7636: 43-128 characters, unreserved characters [A-Z, a-z, 0-9, -, ., _, ~]
        """
        # secrets.token_urlsafe generates base64url-encoded random bytes
        # We use 96 bytes which gives us ~128 characters after encoding
        verifier = secrets.token_urlsafe(96)
        
        # Ensure it meets RFC 7636 length requirements
        if len(verifier) < self.MIN_VERIFIER_LENGTH:
            verifier = secrets.token_urlsafe(self.MIN_VERIFIER_LENGTH)
        elif len(verifier) > self.MAX_VERIFIER_LENGTH:
            verifier = verifier[:self.MAX_VERIFIER_LENGTH]
            
        return verifier

    def _generate_code_challenge(self, verifier):
        """
        Create code_challenge from verifier using S256 method.
        RFC 7636: BASE64URL(SHA256(ASCII(code_verifier)))
        """
        if not verifier:
            raise ValueError("code_verifier cannot be empty")
            
        sha256_hash = hashlib.sha256(verifier.encode('ascii')).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).decode('ascii').rstrip('=')
        return challenge

    def exchange_token(self, code):
        """
        Exchange authorization code for access token using PKCE.
        Endpoint: https://secure.soundcloud.com/oauth/token
        """
        if not self.code_verifier:
            raise ValueError(
                "code_verifier not found. Ensure authorization flow was initiated properly."
            )
            
        # UPDATED: Use secure.soundcloud.com for token exchange
        url = 'https://%s/oauth/token' % self.auth_host
        
        options = {
            'grant_type': 'authorization_code',
            'redirect_uri': self._redirect_uri(),
            'client_id': self.options.get('client_id'),
            'code': code,
            'code_verifier': self.code_verifier  # PKCE: Server validates this
        }
        
        # Client Secret is required for confidential clients
        client_secret = self.options.get('client_secret')
        if client_secret:
            options['client_secret'] = client_secret
            
        options.update({
            'verify_ssl': self.options.get('verify_ssl', True),
            'proxies': self.options.get('proxies', None)
        })
        
        self.token = wrapped_resource(
            make_request('post', url, options))
        self.access_token = self.token.access_token
        
        # Clear verifier after successful exchange (security best practice)
        self.code_verifier = None
        
        return self.token

    def authorize_url(self):
        """Return the authorization URL with PKCE parameters."""
        return self._authorize_url

    def _authorization_code_flow(self):
        """
        Build authorization URL with PKCE challenge.
        Endpoint: https://secure.soundcloud.com/authorize
        """
        if not self.code_verifier:
            raise ValueError("code_verifier must be generated before building authorize URL")
            
        code_challenge = self._generate_code_challenge(self.code_verifier)
        
        # UPDATED: Default scope is empty string per new API requirements
        # UPDATED: Endpoint is secure.soundcloud.com/authorize
        
        options = {
            'scope': getattr(self, 'scope', ''), 
            'client_id': self.options.get('client_id'),
            'response_type': 'code',
            'redirect_uri': self._redirect_uri(),
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        if 'state' in self.options:
            options['state'] = self.options.get('state')
            
        url = 'https://%s/authorize' % self.auth_host
        self._authorize_url = '%s?%s' % (url, urlencode(options))

    def _refresh_token_flow(self):
        """
        Refresh access token using refresh token.
        Endpoint: https://secure.soundcloud.com/oauth/token
        """
        # UPDATED: Use secure.soundcloud.com for token refresh
        url = 'https://%s/oauth/token' % self.auth_host
        
        options = {
            'grant_type': 'refresh_token',
            'client_id': self.options.get('client_id'),
            'refresh_token': self.options.get('refresh_token'),
        }
        
        client_secret = self.options.get('client_secret')
        if client_secret:
            options['client_secret'] = client_secret
            
        options.update({
            'verify_ssl': self.options.get('verify_ssl', True),
            'proxies': self.options.get('proxies', None)
        })
        
        self.token = wrapped_resource(
            make_request('post', url, options))
        self.access_token = self.token.access_token
        
        # Refresh Token Rotation
        if hasattr(self.token, 'refresh_token') and self.token.refresh_token:
            self.options['refresh_token'] = self.token.refresh_token

    def _credentials_flow(self):
        """
        DEPRECATED: Resource Owner Password Credentials Flow.
        """
        raise DeprecationWarning(
            "Resource Owner Password Credentials flow is deprecated in OAuth 2.1. "
            "Use Authorization Code flow with PKCE instead."
        )
    def _request(self, method, resource, **kwargs):
            """Make authenticated API requests."""
            url = self._resolve_resource_name(resource)

            # JEŚLI mamy token, używamy TYLKO tokena (Bearer)
            if hasattr(self, 'access_token') and self.access_token:
                kwargs.update(dict(oauth_token=self.access_token))
            # W przeciwnym razie (brak tokena), wysyłamy client_id (dla publicznych zasobów)
            elif hasattr(self, 'client_id'):
                kwargs.update(dict(client_id=self.client_id))

            kwargs.update({
                'verify_ssl': self.options.get('verify_ssl', True),
                'proxies': self.options.get('proxies', None)
            })
            return wrapped_resource(make_request(method, url, kwargs))


    def __getattr__(self, name, **kwargs):
        if name not in ('get', 'post', 'put', 'head', 'delete'):
            raise AttributeError
        return partial(self._request, name, **kwargs)

    def _resolve_resource_name(self, name):
        """Resolve resource name to full URL."""
        if name[:4] == 'http':
            return name
        name = name.rstrip('/').lstrip('/')
        return '%s%s/%s' % (self.scheme, self.host, name)

    def _redirect_uri(self):
        """Get redirect URI with exact matching (OAuth 2.1 requirement)."""
        redirect_uri = self.options.get(
            'redirect_uri',
            self.options.get('redirect_url', None))
            
        if not redirect_uri:
            raise ValueError("redirect_uri is required for authorization code flow")
            
        # OAuth 2.1: Validate HTTPS for non-loopback URIs
        if not redirect_uri.startswith(('https://', 'http://localhost', 'http://127.0.0.1')):
            raise ValueError(
                "OAuth 2.1 requires HTTPS for redirect URIs (except loopback)"
            )
            
        return redirect_uri

    def _options_present(self, options, kwargs):
        """Check if all required options are present."""
        return all(map(lambda k: k in kwargs, options))

    def _options_for_credentials_flow_present(self):
        """Check for deprecated password credentials flow."""
        required = ('client_id', 'client_secret', 'username', 'password')
        return self._options_present(required, self.options)

    def _options_for_authorization_code_flow_present(self):
        """Check for authorization code flow options."""
        required = ('client_id', 'redirect_uri')
        or_required = ('client_id', 'redirect_url')
        return (self._options_present(required, self.options) or
                self._options_present(or_required, self.options))

    def _options_for_token_refresh_present(self):
        """Check for refresh token flow options."""
        required = ('client_id', 'refresh_token')
        return self._options_present(required, self.options)
