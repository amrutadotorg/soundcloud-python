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
    host = "api.soundcloud.com"
    auth_host = "secure.soundcloud.com"

    MIN_VERIFIER_LENGTH = 43
    MAX_VERIFIER_LENGTH = 128

    def __init__(self, **kwargs):
        self.use_ssl = kwargs.get("use_ssl", self.use_ssl)
        self.host = kwargs.get("host", self.host)
        self.scheme = self.use_ssl and "https://" or "http://"
        self.options = kwargs
        self._authorize_url = None

        # Zapisujemy client_id zawsze (potrzebne do testów i refresh flow)
        self.client_id = kwargs.get("client_id")

        self.code_verifier = None

        # Jeśli mamy access_token, przerywamy dalszą inicjalizację (nie robimy flow auth)
        if "access_token" in kwargs and kwargs.get("access_token"):
            self.access_token = kwargs.get("access_token")
            return

        if "client_id" not in kwargs:
            raise TypeError("At least a client_id must be provided.")

        if "scope" in kwargs:
            self.scope = kwargs.get("scope")

        if self._options_for_authorization_code_flow_present():
            self.code_verifier = self._generate_code_verifier()
            self._authorization_code_flow()
        elif self._options_for_credentials_flow_present():
            raise DeprecationWarning("Password flow is deprecated.")
        elif self._options_for_token_refresh_present():
            self._refresh_token_flow()

    def _generate_code_verifier(self):
        verifier = secrets.token_urlsafe(96)
        if len(verifier) < self.MIN_VERIFIER_LENGTH:
            verifier = secrets.token_urlsafe(self.MIN_VERIFIER_LENGTH)
        elif len(verifier) > self.MAX_VERIFIER_LENGTH:
            verifier = verifier[: self.MAX_VERIFIER_LENGTH]
        return verifier

    def _generate_code_challenge(self, verifier):
        if not verifier:
            raise ValueError("code_verifier cannot be empty")
        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

    def exchange_token(self, code):
        if not self.code_verifier:
            raise ValueError("code_verifier not found.")

        url = "https://%s/oauth/token" % self.auth_host
        options = {
            "grant_type": "authorization_code",
            "redirect_uri": self._redirect_uri(),
            "client_id": self.options.get("client_id"),
            "code": code,
            "code_verifier": self.code_verifier,
        }

        client_secret = self.options.get("client_secret")
        if client_secret:
            options["client_secret"] = client_secret

        options.update(
            {
                "verify_ssl": self.options.get("verify_ssl", True),
                "proxies": self.options.get("proxies", None),
            }
        )

        self.token = wrapped_resource(make_request("post", url, options))
        self.access_token = self.token.access_token
        self.code_verifier = None
        return self.token

    def authorize_url(self):
        return self._authorize_url

    def _authorization_code_flow(self):
        if not self.code_verifier:
            raise ValueError("code_verifier missing")

        code_challenge = self._generate_code_challenge(self.code_verifier)
        options = {
            "scope": getattr(self, "scope", ""),
            "client_id": self.options.get("client_id"),
            "response_type": "code",
            "redirect_uri": self._redirect_uri(),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if "state" in self.options:
            options["state"] = self.options.get("state")

        url = "https://%s/authorize" % self.auth_host
        self._authorize_url = "%s?%s" % (url, urlencode(options))

    def _refresh_token_flow(self):
        url = "https://%s/oauth/token" % self.auth_host
        options = {
            "grant_type": "refresh_token",
            "client_id": self.options.get("client_id"),
            "refresh_token": self.options.get("refresh_token"),
        }
        client_secret = self.options.get("client_secret")
        if client_secret:
            options["client_secret"] = client_secret

        options.update(
            {
                "verify_ssl": self.options.get("verify_ssl", True),
                "proxies": self.options.get("proxies", None),
            }
        )

        self.token = wrapped_resource(make_request("post", url, options))
        self.access_token = self.token.access_token
        if hasattr(self.token, "refresh_token") and self.token.refresh_token:
            self.options["refresh_token"] = self.token.refresh_token

    def _request(self, method, resource, **kwargs):
        url = self._resolve_resource_name(resource)

        # KLUCZOWA LOGIKA:
        # Jeśli mamy access_token, wysyłamy TYLKO token (Bearer).
        # Jeśli nie mamy tokena, wysyłamy client_id.
        if hasattr(self, "access_token") and self.access_token:
            kwargs.update(dict(oauth_token=self.access_token))
        elif hasattr(self, "client_id") and self.client_id:
            kwargs.update(dict(client_id=self.client_id))

        kwargs.update(
            {
                "verify_ssl": self.options.get("verify_ssl", True),
                "proxies": self.options.get("proxies", None),
            }
        )
        return wrapped_resource(make_request(method, url, kwargs))

    def __getattr__(self, name, **kwargs):
        if name not in ("get", "post", "put", "head", "delete"):
            raise AttributeError
        return partial(self._request, name, **kwargs)

    def _resolve_resource_name(self, name):
        if name[:4] == "http":
            return name
        name = name.rstrip("/").lstrip("/")
        return "%s%s/%s" % (self.scheme, self.host, name)

    def _redirect_uri(self):
        redirect_uri = self.options.get(
            "redirect_uri", self.options.get("redirect_url", None)
        )
        if not redirect_uri:
            raise ValueError("redirect_uri required")
        if not redirect_uri.startswith(
            ("https://", "http://localhost", "http://127.0.0.1")
        ):
            raise ValueError("HTTPS required for redirect_uri")
        return redirect_uri

    def _options_present(self, options, kwargs):
        return all(map(lambda k: k in kwargs, options))

    def _options_for_credentials_flow_present(self):
        return self._options_present(
            ("client_id", "client_secret", "username", "password"), self.options
        )

    def _options_for_authorization_code_flow_present(self):
        return self._options_present(
            ("client_id", "redirect_uri"), self.options
        ) or self._options_present(("client_id", "redirect_url"), self.options)

    def _options_for_token_refresh_present(self):
        return self._options_present(("client_id", "refresh_token"), self.options)
