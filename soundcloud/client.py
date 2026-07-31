import base64
import hashlib
import secrets
from functools import partial
from typing import Any
from urllib.parse import urlencode

import requests

from soundcloud.auth import AccessTokenCredential, AuthFlow
from soundcloud.request import make_request
from soundcloud.resource import Resource, ResourceList, wrapped_resource


class Client:
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
        self._authorize_url: str | None = None

        # client_id is always kept (needed for refresh flow and public requests)
        self.client_id: str | None = kwargs.get("client_id")

        self.code_verifier: str | None = None
        self.access_token: str | None = kwargs.get("access_token")
        self.token: Resource | ResourceList | None = None

        if "scope" in kwargs:
            self.scope = kwargs.get("scope")

        self.flow = AuthFlow.from_options(kwargs)
        self.flow.prepare(self)
        self.credential = self.flow.resolve(self)

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

    def _set_token(self, token: Resource | ResourceList) -> Resource | ResourceList:
        """Store a token response and switch requests to Bearer auth."""
        self.token = token
        access_token = token.access_token
        if not access_token:
            raise ValueError("Token response missing access_token")
        self.access_token = access_token
        self.credential = AccessTokenCredential(access_token)
        return token

    def _transport_options(self) -> dict:
        return {
            "verify_ssl": self.options.get("verify_ssl", True),
            "proxies": self.options.get("proxies", None),
            "timeout": self.options.get("timeout"),
        }

    def exchange_token(self, code) -> Resource | ResourceList:
        if not self.code_verifier:
            raise ValueError("code_verifier not found.")

        url = f"https://{self.auth_host}/oauth/token"
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

        options.update(self._transport_options())

        self.token = self._set_token(
            wrapped_resource(make_request("post", url, options))
        )
        self.code_verifier = None
        return self.token

    def client_credentials_token(self) -> Resource | ResourceList:
        """Obtain an app-level token for public resources (client_credentials flow).

        Requires client_id and client_secret, sent via HTTP Basic auth (per the
        SoundCloud docs). The token grants access to public resources only
        (search, playback, URL resolution) — no user session. The response
        includes a single-use refresh_token, stored in ``self.options``.
        """
        if not self.client_id:
            raise ValueError("client_id required for client_credentials flow")
        client_secret = self.options.get("client_secret")
        if not client_secret:
            raise ValueError("client_secret required for client_credentials flow")

        url = f"https://{self.auth_host}/oauth/token"
        basic = base64.b64encode(
            f"{self.client_id}:{client_secret}".encode("ascii")
        ).decode("ascii")
        headers = {
            "accept": "application/json; charset=utf-8",
            "Authorization": f"Basic {basic}",
        }

        transport = self._transport_options()
        request_kwargs = {}
        if transport["verify_ssl"] is False:
            request_kwargs["verify"] = False
        if transport["proxies"]:
            request_kwargs["proxies"] = transport["proxies"]

        response = requests.post(
            url,
            headers=headers,
            data={"grant_type": "client_credentials"},
            **request_kwargs,
        )
        response.raise_for_status()
        token = self._set_token(wrapped_resource(response))
        if hasattr(token, "refresh_token") and token.refresh_token:
            self.options["refresh_token"] = token.refresh_token
        return token

    def authorize_url(self) -> str | None:
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

        url = f"https://{self.auth_host}/authorize"
        self._authorize_url = f"{url}?{urlencode(options)}"

    def _refresh_token_flow(self):
        url = f"https://{self.auth_host}/oauth/token"
        options = {
            "grant_type": "refresh_token",
            "client_id": self.options.get("client_id"),
            "refresh_token": self.options.get("refresh_token"),
        }
        client_secret = self.options.get("client_secret")
        if client_secret:
            options["client_secret"] = client_secret

        options.update(self._transport_options())

        self.token = self._set_token(
            wrapped_resource(make_request("post", url, options))
        )
        if hasattr(self.token, "refresh_token") and self.token.refresh_token:
            self.options["refresh_token"] = self.token.refresh_token

    def _request(self, method, resource, **kwargs):
        url = self._resolve_resource_name(resource)
        self.credential.apply(kwargs)
        kwargs.update(self._transport_options())
        return wrapped_resource(make_request(method, url, kwargs))

    def __getattr__(self, name, **kwargs) -> Any:
        if name not in ("get", "post", "put", "head", "delete"):
            raise AttributeError
        return partial(self._request, name, **kwargs)

    def _resolve_resource_name(self, name):
        if name[:4] == "http":
            return name
        name = name.rstrip("/").lstrip("/")
        return f"{self.scheme}{self.host}/{name}"

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
