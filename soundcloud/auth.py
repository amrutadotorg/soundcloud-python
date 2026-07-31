class Credential:
    """Authenticates a single request via ``apply`` on the request kwargs."""

    def apply(self, kwargs: dict) -> None:
        raise NotImplementedError


class AccessTokenCredential(Credential):
    """Bearer-token auth for requests (OAuth user or app session)."""

    def __init__(self, access_token: str):
        self.access_token = access_token

    def apply(self, kwargs: dict) -> None:
        kwargs["oauth_token"] = self.access_token


class ClientIdCredential(Credential):
    """Public ``client_id`` query-param auth for unauthenticated requests."""

    def __init__(self, client_id: str):
        self.client_id = client_id

    def apply(self, kwargs: dict) -> None:
        kwargs["client_id"] = self.client_id


class AuthFlow:
    """Describes how a Client obtains its credential."""

    @classmethod
    def from_options(cls, options: dict) -> "AuthFlow":
        if options.get("access_token"):
            return StaticTokenFlow(options["access_token"])
        if "client_id" not in options:
            raise TypeError("At least a client_id must be provided.")
        if "redirect_uri" in options or "redirect_url" in options:
            return AuthorizationCodeFlow(options)
        if all(
            k in options for k in ("client_id", "client_secret", "username", "password")
        ):
            raise DeprecationWarning("Password flow is deprecated.")
        if "refresh_token" in options:
            return RefreshTokenFlow()
        return ClientIdFlow(options["client_id"])

    def prepare(self, client) -> None:
        """Run construction-time side effects (verifier, token refresh)."""

    def resolve(self, client) -> Credential:
        raise NotImplementedError


class ClientIdFlow(AuthFlow):
    """No OAuth flow: requests are signed with the public client_id."""

    def __init__(self, client_id: str):
        self.client_id = client_id

    def resolve(self, client) -> Credential:
        return ClientIdCredential(self.client_id)


class StaticTokenFlow(AuthFlow):
    """A pre-obtained access_token is used as-is."""

    def __init__(self, access_token: str):
        self.access_token = access_token

    def resolve(self, client) -> Credential:
        return AccessTokenCredential(self.access_token)


class AuthorizationCodeFlow(AuthFlow):
    """OAuth 2.1 / PKCE: build the authorize_url, exchange the code later."""

    def __init__(self, options: dict):
        self.options = options

    def prepare(self, client) -> None:
        client.code_verifier = client._generate_code_verifier()
        client._authorization_code_flow()

    def resolve(self, client) -> Credential:
        return ClientIdCredential(self.options["client_id"])


class RefreshTokenFlow(AuthFlow):
    """OAuth 2.1: rotate the refresh_token into a fresh access_token."""

    def prepare(self, client) -> None:
        client._refresh_token_flow()

    def resolve(self, client) -> Credential:
        return AccessTokenCredential(client.access_token)
