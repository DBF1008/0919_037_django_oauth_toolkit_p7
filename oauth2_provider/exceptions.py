from oauthlib.oauth2 import OAuth2Error
from oauthlib.oauth2.rfc6749.errors import ServerError as OAuthLibServerError
from oauthlib.oauth2.rfc6749.errors import (
    TemporarilyUnavailableError as OAuthLibTemporarilyUnavailableError,
)


class OAuthToolkitError(Exception):
    """
    Base class for exceptions
    """

    def __init__(self, error=None, redirect_uri=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.oauthlib_error = error

        if redirect_uri:
            self.oauthlib_error.redirect_uri = redirect_uri


class FatalClientError(OAuthToolkitError):
    """
    Class for critical errors caused by a malformed or malicious client.

    These errors MUST NOT be redirected back to the client supplied
    ``redirect_uri`` and are mapped to a ``400 Bad Request`` response.
    """

    pass


class RecoverableError(OAuthToolkitError):
    """
    Class for transient errors where the client is allowed to retry the same
    request later without changing it.

    As per :rfc:`5.2.3` the response uses the ``temporarily_unavailable``
    error code and is mapped to a ``503 Service Unavailable`` HTTP response.
    """

    def __init__(self, error=None, redirect_uri=None, *args, **kwargs):
        if error is None:
            error = OAuthLibTemporarilyUnavailableError()
        if isinstance(error, OAuth2Error):
            error.status_code = 503
        super().__init__(error=error, redirect_uri=redirect_uri, *args, **kwargs)


class ServerError(OAuthToolkitError):
    """
    Class for unexpected failures of the authorization server itself.

    As per :rfc:`5.2` the response uses the ``server_error`` error code and is
    mapped to a ``500 Internal Server Error`` HTTP response.  Unlike oauthlib's
    own ``server_error`` representation (which targets the redirect based
    authorization endpoint and therefore keeps HTTP status ``400``), this
    exception is used by the direct response endpoints (token, revocation,
    userinfo and device authorization).
    """

    def __init__(self, error=None, redirect_uri=None, description=None, *args, **kwargs):
        if error is None:
            error_kwargs = {}
            if description is not None:
                error_kwargs["description"] = description
            error = OAuthLibServerError(**error_kwargs)
        elif not isinstance(error, OAuth2Error):
            # Allow constructing a ServerError from an arbitrary exception.
            error = OAuthLibServerError(description=str(error) or "An unexpected error occurred.")
        error.status_code = 500
        super().__init__(error=error, redirect_uri=redirect_uri, *args, **kwargs)


def as_oauthlib_error(error):
    """
    Return the oauthlib error wrapped by an :class:`OAuthToolkitError`.

    :class:`ServerError` instances may also be built directly from a plain
    :class:`Exception`; in that case a generic ``server_error`` is returned so
    callers always have an object exposing ``json``, ``headers``, ``error`` and
    ``status_code``.
    """
    if isinstance(error, OAuthToolkitError):
        wrapped = error.oauthlib_error
        if isinstance(wrapped, OAuth2Error):
            return wrapped
    if isinstance(error, OAuth2Error):
        return error
    generic = OAuthLibServerError(description="An unexpected error occurred.")
    generic.status_code = 500
    return generic


class OIDCError(Exception):
    """
    General class to derive from for all OIDC related errors.
    """

    status_code = 400
    error = None

    def __init__(self, description=None):
        if description is not None:
            self.description = description

        message = "({}) {}".format(self.error, self.description)
        super().__init__(message)


class InvalidRequestFatalError(OIDCError):
    """
    For fatal errors. These are requests with invalid parameter values, missing parameters or otherwise
    incorrect requests.
    """

    error = "invalid_request"


class ClientIdMissmatch(InvalidRequestFatalError):
    description = "Mismatch between the Client ID of the ID Token and the Client ID that was provided."


class InvalidOIDCClientError(InvalidRequestFatalError):
    description = "The client is unknown or no client has been included."


class InvalidOIDCRedirectURIError(InvalidRequestFatalError):
    description = "Invalid post logout redirect URI."


class InvalidIDTokenError(InvalidRequestFatalError):
    description = "The ID Token is expired, revoked, malformed, or otherwise invalid."


class LogoutDenied(OIDCError):
    error = "logout_denied"
    description = "Logout has been refused by the user."
